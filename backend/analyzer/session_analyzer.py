"""Phase 4-4: bounded, static bidirectional TCP/UDP policy diagnosis."""
from dataclasses import replace
from backend.analyzer.communication_analyzer import analyze_communication
from backend.analyzer.security_group_analyzer import SECURITY_GROUP_CHECK
from backend.analyzer.network_acl_analyzer import NETWORK_ACL_CHECK

CHECKS = (SECURITY_GROUP_CHECK, NETWORK_ACL_CHECK)


def analyze_session(resources, scenario, *, complete_routing_config=False,
                    assume_tracked_response=False):
    """Separate candidate paths, ordered checks, and conditional downstream results.

    Only direct same-VPC IPv4 endpoint sessions are supported. A PASS is a
    configuration prediction, not evidence of a live session or listening app.
    """
    def analyze(s):
        return analyze_communication(resources, s, CHECKS, trace=True,
                    complete_routing_config=complete_routing_config)

    result = analyze(scenario)
    original = list(result['findings'])
    def append_finding(check, status, resource, reason, evidence=(), assumptions=()):
        f = dict(id=f'F{len(result["findings"])+1:03d}', check=check, status=status,
                 evaluation_mode='CONDITIONAL_CHECK', resource=resource, reason=reason,
                 evidence=list(evidence), assumptions=list(assumptions), dependencies=[])
        result['findings'].append(f)
        return f

    def select(findings, check, direction, resource):
        candidates = [f for f in findings if f['check']==check and f['resource']==resource
                      and f['reason'].startswith(direction.upper()+':')]
        if len(candidates)==1:
            return candidates[0]
        return append_finding(check,'UNKNOWN',resource,f'{direction.upper()}: missing or ambiguous result')

    def valid_port(p):
        return type(p) is int and 1 <= p <= 65535

    forward = result['forwarding']
    def supported(path):
        return (path.get('status')=='REACHED_DESTINATION' and path.get('path_complete') is True
                and [h['stage'] for h in path['hops']] in
                [['SOURCE_ENDPOINT','SAME_SUBNET','DESTINATION_ENDPOINT'],
                 ['SOURCE_ENDPOINT','ROUTE_LOOKUP','VPC_LOCAL','DESTINATION_ENDPOINT']])

    scope_ok = (scenario.request_type=='network' and scenario.protocol.lower() in ('tcp','udp')
                and valid_port(scenario.destination_port) and scenario.assume_direct_private
                and complete_routing_config and scenario.complete_config and supported(forward))
    # The forwarding candidate is separate from policy outcomes. Do not certify
    # first-blocker ordering outside a fully resolved direct path.
    src_sub = scenario.source_subnet
    dst_sub = forward['hops'][-1].get('subnet') if supported(forward) else None
    req = []
    def step(steps, label, finding):
        steps.append(dict(id=('REQ' if steps is req else 'RET')+f'{len(steps)+1:02d}',
                          stage=label, status=finding['status'], resource=finding['resource'],
                          finding_id=finding['id'], reason=finding['reason']))
    def path_step(steps, path, allowed, name):
        ok = allowed and supported(path)
        f = append_finding(name,'PASS' if ok else 'UNKNOWN',
             path.get('hops',[{}])[-1].get('resource') if path.get('hops') else None,
             path.get('reason','Path unavailable'), path.get('hops',[]))
        step(steps,'FORWARDING',f)
    step(req,'SG_EGRESS',select(original,'security_group','egress',scenario.source_resource))
    step(req,'NACL_EGRESS',select(original,'network_acl','egress',src_sub))
    path_step(req,forward,scope_ok,'request_forwarding')
    step(req,'NACL_INGRESS',select(original,'network_acl','ingress',dst_sub))
    step(req,'SG_INGRESS',select(original,'security_group','ingress',scenario.destination_resource))

    def order(steps, active):
        uncertain = not active
        first = None
        for s in steps:
            s['evaluation_mode'] = 'CONDITIONAL' if uncertain or first else 'PREDICTED_PATH'
            if uncertain or first:
                continue
            if s['status']=='BLOCKED':
                first=s
            elif s['status']!='PASS':
                uncertain=True
        state = 'BLOCKED' if first else 'UNKNOWN' if uncertain else 'PASS'
        return state, first
    req_state, req_first = order(req,scope_ok)
    ret = []
    reverse_path = None
    reverse_scenario = None
    reverse_allowed = scope_ok and valid_port(scenario.source_port)
    if reverse_allowed:
        reverse_scenario = replace(scenario,source_subnet=dst_sub,source_resource=scenario.destination_resource,
                   source_ip=scenario.destination_ip,source_port=scenario.destination_port,
                   destination_resource=scenario.source_resource,destination_ip=scenario.source_ip,
                   destination_port=scenario.source_port)
        rev = analyze(reverse_scenario)
        reverse_path = rev['forwarding']
        # Copy NACL observations with new unique IDs. No reverse SG as a new
        # connection unless the user does not assert tracked response.
        reverse_findings=[]
        for f in rev['findings']:
            if f['check']=='network_acl' or (f['check']=='security_group' and not assume_tracked_response):
                reverse_findings.append(append_finding('return_'+f['check'],('UNKNOWN' if f['check']=='security_group' and f['status']!='PASS' else f['status']),f['resource'],
                    f['reason'],f['evidence'],['Hypothetical reverse tuple; unchanged configuration.']))
        # An explicit tracked-response assumption is not a claim of observed state.
        def return_sg(direction, resource):
            if assume_tracked_response:
                return append_finding('return_security_group','PASS',resource,
                        'Tracked response assumed; no new SG connection evaluation.',
                        [{'direction':direction,'match':'ASSUMED_TRACKED_RESPONSE'}],
                        ['Original request permitted, tracking state valid and capacity available.'])
            f=select(reverse_findings,'return_security_group',direction,resource)
            if f['status']=='PASS': return f
            return append_finding('return_security_group','UNKNOWN',resource,
                'Tracking state not asserted and explicit reverse SG allow not established.',f['evidence'])
        step(ret,'SG_EGRESS',return_sg('egress',scenario.destination_resource))
        step(ret,'NACL_EGRESS',select(reverse_findings,'return_network_acl','egress',dst_sub))
        path_step(ret,reverse_path,supported(reverse_path),'return_forwarding')
        step(ret,'NACL_INGRESS',select(reverse_findings,'return_network_acl','ingress',src_sub))
        step(ret,'SG_INGRESS',return_sg('ingress',scenario.source_resource))
    else:
        f=append_finding('return_path','UNKNOWN',None,'Direct path or explicit source port missing.')
        step(ret,'RETURN_PREREQUISITES',f)
    # A reply is hypothetical unless the request passes. Evaluate it anyway,
    # but never promote it to a confirmed first blocker before the request.
    hypothetical_state, _ = order(ret,reverse_allowed)
    ret_state, ret_first = order(ret,reverse_allowed and req_state=='PASS')
    first=req_first or ret_first
    overall='BLOCKED' if first else 'REACHABLE' if req_state==ret_state=='PASS' else 'UNKNOWN'
    result.update(predicted_connectivity=overall,first_blocker=first['finding_id'] if first else None,
                  first_blocker_step=first['id'] if first else None,
                  conditional_blockers=[s['finding_id'] for s in req+ret if s['status']=='BLOCKED' and s['evaluation_mode']=='CONDITIONAL'],
                  analysis_type='STATIC_IAC_PREDICTION',
                  session_trace=dict(schema_version='1.0',scope='DIRECT_SAME_VPC_IPV4_TCP_UDP',
                     scope_supported=scope_ok, assumptions={'tracked_response':assume_tracked_response,
                      'complete_routing_config':complete_routing_config},
                     request={'status':req_state,'steps':req},
                     response={'status':ret_state,'hypothetical_status':hypothetical_state,
                         'conditional':req_state!='PASS','steps':ret,'forwarding':reverse_path,
                         'tuple':None if reverse_scenario is None else {'source_ip':reverse_scenario.source_ip,
                             'destination_ip':reverse_scenario.destination_ip,'source_port':reverse_scenario.source_port,
                             'destination_port':reverse_scenario.destination_port,'protocol':reverse_scenario.protocol}},
                     limitations=['No live traffic, application listener, host firewall, NAT translation or ALB analysis.',
                                  'SG tracked response is an explicit assumption, not observed state.']))
    checks=result['coverage']['checks']
    checks['return_path']={'state':'EVALUATED' if hypothetical_state!='UNKNOWN' else 'UNKNOWN',
                           'reason':'Static reverse checks; conditional if request not passed.'}
    checks['session_static']={'state':'EVALUATED' if overall!='UNKNOWN' else 'UNKNOWN',
                              'reason':'Bounded ordered static session prediction.'}
    checks['full_path_simulation']={'state':'NOT_EVALUATED','reason':'General packet simulation outside direct scope not implemented.'}
    for state in ('evaluated','unknown','not_evaluated'):
        result['coverage'][state]=sum(x['state'].lower()==state for x in checks.values())
    return result
