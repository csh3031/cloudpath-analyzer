"""Bounded offline ELB policy and local-route checks; no runtime mapping or session verdict."""
import hashlib
from ipaddress import IPv4Address, IPv4Network
from backend.aws.elb_target_evidence import inspect_elb_targets
from backend.aws.peering_evidence import _load, _timestamp
from backend.aws.policy_evidence import _sg, _acl, _port
from backend.aws.route_evidence import lookup_observed_route
from backend.aws.endpoint_evidence import lookup_observed_endpoint
from backend.aws.load_balancer_evidence import _id, _arn
from backend.iac.plan_adapter import _read

FORMAT = 'cloudpath-elb-path-v1'


def inspect_elb_paths(inventory_raw, elbv2_raw, health_raw, path_evidence_raw,
                      load_balancer_id, listener_port, client_ip, *,
                      frontend_node_ip, backend_node_ip, client_port,
                      backend_source_port, health_source_port, rules_raw=None,
                      host=None, path=None, attributes_raw=None):
    """Evaluate assumed internal IPv4 paths; node IPs/ports are hypothetical, not observations."""
    for p in (client_port, backend_source_port, health_source_port):
        if not _port(p): raise ValueError('Expected TCP port 1..65535')
    for ip in (frontend_node_ip, backend_node_ip):
        if not isinstance(ip,str): raise ValueError('Expected hypothetical node IPv4 string')
        IPv4Address(ip)
    target = inspect_elb_targets(inventory_raw,elbv2_raw,health_raw,load_balancer_id,listener_port,client_ip,
        rules_raw=rules_raw,host=host,path=path,attributes_raw=attributes_raw,
        backend_node_ip=backend_node_ip,backend_source_port=backend_source_port)
    identity,meta,inv=_load(inventory_raw)
    doc=_read(elbv2_raw); evidence=_read(path_evidence_raw)
    if set(evidence)!={'format','collected_at','elbv2_input_identity','complete','load_balancer_arn','security_group_ids','health_checks'} or evidence['format']!=FORMAT:
        raise ValueError('Invalid ELB path evidence wrapper')
    if not isinstance(evidence['security_group_ids'],list) or not all(isinstance(x,str) for x in evidence['security_group_ids']) or len(set(evidence['security_group_ids']))!=len(evidence['security_group_ids']):
        raise ValueError('Invalid LB security group list')
    if not isinstance(evidence['health_checks'],list) or len(evidence['health_checks'])>300: raise ValueError('Invalid health check list')
    configs={}
    for row in evidence['health_checks']:
        if not isinstance(row,dict) or set(row)!={'target_group_arn','enabled','protocol','port','path'}: raise ValueError('Invalid health check row')
        arn=row['target_group_arn']; _arn(arn,'targetgroup')
        if arn in configs: raise ValueError('Duplicate health check group')
        configs[arn]=row
    out=dict(analysis_type='STATIC_AWS_ELB_PATH_CONSTRAINTS',input_identity=identity,
             path_input_identity='sha256-elb-path-v1:'+hashlib.sha256(path_evidence_raw).hexdigest(),
             target_analysis=target,frontend=None,targets=[],session_status='UNKNOWN',live_observation=False,
             scenario=dict(client_ip=client_ip,client_port=client_port,hypothetical_frontend_node_ip=frontend_node_ip,
                           hypothetical_backend_node_ip=backend_node_ip,hypothetical_backend_source_port=backend_source_port,
                           hypothetical_health_source_port=health_source_port),
             limitations=['Offline evidence, unauthenticated; node addresses and source ports hypothetical.',
                          'Internal direct same-VPC IPv4, primary single-ENI EC2 only; no DNS or runtime target selection.',
                          'CIDR SG rules only; SG references and prefix lists unresolved.',
                          'Independent checks, not an observed or guaranteed path; response assumes tracked request.',
                          'Same-subnet forwarding/NACL applicability not inferred; NLB preserved backend not composed; ALB cross-zone eligibility unverified.',
                          'Health configuration and network checks only; no health execution, TLS or application checks.'])
    def finish(reason,status='UNKNOWN'): return dict(out,status=status,reason=reason)
    base=target['configuration']; lb=base['load_balancer']
    if target['status']!='TARGET_CONSTRAINTS_CANDIDATE' or not lb or lb['scheme']!='internal': return finish('TARGET_OR_INTERNAL_SCOPE_UNCONFIRMED')
    arn=evidence['load_balancer_arn']; _arn(arn,'loadbalancer')
    matches=[x for x in doc['LoadBalancers'] if x['LoadBalancerArn']==arn and _id(arn)==load_balancer_id]
    if evidence['complete'] is not True or evidence['elbv2_input_identity']!=base['elbv2_input_identity'] or len(matches)!=1: return finish('PATH_EVIDENCE_IDENTITY_OR_COMPLETENESS_UNCONFIRMED')
    times=[_timestamp(x['collected_at']) for x in [meta,doc,_read(health_raw),evidence]+[_read(x) for x in (rules_raw,attributes_raw) if x is not None]]
    if (max(times)-min(times)).total_seconds()>300: return finish('SNAPSHOT_TIME_GAP')
    groups={x['GroupId']:x for x in inv['SecurityGroups']}; ids=evidence['security_group_ids']; kind=lb['type']
    # Explicit empty list is valid only for an NLB without SGs; never infer it from omission.
    if (kind=='application' and not ids) or any(i not in groups for i in ids): return finish('LB_SECURITY_GROUPS_UNCONFIRMED')
    if 'SecurityGroups' in matches[0] and sorted(matches[0]['SecurityGroups'])!=sorted(ids): return finish('LB_SECURITY_GROUP_EVIDENCE_CONFLICT')
    subnets={s['SubnetId']:s for s in inv['Subnets']}; lb_subnets={x['subnet_id'] for x in lb['subnets']}
    def node(ip):
        addr=IPv4Address(ip)
        ss=[s for s in subnets.values() if addr in IPv4Network(s['CidrBlock'])]
        occupied=any(ip==e.get('PrivateIpAddress') or any(a.get('PrivateIpAddress')==ip for a in e.get('PrivateIpAddresses',[])) for e in inv['NetworkInterfaces'])
        if len(ss)!=1 or ss[0]['SubnetId'] not in lb_subnets or occupied: return None
        net=IPv4Network(ss[0]['CidrBlock'])
        if int(addr)-int(net.network_address)<4 or addr==net.broadcast_address: return None
        return dict(private_ip=ip,subnet_id=ss[0]['SubnetId'],security_group_ids=ids,availability_zone=ss[0]['AvailabilityZone'])
    front=node(frontend_node_ip); back=node(backend_node_ip)
    client=lookup_observed_endpoint(inventory_raw,client_ip)
    if not front or not back or client['status']!='ENDPOINT_CANDIDATE': return finish('NODE_OR_CLIENT_UNCONFIRMED')
    cn=IPv4Network(subnets[client['subnet_id']]['CidrBlock']); ci=IPv4Address(client_ip)
    if int(ci)-int(cn.network_address)<4 or ci==cn.broadcast_address: return finish('CLIENT_RESERVED_ADDRESS')
    def check_flow(src,dst,sport,dport,scope):
        req=[]; rep=[]
        def add(rows,stage,v): rows.append(dict(stage=stage,evaluation_mode='INDEPENDENT_RULE_CHECK',**v))
        def sg(ep,peer,egress,port):
            if not ep['security_group_ids']: return dict(status='NOT_APPLICABLE',reason='EXPLICIT_NLB_WITHOUT_SECURITY_GROUP')
            return _sg(groups,ep,peer,egress,port)
        def route(a,b):
            if a['subnet_id']==b['subnet_id']: return dict(status='UNKNOWN',reason='SAME_SUBNET_FORWARDING_NOT_IN_SCOPE')
            r=lookup_observed_route(inventory_raw,a['subnet_id'],b['private_ip'])
            return dict(status='ALLOW_CANDIDATE' if r['status']=='LOCAL_CANDIDATE' else r['status'] if r['status']=='BLOCKED' else 'UNKNOWN',reason=r['reason'],route_evidence=r)
        def acl(a,b,e,p):
            if a['subnet_id']==b['subnet_id']: return dict(status='UNKNOWN',reason='SAME_SUBNET_NACL_APPLICABILITY_NOT_COMPOSED')
            return _acl(inv['NetworkAcls'],a,b,e,p)
        add(req,'SOURCE_SG_EGRESS',sg(src,dst,True,dport)); add(req,'SOURCE_NACL_EGRESS',acl(src,dst,True,dport)); add(req,'LOCAL_ROUTE',route(src,dst)); add(req,'DESTINATION_NACL_INGRESS',acl(dst,src,False,dport)); add(req,'DESTINATION_SG_INGRESS',sg(dst,src,False,dport))
        conditional=dict(status='CONDITIONAL',reason='REQUIRES_ESTABLISHED_TRACKED_REQUEST')
        add(rep,'SOURCE_SG_REPLY',conditional if dst['security_group_ids'] else dict(status='NOT_APPLICABLE',reason='EXPLICIT_NLB_WITHOUT_SECURITY_GROUP')); add(rep,'SOURCE_NACL_EGRESS',acl(dst,src,True,sport)); add(rep,'LOCAL_ROUTE',route(dst,src)); add(rep,'DESTINATION_NACL_INGRESS',acl(src,dst,False,sport)); add(rep,'DESTINATION_SG_REPLY',conditional if src['security_group_ids'] else dict(status='NOT_APPLICABLE',reason='EXPLICIT_NLB_WITHOUT_SECURITY_GROUP'))
        def status(rows):
            states={r['status'] for r in rows}; return 'RULE_BLOCK_CANDIDATE' if 'BLOCKED' in states else 'UNKNOWN' if 'UNKNOWN' in states else 'CONDITIONAL_CANDIDATE'
        return dict(scope=scope,source_ip=src['private_ip'],destination_ip=dst['private_ip'],source_port=sport,destination_port=dport,request=req,response=rep,request_status=status(req),response_status=status(rep),session_status='UNKNOWN')
    out['frontend']=check_flow(client,front,client_port,listener_port,'HYPOTHETICAL_CLIENT_TO_LB')
    fwd=target['forwarding']; preserve=kind=='network' and fwd['address_processing']['preserve_client_ip']
    crosszone=kind!='network' or fwd['cross_zone']['enabled'] is True
    for group in target['groups']:
        g=group['target_group']; ga=[x['TargetGroupArn'] for x in doc['TargetGroups'] if _id(x['TargetGroupArn'])==g['id']]
        hc=configs.get(ga[0]) if len(ga)==1 else None
        for t in group['targets']:
            row=dict(target_group_id=g['id'],target_id=t['id'],registered_port=t['registered_port'],health_state=t['health_state'],backend=None,health_check=None,backend_status='NOT_EVALUATED',health_check_status='NOT_EVALUATED'); out['targets'].append(row)
            ep=t['endpoint']
            if not ep or ep['status']!='ENDPOINT_CANDIDATE' or t['zone_status']!='ENABLED_ZONE_CANDIDATE': continue
            if g['configured_weight']!=0:
                if preserve: row['backend_status']='UNKNOWN_PRESERVED_NLB_PATH_NOT_COMPOSED'
                elif not crosszone and (front['availability_zone']!=back['availability_zone'] or back['availability_zone']!=t['availability_zone']): row['backend_status']='UNKNOWN_ZONE_SCOPE'
                else:
                    row['backend']=check_flow(back,ep,backend_source_port,t['registered_port'],'HYPOTHETICAL_LB_TO_TARGET'); row['backend_status']=row['backend']['request_status']
            if not hc: row['health_check_status']='UNKNOWN_CONFIGURATION_MISSING'; continue
            row['health_configuration']=hc
            if hc['enabled'] is False: row['health_check_status']='NOT_APPLICABLE_DISABLED'; continue
            hp=t['registered_port'] if hc['port']=='traffic-port' else hc['port']
            allowed=('HTTP','HTTPS') if kind=='application' else ('TCP','HTTP','HTTPS')
            if hc['enabled'] is not True or hc['protocol'] not in allowed or not _port(hp) or (hc['protocol'] in ('HTTP','HTTPS') and (not isinstance(hc['path'],str) or not hc['path'].startswith('/'))) or (hc['protocol']=='TCP' and hc['path'] is not None):
                row['health_check_status']='UNKNOWN_CONFIGURATION_UNSUPPORTED'; continue
            row['health_check']=check_flow(back,ep,health_source_port,hp,'HYPOTHETICAL_LB_HEALTH_CHECK'); row['health_check_status']=row['health_check']['request_status']
    return finish('INDEPENDENT_HYPOTHETICAL_PATH_CHECKS','ELB_PATH_CONSTRAINTS_CANDIDATE')
