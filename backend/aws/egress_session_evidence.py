"""Bounded static internet egress TCP policy constraints, not a live session."""
from backend.aws.egress_evidence import trace_internet_egress
from backend.aws.policy_evidence import _acl, _sg, _port
from backend.aws.route_evidence import lookup_observed_route
from backend.aws.snapshot import sanitize_inventory
from backend.iac.plan_adapter import _read


def _result(status, reason, **details):
    return dict(status=status, reason=reason, **details)


def _port_range_acl(acls, endpoint, peer, low=1024, high=65535):
    """Partition at every rule boundary; _acl is constant on each partition.

    Never choose a translated port. Mixed or unresolved decisions stay UNKNOWN.
    """
    cuts = {low, high + 1}
    for acl in acls:
        for rule in acl['Entries']:
            ports = rule.get('PortRange', {})
            a, b = ports.get('From'), ports.get('To')
            if type(a) is int and type(b) is int and 0 <= a <= b <= 65535:
                if low < a <= high:
                    cuts.add(a)
                if low < b + 1 <= high:
                    cuts.add(b + 1)
    cuts = sorted(cuts)
    segments = []
    for a,b in zip(cuts,cuts[1:]):
        result = _acl(acls, endpoint, peer, False, a)
        segments.append(dict(from_port=a,to_port=b-1,evidence=result))
    states = {s['evidence']['status'] for s in segments}
    status = states.pop() if len(states)==1 else 'UNKNOWN'
    return _result(status, 'NAT_PORT_RANGE_CONSTRAINT', port_range=[low,high],
                   translated_port=None, segments=segments)


def analyze_internet_egress_session(raw: bytes, source_ip: str, destination_ip: str,
                                    source_port: int, destination_port: int) -> dict:
    if not _port(source_port) or not _port(destination_port):
        raise ValueError('Expected explicit TCP ports in 1..65535')
    route = trace_internet_egress(raw, source_ip, destination_ip)
    doc = _read(raw)
    inv = sanitize_inventory(doc['inventory'], version=doc['format'])
    acls = inv['NetworkAcls']
    request, response = [], []
    out = dict(analysis_type='STATIC_AWS_INTERNET_EGRESS_TCP_CONSTRAINTS',
               input_identity=route['input_identity'], region=route['region'],
               collected_at=route['collected_at'], scenario=dict(source_ip=source_ip,
               destination_ip=destination_ip, source_port=source_port,
               destination_port=destination_port, protocol='tcp'), route=route,
               request=request, response=response, first_request_stop=None,
               conditional_first_response_stop=None, internet_reachability='UNKNOWN',
               live_observation=False, limitations=[
                   'Static uploaded configuration only; no authenticity, completeness or freshness guarantee.',
                   'External delivery, application and host policies not evaluated; VPC BPA and gateway ingress routing not established.',
                   'NAT source port and runtime tracking unknown; reverse checks are hypothetical only.',
                   'Public NAT port constraint 1024..65535; no selected translated port.',
                   'NAT gateway has no security group; subnet NACL constraints only.',
                   'No AWS API calls or packet transmission.'])
    def append(rows, stage, evidence):
        previous_stop = any(r['status'] not in ('ALLOW_CANDIDATE','CONDITIONAL') for r in rows)
        mode = ('INDEPENDENT_CHECK' if previous_stop else
                'CONDITIONAL_CHECK' if rows is response else 'PREDICTED_PATH')
        rows.append(dict(stage=stage, evaluation_mode=mode, **evidence))
    def summarize(rows):
        stop = next((r for r in rows if r['status'] not in ('ALLOW_CANDIDATE','CONDITIONAL')),None)
        return (stop['status'],stop['stage']) if stop else ('CONDITIONAL_CANDIDATE',None)
    ep = route['endpoint']
    if not ep or ep['status'] != 'ENDPOINT_CANDIDATE':
        append(request,'SOURCE_ENDPOINT',_result('UNKNOWN','ENDPOINT_UNCONFIRMED'))
    else:
        peer = dict(private_ip=destination_ip)
        # Only use valid external tuple; upstream trace rejects invalid/in-scope destination.
        if not route['hops']:
            append(request,'EGRESS_SCOPE',_result('UNKNOWN',route['reason']))
        else:
            groups = {g['GroupId']:g for g in inv['SecurityGroups']}
            append(request,'SOURCE_SG_EGRESS',_sg(groups,ep,peer,True,destination_port))
            append(request,'SOURCE_NACL_EGRESS',_acl(acls,ep,peer,True,destination_port))
            status = route['status']
            # Split first route from NAT-side route so a later blackhole does not
            # precede the NAT subnet ingress check in the predicted path.
            lookups = route['route_lookups']
            first = lookups[0] if lookups else None
            nat_hop = next((h for h in route['hops'] if h['stage']=='PUBLIC_NAT_GATEWAY'),None)
            if first:
                first_status = first['status']
                if first_status=='ACTIVE_ROUTE_CANDIDATE':
                    first_status = 'ALLOW_CANDIDATE' if nat_hop or status=='EGRESS_ROUTE_CANDIDATE' else 'UNKNOWN'
                append(request,'SOURCE_ROUTE',dict(first,status=first_status,reason=route['reason'] if first_status=='UNKNOWN' and first['status']=='ACTIVE_ROUTE_CANDIDATE' else first['reason']))
            nat = None
            if nat_hop:
                nat = next(g for g in inv['NatGateways'] if g['NatGatewayId']==nat_hop['resource_id'])
                nat_ep = dict(subnet_id=nat['SubnetId'])
                client = dict(private_ip=source_ip)
                append(request,'NAT_SUBNET_INGRESS',_acl(acls,nat_ep,client,False,destination_port))
                if len(lookups)>1:
                    second=lookups[1]
                    second_status=second['status']
                    if second_status=='ACTIVE_ROUTE_CANDIDATE':
                        second_status='ALLOW_CANDIDATE' if status=='EGRESS_ROUTE_CANDIDATE' else 'UNKNOWN'
                    append(request,'NAT_ROUTE',dict(second,status=second_status,reason=route['reason'] if second_status=='UNKNOWN' and second['status']=='ACTIVE_ROUTE_CANDIDATE' else second['reason']))
                append(request,'NAT_SUBNET_EGRESS',_acl(acls,nat_ep,peer,True,destination_port))
            if status != 'EGRESS_ROUTE_CANDIDATE':
                if not first or (nat and len(lookups)<2):
                    append(request,'EGRESS_ROUTE_SCOPE',_result(status,route['reason']))
            else:
                translation = route['translation'] or {}
                mapping_ok = translation.get('state')=='ADDRESS_MAPPING_CANDIDATE'
                append(request,'ADDRESS_MAPPING',_result('ALLOW_CANDIDATE' if mapping_ok else 'UNKNOWN',translation.get('reason','MAPPING_UNCONFIRMED')))
                # Reverse path is never predicted as traversed. Gateway edge routing
                # and public access state are unverified, regardless of ACL matches.
                append(response,'IGW_RETURN_SCOPE',_result('UNKNOWN','IGW_INGRESS_AND_RUNTIME_UNVERIFIED'))
                if nat:
                    append(response,'NAT_SUBNET_INGRESS_PORT_RANGE',_port_range_acl(acls,nat_ep,peer))
                    append(response,'NAT_REVERSE_MAPPING',_result('CONDITIONAL','REQUIRES_EXISTING_NAT_STATE'))
                    back=lookup_observed_route(raw,nat['SubnetId'],source_ip)
                    table=next((t for t in inv['RouteTables'] if t['RouteTableId']==back['route_table_id']),{})
                    bstatus='ALLOW_CANDIDATE' if back['status']=='LOCAL_CANDIDATE' else back['status']
                    if table.get('PropagatingVgws'):
                        bstatus='UNKNOWN'
                    append(response,'NAT_RETURN_ROUTE',_result(bstatus,'STATIC_LOCAL_RETURN_CONSTRAINT',route=back))
                    append(response,'NAT_SUBNET_EGRESS',_acl(acls,nat_ep,client,True,source_port))
                append(response,'SOURCE_NACL_INGRESS',_acl(acls,ep,peer,False,source_port))
                append(response,'SOURCE_SG_INGRESS',_result('CONDITIONAL','REQUIRES_ESTABLISHED_TRACKED_REQUEST'))
    req, stop=summarize(request)
    out['request_status'],out['first_request_stop']=req,stop
    # These are individual independent reverse constraints, not a traversed response.
    out['response_status']='UNKNOWN' if response else 'NOT_EVALUATED'
    out['conditional_first_response_stop']=summarize(response)[1] if response else None
    out['session_status']='BLOCKED' if req=='BLOCKED' else 'UNKNOWN'
    return out
