"""Offline cross-subnet TCP constraints between two correlated ECS task ENIs."""
from ipaddress import IPv4Address, IPv4Network
from backend.aws.ecs_task_evidence import inspect_ecs_task
from backend.aws.peering_evidence import _load
from backend.aws.prefix_list_evidence import load_prefix_lists
from backend.aws.policy_evidence import _sg, _acl, _port, _result
from backend.aws.local_delivery_evidence import same_subnet_delivery, subnet_policy
from backend.aws.route_evidence import lookup_observed_route
from backend.iac.plan_adapter import _read

def _read_ecs_time(raw):
    return _read(raw)['collected_at']


def analyze_ecs_task_session(inventory_raw, ecs_raw, source_task_id, destination_task_id,
                             source_port, destination_port, *, prefix_list_raw=None):
    """No runtime delivery, no synthetic EC2; return path conditional on tracking."""
    if not _port(source_port) or not _port(destination_port):
        raise ValueError('Expected explicit TCP ports in 1..65535')
    identity, meta, inv = _load(inventory_raw)
    src = inspect_ecs_task(inventory_raw, ecs_raw, source_task_id)
    dst = inspect_ecs_task(inventory_raw, ecs_raw, destination_task_id)
    out = dict(analysis_type='STATIC_AWS_ECS_TASK_TCP_CONSTRAINTS',
               input_identity=identity, ecs_input_identity=src['ecs_input_identity'],
               region=meta['region'], vpc_id=meta['vpc_id'],
               scenario=dict(source_task_id=source_task_id, destination_task_id=destination_task_id,
                             protocol='tcp', source_port=source_port,destination_port=destination_port),
               source_endpoint=src,destination_endpoint=dst,
               request=[],response=[],request_status='UNKNOWN',response_status='NOT_EVALUATED',
               first_request_stop=None,conditional_first_response_stop=None,
               session_status='UNKNOWN',live_observation=False,
               response_assumptions=['REQUEST_DELIVERY_PREDICTED','TCP_REPLY_CONNECTION_TRACKED'],
               limitations=['Offline unauthenticated non-atomic snapshots; 300s time proximity is heuristic.',
                            'Same VPC distinct ENI primary IPv4; conditional direct same-subnet delivery; awsvpc task ENIs; TCP CIDR and direct private ENI SG reference checks.',
                            'Non-direct SG references and missing/unsupported prefix list evidence unresolved; no container listener or runtime verification.',
                            'Conditional reply assumes request delivery and tracked connection; no AWS API calls or packets.'])
    prefix_lists,prefix_summary=load_prefix_lists(prefix_list_raw,identity,meta['region'],meta['collected_at'],additional_times=(_read_ecs_time(ecs_raw),) if prefix_list_raw is not None else ())
    if prefix_summary is not None: out['prefix_list_evidence']=prefix_summary
    def unknown(reason):
        out['request']=[dict(stage='ECS_SCOPE',status='UNKNOWN',reason=reason,evaluation_mode='PREDICTED_PATH')]
        out['first_request_stop']='ECS_SCOPE'
        return dict(out,status='UNKNOWN',reason=reason)
    if src['status']!='TASK_ENDPOINT_CANDIDATE' or dst['status']!='TASK_ENDPOINT_CANDIDATE':
        return unknown('TASK_ENDPOINT_NOT_CONFIRMED')
    a,b=src['endpoint'],dst['endpoint']
    if a['eni_id']==b['eni_id'] or a['private_ip']==b['private_ip']:
        return unknown('SAME_ENDPOINT_NOT_IN_SCOPE')
    out['path_kind']='SAME_SUBNET_DIRECT' if a['subnet_id']==b['subnet_id'] else 'CROSS_SUBNET_DIRECT'
    vpc=inv['Vpcs'][0]
    if vpc.get('State')!='available':
        return unknown('VPC_STATE_NOT_AVAILABLE')
    primary=IPv4Network(vpc['CidrBlock'])
    for e in (a,b):
        ip=IPv4Address(e['private_ip'])
        matches=[s for s in inv['Subnets'] if ip in IPv4Network(s['CidrBlock'])]
        if len(matches)!=1 or matches[0]['SubnetId']!=e['subnet_id']:
            return unknown('SUBNET_MISSING_OR_AMBIGUOUS')
        net=IPv4Network(matches[0]['CidrBlock'])
        if not net.subnet_of(primary) or int(ip)-int(net.network_address)<4 or ip==net.broadcast_address:
            return unknown('TASK_SUBNET_ADDRESS_OUT_OF_SCOPE')
    if a['subnet_id']==b['subnet_id'] and any(same_subnet_delivery(inv,x,y)['status']!='ALLOW_CANDIDATE' for x,y in ((a,b),(b,a))):
        return unknown('SAME_SUBNET_NORMAL_LOCAL_CONFIGURATION_UNCONFIRMED')
    groups={g['GroupId']:g for g in inv['SecurityGroups']}
    acls=inv['NetworkAcls']
    def direction(start,end,port,reply,enabled):
        same=start['subnet_id']==end['subnet_id']
        local=same_subnet_delivery(inv,start,end) if same else {}
        route=lookup_observed_route(inventory_raw,start['subnet_id'],end['private_ip']) if not same else local
        direct = route['status'] in ('LOCAL_CANDIDATE','ALLOW_CANDIDATE') and not any(t.get('PropagatingVgws') for t in inv['RouteTables'] if t['RouteTableId']==route.get('route_table_id'))
        route_status={'LOCAL_CANDIDATE':'ALLOW_CANDIDATE','ALLOW_CANDIDATE':'ALLOW_CANDIDATE','BLOCKED':'BLOCKED'}.get(route['status'],'UNKNOWN')
        conditional=_result('CONDITIONAL','REQUIRES_ESTABLISHED_TRACKED_REQUEST')
        rows=[('SOURCE_SG_EGRESS',conditional if reply else _sg(groups,start,end,True,port,direct_same_vpc=direct,prefix_lists=prefix_lists),start),
              ('SOURCE_NACL_EGRESS',subnet_policy(_acl,inv,start,end,True,port,local),start),
              ('LOCAL_ROUTE',_result(route_status,route['reason'],route_evidence=route),start),
              ('DESTINATION_NACL_INGRESS',subnet_policy(_acl,inv,end,start,False,port,local),end),
              ('DESTINATION_SG_INGRESS',conditional if reply else _sg(groups,end,start,False,port,direct_same_vpc=direct,prefix_lists=prefix_lists),end)]
        active=enabled; stop=None; status='CONDITIONAL_CANDIDATE' if enabled else 'NOT_EVALUATED'; checks=[]
        for stage,detail,endpoint in rows:
            mode=('CONDITIONAL_CHECK' if reply else 'PREDICTED_PATH') if active else 'INDEPENDENT_CHECK'
            checks.append(dict(detail,stage=stage,evaluation_mode=mode,eni_id=endpoint['eni_id'],subnet_id=endpoint['subnet_id']))
            if active and not (detail['status'] in ('ALLOW_CANDIDATE','NOT_APPLICABLE') or (reply and detail['status']=='CONDITIONAL')):
                stop=stage;status='BLOCKED' if detail['status']=='BLOCKED' else 'UNKNOWN';active=False
        return checks,status,stop
    out['request'],out['request_status'],out['first_request_stop']=direction(a,b,destination_port,False,True)
    out['response'],out['response_status'],out['conditional_first_response_stop']=direction(b,a,source_port,True,out['request_status']=='CONDITIONAL_CANDIDATE')
    if out['request_status']=='BLOCKED':
        out['session_status']='BLOCKED'
    return dict(out,status='ECS_TASK_PATH_CONSTRAINTS_CANDIDATE',reason='STATIC_TASK_ENI_ROUTE_AND_POLICY_CHECKS')
