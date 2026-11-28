"""Shared conditional direct private IPv4 service TCP policy checks."""
from backend.aws.policy_evidence import _sg, _acl, _result
from backend.aws.local_delivery_evidence import same_subnet_delivery, subnet_policy
from backend.aws.route_evidence import lookup_observed_route


def evaluate_direct_service_tcp(out, inventory_raw, inv, a, b, destination_port, source_port, prefix, np):
    """Mutate only result dict; callers establish endpoint ownership and scope."""
    groups={g['GroupId']:g for g in inv['SecurityGroups']}
    def direction(start,end,port,reply,enabled):
        same=start['subnet_id']==end['subnet_id']; local=same_subnet_delivery(inv,start,end,prefix_lists=prefix or None) if same else {}
        route=local if same else lookup_observed_route(inventory_raw,start['subnet_id'],end['private_ip'],prefix_lists=prefix or None)
        direct=route['status'] in ('LOCAL_CANDIDATE','ALLOW_CANDIDATE') and not any(t.get('PropagatingVgws') for t in inv['RouteTables'] if t['RouteTableId']==route.get('route_table_id'))
        route_status='ALLOW_CANDIDATE' if direct else 'BLOCKED' if route['status']=='BLOCKED' else 'UNKNOWN'
        conditional=_result('CONDITIONAL','REQUIRES_ESTABLISHED_TRACKED_REQUEST')
        checks=[('SOURCE_SG_EGRESS',conditional if reply else _sg(groups,start,end,True,port,direct_same_vpc=direct,prefix_lists=prefix),start),
                ('SOURCE_NACL_EGRESS',subnet_policy(_acl,inv,start,end,True,port,local),start),
                ('LOCAL_ROUTE',_result(route_status,route['reason'] if direct or route['status'] not in ('LOCAL_CANDIDATE','ALLOW_CANDIDATE') else 'PROPAGATION_UNCONFIRMED',route_evidence=route),start),
                ('DESTINATION_NACL_INGRESS',subnet_policy(_acl,inv,end,start,False,port,local),end),
                ('DESTINATION_SG_INGRESS',conditional if reply else _sg(groups,end,start,False,port,direct_same_vpc=direct,prefix_lists=prefix),end)]
        if np is not None:
            if reply: checks.append(('DESTINATION_NETWORK_POLICY_INGRESS',_result('CONDITIONAL','REPLY_TO_ALLOWED_CONNECTION_ASSUMED'),end))
            else: checks.insert(0,('SOURCE_NETWORK_POLICY_EGRESS',np,start))
        active=enabled;status='CONDITIONAL_CANDIDATE' if enabled else 'NOT_EVALUATED';stop=None;result=[]
        for stage,detail,item in checks:
            result.append(dict(detail,stage=stage,eni_id=item['eni_id'],subnet_id=item['subnet_id'],evaluation_mode=('CONDITIONAL_CHECK' if reply else 'PREDICTED_PATH') if active else 'INDEPENDENT_CHECK'))
            if active and not (detail['status'] in ('ALLOW_CANDIDATE','NOT_APPLICABLE') or (reply and detail['status']=='CONDITIONAL')):
                stop=stage;status='BLOCKED' if detail['status']=='BLOCKED' else 'UNKNOWN';active=False
        return result,status,stop
    out['request'],out['request_status'],out['first_request_stop']=direction(a,b,destination_port,False,True)
    out['response'],out['response_status'],out['conditional_first_response_stop']=direction(b,a,source_port,True,out['request_status']=='CONDITIONAL_CANDIDATE')
    if out['request_status']=='BLOCKED': out['session_status']='BLOCKED'
