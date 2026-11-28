"""Conditional internal ELB-to-awsvpc Task network legs, with explicit node evidence."""
import hashlib
from ipaddress import IPv4Address, IPv4Network
from backend.aws.ecs_service_evidence import inspect_ecs_service
from backend.aws.endpoint_evidence import lookup_observed_endpoint
from backend.aws.peering_evidence import _load, _timestamp, _primary_only
from backend.aws.policy_evidence import _sg, _acl, _port
from backend.aws.prefix_list_evidence import load_prefix_lists
from backend.aws.local_delivery_evidence import same_subnet_delivery, subnet_policy
from backend.aws.route_evidence import lookup_observed_route
from backend.aws.load_balancer_evidence import _id, _arn
from backend.iac.plan_adapter import _read

FORMAT='cloudpath-ecs-elb-node-path-v1'


def inspect_ecs_elb_paths(inventory_raw, ecs_raw, service_raw, elbv2_raw, health_raw, node_raw,
                          service_arn, load_balancer_id, listener_port, client_ip, *,
                          node_eni_id, client_port, backend_source_port, health_source_port,
                          rules_raw=None, host=None, path=None, attributes_raw=None, prefix_list_raw=None):
    """Node-specific conditional checks; no actual LB target selection or session guarantee."""
    if not all(_port(p) for p in (client_port,backend_source_port,health_source_port)):
        raise ValueError('Expected explicit TCP ports 1..65535')
    if not isinstance(node_eni_id,str): raise ValueError('Expected node ENI ID')
    service=inspect_ecs_service(inventory_raw,ecs_raw,service_raw,elbv2_raw,health_raw,
                               service_arn,load_balancer_id,listener_port,client_ip,
                               rules_raw=rules_raw,host=host,path=path,attributes_raw=attributes_raw)
    identity,meta,inv=_load(inventory_raw); elb=_read(elbv2_raw); doc=_read(node_raw)
    if set(doc)!={'format','collected_at','inventory_identity','elbv2_input_identity','complete','load_balancer_arn','nodes','health_check','alb_cross_zone_enabled'} or doc['format']!=FORMAT:
        raise ValueError('Invalid ECS ELB node path wrapper')
    if not isinstance(doc['nodes'],list) or not 1<=len(doc['nodes'])<=100: raise ValueError('Invalid node evidence list')
    nodes={}
    for row in doc['nodes']:
        if not isinstance(row,dict) or set(row)!={'eni_id','private_ip','subnet_id'} or not all(isinstance(v,str) for v in row.values()) or row['eni_id'] in nodes:
            raise ValueError('Invalid or duplicate node record')
        IPv4Address(row['private_ip']); nodes[row['eni_id']]=row
    hc=doc['health_check']
    if not isinstance(hc,dict) or set(hc)!={'target_group_arn','enabled','protocol','port','path'}: raise ValueError('Invalid health configuration')
    _arn(hc['target_group_arn'],'targetgroup'); _arn(doc['load_balancer_arn'],'loadbalancer')
    if doc['alb_cross_zone_enabled'] is not None and type(doc['alb_cross_zone_enabled']) is not bool: raise ValueError('Invalid ALB cross-zone assertion')
    times=[meta['collected_at'],*(_read(r)['collected_at'] for r in (ecs_raw,service_raw,elbv2_raw,health_raw,node_raw,rules_raw,attributes_raw) if r is not None)]
    stamps=[_timestamp(t) for t in times]; gap=(max(stamps)-min(stamps)).total_seconds()
    out=dict(analysis_type='STATIC_AWS_ECS_ELB_PATH_CONSTRAINTS',input_identity=identity,
             node_input_identity='sha256-ecs-elb-node-path-v1:'+hashlib.sha256(node_raw).hexdigest(),
             service_correlation=service,time_gap_seconds=gap,node=None,client=None,frontend=None,targets=[],
             target_selection='NOT_EVALUATED',session_status='UNKNOWN',live_observation=False,
             limitations=['Offline asserted node-to-LB mapping; not authenticated or a runtime selection.',
                          'Internal IPv4, same VPC, one selected node, distinct ENI direct legs; conditional same-subnet delivery.',
                          'ALB and non-preserving NLB backend tuples are conditional; NLB preserved client backend not composed.',
                          'SG refs require confirmed direct local ENI membership; prefix lists optional version-bound evidence.',
                          'Frontend/backend/health checks are separate; no DNS, TLS, application, actual health or tracked state verification.'])
    def finish(reason,status='UNKNOWN'): return dict(out,status=status,reason=reason)
    if service['status']!='SERVICE_ELB_CORRELATION_CANDIDATE': return finish('SERVICE_CORRELATION_UNCONFIRMED')
    base=service['elb_analysis']['configuration']; lb=base['load_balancer']; kind=lb['type']
    if lb['scheme']!='internal' or not _primary_only(inv['Vpcs'][0]) or inv['Vpcs'][0].get('State')!='available': return finish('INTERNAL_PRIMARY_VPC_SCOPE_REQUIRED')
    matches=[x for x in elb['LoadBalancers'] if _id(x['LoadBalancerArn'])==load_balancer_id]
    if len(matches)!=1 or matches[0]['LoadBalancerArn']!=doc['load_balancer_arn'] or doc['inventory_identity']!=identity or doc['elbv2_input_identity']!=base['elbv2_input_identity'] or doc['complete'] is not True:
        return finish('NODE_EVIDENCE_IDENTITY_OR_COMPLETENESS_UNCONFIRMED')
    if gap>300: return finish('SNAPSHOT_TIME_GAP')
    if hc['target_group_arn']!=service['service_binding']['target_group_arn']: return finish('HEALTH_GROUP_IDENTITY_MISMATCH')
    groups={g['GroupId']:g for g in inv['SecurityGroups']}; ids=matches[0].get('SecurityGroups')
    if not isinstance(ids,list) or not all(isinstance(g,str) and g in groups for g in ids) or len(ids)!=len(set(ids)) or (kind=='application' and not ids): return finish('LB_SECURITY_GROUPS_UNCONFIRMED')
    subnets={s['SubnetId']:s for s in inv['Subnets']}; zones={s['subnet_id']:s['availability_zone'] for s in lb['subnets']}; primary=IPv4Network(inv['Vpcs'][0]['CidrBlock'])
    def endpoint_valid(e):
        ip=IPv4Address(e['private_ip']); candidates=[s for s in subnets.values() if ip in IPv4Network(s['CidrBlock'])]
        if len(candidates)!=1 or candidates[0]['SubnetId']!=e['subnet_id'] or candidates[0].get('State')!='available': return False
        net=IPv4Network(candidates[0]['CidrBlock']); return net.subnet_of(primary) and int(ip)-int(net.network_address)>=4 and ip!=net.broadcast_address
    def correlate(row):
        candidates=[e for e in inv['NetworkInterfaces'] if e.get('NetworkInterfaceId')==row['eni_id']]
        owners=[e for e in inv['NetworkInterfaces'] if e.get('PrivateIpAddress')==row['private_ip'] or any(a.get('PrivateIpAddress')==row['private_ip'] for a in e.get('PrivateIpAddresses',[]))]
        if len(candidates)!=1 or owners!=candidates or row['subnet_id'] not in zones: return None
        e=candidates[0]; addr=e.get('PrivateIpAddresses',[]); attached=e.get('Attachment',{})
        if (e.get('SubnetId')!=row['subnet_id'] or e.get('PrivateIpAddress')!=row['private_ip'] or len(addr)!=1 or addr[0].get('PrivateIpAddress')!=row['private_ip'] or addr[0].get('Primary') is not True or e.get('Status')!='in-use' or e.get('RequesterManaged') is not True or e.get('InterfaceType')!=('load_balancer' if kind=='application' else 'network_load_balancer') or attached.get('InstanceId') or e.get('Association') or addr[0].get('Association')): return None
        eni_groups=[g['GroupId'] for g in e['Groups']]
        if sorted(eni_groups)!=sorted(ids): return None
        candidate=dict(row,security_group_ids=ids,availability_zone=zones[row['subnet_id']],status='LB_NODE_ENI_CORRELATION_CANDIDATE')
        return candidate if endpoint_valid(candidate) else None
    if node_eni_id not in nodes: return finish('SELECTED_NODE_NOT_IN_EVIDENCE')
    node=correlate(nodes[node_eni_id]); client=lookup_observed_endpoint(inventory_raw,client_ip)
    if node is None: return finish('LB_NODE_ENI_UNCONFIRMED')
    out['node']=node;out['client']=client
    if client['status']!='ENDPOINT_CANDIDATE' or not endpoint_valid(client): return finish('CLIENT_ENDPOINT_UNCONFIRMED')
    prefix_lists,prefix_summary=load_prefix_lists(prefix_list_raw,identity,meta['region'],meta['collected_at'],additional_times=times[1:])
    if prefix_summary is not None: out['prefix_list_evidence']=prefix_summary
    def flow(a,b,sport,dport,scope):
        result=dict(scope=scope,source_ip=a['private_ip'],destination_ip=b['private_ip'],source_port=sport,destination_port=dport,request=[],response=[],request_status='UNKNOWN',response_status='NOT_EVALUATED',first_request_stop=None,conditional_first_response_stop=None)
        if a['eni_id']==b['eni_id'] or a['private_ip']==b['private_ip']:
            result.update(first_request_stop='PATH_SCOPE',request=[dict(stage='PATH_SCOPE',status='UNKNOWN',reason='DISTINCT_ENDPOINTS_REQUIRED',evaluation_mode='PREDICTED_PATH')]); return result
        if a['subnet_id']==b['subnet_id'] and any(same_subnet_delivery(inv,x,y)['status']!='ALLOW_CANDIDATE' for x,y in ((a,b),(b,a))):
            result.update(first_request_stop='PATH_SCOPE',request=[dict(stage='PATH_SCOPE',status='UNKNOWN',reason='SAME_SUBNET_NORMAL_LOCAL_CONFIGURATION_UNCONFIRMED',evaluation_mode='PREDICTED_PATH')]); return result
        def direction(start,end,port,reply,enabled):
            same=start['subnet_id']==end['subnet_id']; local=same_subnet_delivery(inv,start,end) if same else {}
            r=local if same else lookup_observed_route(inventory_raw,start['subnet_id'],end['private_ip']); direct=r['status'] in ('LOCAL_CANDIDATE','ALLOW_CANDIDATE') and not any(t.get('PropagatingVgws') for t in inv['RouteTables'] if t['RouteTableId']==r.get('route_table_id'))
            def sg(ep,peer,egress):
                if not ep['security_group_ids']: return dict(status='NOT_APPLICABLE',reason='EXPLICIT_NLB_WITHOUT_SG')
                if reply: return dict(status='CONDITIONAL',reason='REQUIRES_ESTABLISHED_TRACKED_REQUEST')
                return _sg(groups,ep,peer,egress,port,direct_same_vpc=direct,prefix_lists=prefix_lists)
            rows=[('SOURCE_SG_EGRESS',sg(start,end,True)),('SOURCE_NACL_EGRESS',subnet_policy(_acl,inv,start,end,True,port,local)),('LOCAL_ROUTE',dict(status='ALLOW_CANDIDATE' if direct else 'BLOCKED' if r['status']=='BLOCKED' else 'UNKNOWN',reason=r['reason'] if direct or r['status']!='LOCAL_CANDIDATE' else 'PROPAGATION_UNCONFIRMED',route_evidence=r)),('DESTINATION_NACL_INGRESS',subnet_policy(_acl,inv,end,start,False,port,local)),('DESTINATION_SG_INGRESS',sg(end,start,False))]
            active=enabled;status='CONDITIONAL_CANDIDATE' if enabled else 'NOT_EVALUATED';stop=None;checks=[]
            for stage,detail in rows:
                checks.append(dict(detail,stage=stage,evaluation_mode=('CONDITIONAL_CHECK' if reply else 'PREDICTED_PATH') if active else 'INDEPENDENT_CHECK'))
                if active and detail['status'] not in ('ALLOW_CANDIDATE','NOT_APPLICABLE','CONDITIONAL'):
                    status='BLOCKED' if detail['status']=='BLOCKED' else 'UNKNOWN';stop=stage;active=False
            return checks,status,stop
        result['request'],result['request_status'],result['first_request_stop']=direction(a,b,dport,False,True)
        result['response'],result['response_status'],result['conditional_first_response_stop']=direction(b,a,sport,True,result['request_status']=='CONDITIONAL_CANDIDATE')
        return result
    out['frontend']=flow(client,node,client_port,listener_port,'CONDITIONAL_CLIENT_TO_LB_NODE')
    fwd=service['elb_analysis']['forwarding']; preserve=kind=='network' and fwd['address_processing']['preserve_client_ip']
    cross=doc['alb_cross_zone_enabled'] if kind=='application' else fwd['cross_zone']['enabled']
    for reg in service['registrations']:
        ep=reg['endpoint'];port=reg['registered_port']; row=dict(task_arn=reg['task_arn'],endpoint=ep,registered_port=port,health_state=reg['health_state'],backend=None,health_check=None,backend_status='UNKNOWN',health_check_status='UNKNOWN',backend_reason=None,health_check_reason=None,composition_status='UNKNOWN');out['targets'].append(row)
        if reg['status']!='REGISTRATION_MATCH_CANDIDATE' or not ep or not endpoint_valid(ep) or ep['subnet_id'] not in zones and ep['availability_zone'] not in zones.values():
            row.update(backend_reason='TARGET_SCOPE_UNCONFIRMED',health_check_reason='TARGET_SCOPE_UNCONFIRMED');continue
        same_zone=node['availability_zone']==ep['availability_zone']
        if preserve:
            row['backend_reason']='NLB_PRESERVED_CLIENT_PATH_NOT_COMPOSED';row['backend_source_ip_candidate']=client_ip
        elif kind=='network' and fwd['proxy_protocol_v2']:
            row['backend_reason']='NLB_PROXY_PROTOCOL_SCOPE_UNSUPPORTED'
        elif not same_zone and cross is not True:
            row['backend_reason']='CROSS_ZONE_ELIGIBILITY_UNCONFIRMED'
        else:
            row['backend']=flow(node,ep,backend_source_port,port,'INDEPENDENT_CONDITIONAL_LB_TO_TASK');row['backend_status']=row['backend']['request_status'];row['backend_reason']=row['backend']['first_request_stop']
            if out['frontend']['request_status']=='CONDITIONAL_CANDIDATE' and out['frontend']['response_status']=='CONDITIONAL_CANDIDATE' and row['backend_status']=='CONDITIONAL_CANDIDATE' and row['backend']['response_status']=='CONDITIONAL_CANDIDATE': row['composition_status']='TWO_LEGS_CONDITIONAL_CANDIDATE'
        hp=port if hc['port']=='traffic-port' else hc['port']; allowed=('HTTP','HTTPS') if kind=='application' else ('TCP','HTTP','HTTPS')
        if hc['enabled'] is not True or hc['protocol'] not in allowed or not _port(hp) or (hc['protocol'] in ('HTTP','HTTPS') and (not isinstance(hc['path'],str) or not hc['path'].startswith('/'))) or (hc['protocol']=='TCP' and hc['path'] is not None):
            row['health_check_reason']='HEALTH_CONFIGURATION_UNSUPPORTED';continue
        row['health_check']=flow(node,ep,health_source_port,hp,'INDEPENDENT_CONDITIONAL_HEALTH_CHECK');row['health_check_status']=row['health_check']['request_status'];row['health_check_reason']=row['health_check']['first_request_stop']
    return finish('INDEPENDENT_NODE_SPECIFIC_LEG_CHECKS','ECS_ELB_PATH_CONSTRAINTS_CANDIDATE')
