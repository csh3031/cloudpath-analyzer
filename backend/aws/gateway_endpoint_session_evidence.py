"""Source-bound offline Gateway Endpoint TCP/443 constraints, not service authorization."""
import hashlib
from ipaddress import IPv4Address, IPv4Network
from backend.aws.vpc_endpoint_evidence import inspect_vpc_endpoint
from backend.aws.endpoint_evidence import lookup_observed_endpoint
from backend.aws.ecs_task_evidence import inspect_ecs_task
from backend.aws.eks_pod_evidence import inspect_eks_pod, index, rows, obj
from backend.aws.eks_session_evidence import FORMAT as NP_FORMAT, PROFILE, policy_check
from backend.aws.peering_evidence import _load, _timestamp
from backend.aws.policy_evidence import _port, _result
from backend.aws.prefix_list_evidence import load_prefix_lists
from backend.aws.route_evidence import select_subnet_ipv4_route
from backend.aws.peering_evidence import TARGET_KEYS
from backend.aws.policy_evidence import _sg, _acl
from backend.iac.plan_adapter import _read

FORMAT = 'cloudpath-gateway-endpoint-path-v1'


def analyze_gateway_endpoint_session(inventory_raw, endpoint_raw, observation_raw, endpoint_id, source_kind, source_port, *,
                                    client_ip=None, ecs_raw=None, task_id=None, eks_raw=None, policy_raw=None,
                                    namespace=None, pod_name=None, prefix_list_raw=None):
    """One asserted service DNS answer, source tuple and selected Gateway route.

    Alternate routing is reported but not traversed. No service-side ENI/SG or
    actual return routing, TLS, policy or API success is inferred.
    """
    if not _port(source_port) or source_kind not in ('ec2','ecs','eks'):
        raise ValueError('Expected explicit TCP source port and source kind')
    identity,meta,inv=_load(inventory_raw)
    cfg=inspect_vpc_endpoint(inventory_raw,endpoint_raw,endpoint_id)
    times=[meta['collected_at'],_read(endpoint_raw)['collected_at']]
    if source_kind=='ec2':
        if not isinstance(client_ip,str) or any(x is not None for x in (ecs_raw,task_id,eks_raw,policy_raw,namespace,pod_name)): raise ValueError('Expected EC2 client IP only')
        source=lookup_observed_endpoint(inventory_raw,client_ip); a=source if source['status']=='ENDPOINT_CANDIDATE' else None
    elif source_kind=='ecs':
        if ecs_raw is None or task_id is None or any(x is not None for x in (client_ip,eks_raw,policy_raw,namespace,pod_name)): raise ValueError('Expected ECS task evidence and ID only')
        source=inspect_ecs_task(inventory_raw,ecs_raw,task_id); a=source['endpoint'] if source['status']=='TASK_ENDPOINT_CANDIDATE' else None
        times.append(_read(ecs_raw)['collected_at'])
    else:
        if eks_raw is None or policy_raw is None or namespace is None or pod_name is None or any(x is not None for x in (client_ip,ecs_raw,task_id)): raise ValueError('Expected EKS Pod and NetworkPolicy evidence')
        source=inspect_eks_pod(inventory_raw,eks_raw,namespace,pod_name)
        a=dict(source['endpoint'],security_group_ids=source['endpoint']['eni_security_group_ids']) if source['status']=='POD_ENDPOINT_CANDIDATE' else None
        eks=_read(eks_raw); npdoc=_read(policy_raw)
        if set(npdoc)!={'format','collected_at','eks_input_identity','complete','profile','networkPolicies'} or npdoc['format']!=NP_FORMAT: raise ValueError('Expected normalized NetworkPolicy evidence wrapper')
        times.extend((eks['collected_at'],npdoc['collected_at']))
    out=dict(analysis_type='STATIC_AWS_GATEWAY_ENDPOINT_TCP_CONSTRAINTS',input_identity=identity,
             endpoint_configuration=cfg,source_endpoint=source,destination_endpoint=None,dns_evidence=None,
             scenario=dict(source_kind=source_kind,endpoint_id=endpoint_id,protocol='tcp',source_port=source_port,destination_port=443),
             request=[],response=[],request_status='UNKNOWN',response_status='NOT_EVALUATED',first_request_stop=None,
             conditional_first_response_stop=None,session_status='UNKNOWN',authorization_status='NOT_EVALUATED',
             endpoint_policy_status='NOT_EVALUATED',tls_status='NOT_EVALUATED',live_observation=False,
             limitations=['Offline asserted source DNS view and complete AWS-managed list reads; no authenticated or live evidence.',
                          'One regional S3/DynamoDB IPv4 service endpoint name and one A answer; no actual DNS transport or multi-answer selection.',
                          'Direct untranslated source tuple only; EKS requires asserted no SNAT for the service address.',
                          'Selected gateway route and source-side policy checks only; alternative NAT/IGW routes are not composed.',
                          'Return assumes delivered tracked request and service return; no service-side ENI/SG, TLS, endpoint policy, IAM or API success.',
                          'No AWS API calls, DNS queries or packets.'])
    def unknown(reason):
        out['request']=[dict(stage='ENDPOINT_SCOPE',status='UNKNOWN',reason=reason,evaluation_mode='PREDICTED_PATH')]
        out['first_request_stop']='ENDPOINT_SCOPE'
        return dict(out,status='UNKNOWN',reason=reason)
    if cfg['status']!='VPC_ENDPOINT_CONFIGURATION_CANDIDATE': return unknown('ENDPOINT_CONFIGURATION_UNCONFIRMED')
    if cfg['endpoint_type']!='Gateway': return unknown('GATEWAY_ENDPOINT_REQUIRED')
    if a is None: return unknown('ENDPOINT_SOURCE_UNCONFIRMED')
    if observation_raw is None: return unknown('GATEWAY_DNS_EVIDENCE_MISSING')
    if not isinstance(observation_raw,bytes) or len(observation_raw)>5*1024*1024: raise ValueError('Invalid gateway path evidence size')
    doc=_read(observation_raw)
    fields={'format','inventory_identity','endpoint_input_identity','collected_at','complete','endpoint_id','hostname','source_ip','source_eni_id','resolver_scope','resolved_at','ttl_seconds','answers','direct_ipv4_no_translation'}
    if set(doc)!=fields or doc['format']!=FORMAT: raise ValueError('Expected normalized Gateway Endpoint path evidence wrapper')
    if not isinstance(doc['answers'],list) or len(doc['answers'])>32 or any(not isinstance(ip,str) for ip in doc['answers']): raise ValueError('Invalid DNS answer list')
    times.extend((doc['collected_at'],doc['resolved_at']))
    stamps=[_timestamp(t) for t in times];gap=(max(stamps)-min(stamps)).total_seconds();out['time_gap_seconds']=gap
    out['dns_evidence']=dict(input_identity='sha256-gateway-endpoint-path-v1:'+hashlib.sha256(observation_raw).hexdigest(),status='UNKNOWN')
    if doc['inventory_identity']!=identity or doc['endpoint_input_identity']!=cfg['endpoint_input_identity'] or doc['endpoint_id']!=endpoint_id or doc['source_ip']!=a['private_ip'] or doc['source_eni_id']!=a['eni_id']:
        return unknown('ENDPOINT_PATH_EVIDENCE_IDENTITY_MISMATCH')
    if doc['complete'] is not True or doc['resolver_scope']!='SOURCE_VPC_VIEW' or doc['direct_ipv4_no_translation'] is not True: return unknown('GATEWAY_PATH_PROFILE_UNCONFIRMED')
    service=cfg['service_name'].rsplit('.',1)[1]
    if doc['hostname']!=service+'.'+meta['region']+'.amazonaws.com': return unknown('GATEWAY_REGIONAL_DNS_NAME_UNCONFIRMED')
    ttl=doc['ttl_seconds'];resolved=_timestamp(doc['resolved_at']);collected=_timestamp(doc['collected_at'])
    if gap>300: return unknown('SNAPSHOT_TIME_GAP')
    if type(ttl) is not int or not 1<=ttl<=86400 or resolved>collected or (max(stamps)-resolved).total_seconds()>=ttl: return unknown('ENDPOINT_DNS_TIME_SCOPE_UNCONFIRMED')
    if len(doc['answers'])!=1: return unknown('ENDPOINT_DNS_SINGLE_IPV4_UNCONFIRMED')
    try: ip=str(IPv4Address(doc['answers'][0]))
    except ValueError: return unknown('ENDPOINT_DNS_SINGLE_IPV4_UNCONFIRMED')
    primary=IPv4Network(inv['Vpcs'][0]['CidrBlock']);addr=IPv4Address(a['private_ip']);dst=IPv4Address(ip)
    subnets=[s for s in inv['Subnets'] if addr in IPv4Network(s['CidrBlock'])]
    if len(subnets)!=1 or subnets[0]['SubnetId']!=a['subnet_id'] or subnets[0].get('State')!='available': return unknown('SUBNET_MISSING_OR_AMBIGUOUS')
    net=IPv4Network(subnets[0]['CidrBlock'])
    if not net.subnet_of(primary) or int(addr)-int(net.network_address)<4 or addr==net.broadcast_address: return unknown('ENDPOINT_SUBNET_ADDRESS_OUT_OF_SCOPE')
    if dst in primary or dst.is_multicast or dst.is_loopback or dst.is_link_local or dst.is_unspecified or any(dst in IPv4Network(s['CidrBlock']) for s in inv['Subnets']): return unknown('GATEWAY_EXTERNAL_SERVICE_ADDRESS_REQUIRED')
    prefix,summary=load_prefix_lists(prefix_list_raw,identity,meta['region'],meta['collected_at'],additional_times=times[1:])
    if summary is not None:
        out['prefix_list_evidence']=summary
        if (max(stamps+[_timestamp(_read(prefix_list_raw)['collected_at'])])-resolved).total_seconds()>=ttl:
            return unknown('ENDPOINT_DNS_TIME_SCOPE_UNCONFIRMED')
    pid=cfg['route_tables'][0]['destination_prefix_list_id']; pl=prefix.get(pid)
    if not pl or pl['reason'] or pl.get('kind')!='AWS_MANAGED' or pl.get('name')!=cfg['service_name']:
        return unknown('GATEWAY_SERVICE_PREFIX_LIST_UNCONFIRMED')
    if not any(dst in n for n in pl['networks']): return unknown('GATEWAY_DNS_ADDRESS_NOT_IN_SERVICE_PREFIX_LIST')
    # Logical service address only, never a fabricated ENI or security group.
    b=dict(kind='AWS_SERVICE_IPV4',service_name=cfg['service_name'],hostname=doc['hostname'],ip=ip,port=443,eni_id=None)
    out['destination_endpoint']=b
    out['dns_evidence'].update(status='GATEWAY_DNS_PREFIX_CORRELATION_CANDIDATE',hostname=doc['hostname'],ip=ip,resolved_at=doc['resolved_at'],ttl_seconds=ttl,prefix_list_id=pid)
    peer={'private_ip':ip}
    route=select_subnet_ipv4_route(inv,a['subnet_id'],dst,prefix_lists=prefix)
    out['route_selection']=route
    selected=route['selected_route'] or {};targets=[k for k in TARGET_KEYS if k in selected]
    bound=any(t['route_table_id']==route['route_table_id'] for t in cfg['route_tables'])
    selected_gateway=bound and targets in (['GatewayId'],['VpcEndpointId']) and selected.get(targets[0])==endpoint_id and selected.get('DestinationPrefixListId')==pid
    if route['status']=='ACTIVE_ROUTE_CANDIDATE' and selected_gateway and not any(t.get('PropagatingVgws') for t in inv['RouteTables'] if t['RouteTableId']==route['route_table_id']):
        route_check=_result('ALLOW_CANDIDATE','MATCHING_GATEWAY_ENDPOINT_ROUTE',route_evidence=route);out['path_kind']='GATEWAY_ENDPOINT'
    elif route['status']=='BLOCKED':
        route_check=_result('BLOCKED',route['reason'],route_evidence=route)
    else:
        reason=('GATEWAY_ROUTE_PROPAGATION_UNCONFIRMED' if selected_gateway else 'ALTERNATE_ROUTE_NOT_COMPOSED') if route['status']=='ACTIVE_ROUTE_CANDIDATE' else route['reason']
        route_check=_result('UNKNOWN',reason,route_evidence=route)
    np=None
    if source_kind=='eks':
        namespaces=index(eks['namespaces']); pods=index(eks['pods'],True); policies=index(npdoc['networkPolicies'],True); selected=pods[(namespace,pod_name)]
        profile=obj(npdoc['profile']); managed=any(o.get('controller') is True and o.get('kind') in ('ReplicaSet','StatefulSet','DaemonSet','Job') and isinstance(o.get('uid'),str) and o['uid'] for o in rows(selected['metadata'].get('ownerReferences',[])))
        if npdoc['eks_input_identity']!=source['eks_input_identity'] or npdoc['complete'] is not True or any(ns not in namespaces for ns,_ in policies) or set(profile)!=set(PROFILE) or any(type(profile[k]) is not type(v) or profile[k]!=v for k,v in PROFILE.items()) or not managed:
            np=_result('UNKNOWN','CNI_POLICY_APPLICABILITY_UNCONFIRMED')
        else:
            try: np=policy_check(policies,selected,None,namespaces,'Egress',None,443,external_ip=ip)
            except ValueError: np=_result('UNKNOWN','POLICY_SYNTAX_UNSUPPORTED')
        out['policy_input_identity']='sha256-eks-network-policy-v1:'+hashlib.sha256(policy_raw).hexdigest()
    groups={g['GroupId']:g for g in inv['SecurityGroups']}
    checks=[('SOURCE_SG_EGRESS',_sg(groups,a,peer,True,443,prefix_lists=prefix)),
            ('SOURCE_NACL_EGRESS',_acl(inv['NetworkAcls'],a,peer,True,443)),
            ('GATEWAY_ROUTE',route_check)]
    if np is not None: checks.insert(0,('SOURCE_NETWORK_POLICY_EGRESS',np))
    def evaluate(checks,reply,enabled):
        active=enabled;status='CONDITIONAL_CANDIDATE' if enabled else 'NOT_EVALUATED';stop=None;result=[]
        for stage,detail in checks:
            result.append(dict(detail,stage=stage,eni_id=a['eni_id'],subnet_id=a['subnet_id'],evaluation_mode=('CONDITIONAL_CHECK' if reply else 'PREDICTED_PATH') if active else 'INDEPENDENT_CHECK'))
            if active and detail['status'] not in (('ALLOW_CANDIDATE','CONDITIONAL') if reply else ('ALLOW_CANDIDATE',)):
                stop=stage;status='BLOCKED' if detail['status']=='BLOCKED' else 'UNKNOWN';active=False
        return result,status,stop
    out['request'],out['request_status'],out['first_request_stop']=evaluate(checks,False,True)
    replies=[('GATEWAY_RETURN',_result('CONDITIONAL','REQUIRES_SERVICE_RETURN_TO_SOURCE')),
             ('DESTINATION_NACL_INGRESS',_acl(inv['NetworkAcls'],a,peer,False,source_port)),
             ('DESTINATION_SG_INGRESS',_result('CONDITIONAL','REQUIRES_ESTABLISHED_TRACKED_REQUEST'))]
    if np is not None: replies.append(('DESTINATION_NETWORK_POLICY_INGRESS',_result('CONDITIONAL','REPLY_TO_ALLOWED_CONNECTION_ASSUMED')))
    out['response'],out['response_status'],out['conditional_first_response_stop']=evaluate(replies,True,out['request_status']=='CONDITIONAL_CANDIDATE')
    if out['request_status']=='BLOCKED':out['session_status']='BLOCKED'
    return dict(out,status='GATEWAY_ENDPOINT_PATH_CONSTRAINTS_CANDIDATE',reason='STATIC_GATEWAY_ROUTE_AND_SOURCE_POLICY_CHECKS')
