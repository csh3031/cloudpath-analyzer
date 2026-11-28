"""Source-bound offline Interface Endpoint TCP/443 constraints, not service authorization."""
import hashlib
from ipaddress import IPv4Address, IPv4Network
from backend.aws.vpc_endpoint_evidence import inspect_vpc_endpoint, _dns
from backend.aws.endpoint_evidence import lookup_observed_endpoint
from backend.aws.ecs_task_evidence import inspect_ecs_task
from backend.aws.eks_pod_evidence import inspect_eks_pod, index, rows, obj
from backend.aws.eks_session_evidence import FORMAT as NP_FORMAT, PROFILE, policy_check
from backend.aws.peering_evidence import _load, _timestamp
from backend.aws.policy_evidence import _port, _result
from backend.aws.prefix_list_evidence import load_prefix_lists
from backend.aws.direct_service_tcp import evaluate_direct_service_tcp
from backend.iac.plan_adapter import _read

FORMAT = 'cloudpath-interface-endpoint-path-v1'


def _explicit_name(host, cfg):
    # Only declared endpoint-specific names, not inferred service/private DNS.
    if not _dns(host) or host.startswith('*.') or not host.endswith('.vpce.amazonaws.com'):
        return False
    if not any(label.startswith(cfg['endpoint_id']+'-') for label in host.split('.')):
        return False
    for name in cfg['dns_entries']:
        if host == name:
            return True
        if name.startswith('*.') and host.endswith(name[1:]) and len(host.split('.')) == len(name.split('.')):
            return True
    return False


def analyze_interface_endpoint_session(inventory_raw, endpoint_raw, observation_raw, endpoint_id, source_kind, source_port, *,
                                       client_ip=None, ecs_raw=None, task_id=None, eks_raw=None, policy_raw=None,
                                       namespace=None, pod_name=None, prefix_list_raw=None):
    """One explicit source DNS answer for one ENI; no live selection or TLS/API claims."""
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
    out=dict(analysis_type='STATIC_AWS_INTERFACE_ENDPOINT_TCP_CONSTRAINTS', input_identity=identity,
             endpoint_configuration=cfg,source_endpoint=source,destination_endpoint=None,dns_evidence=None,
             scenario=dict(source_kind=source_kind,endpoint_id=endpoint_id,protocol='tcp',source_port=source_port,destination_port=443),
             request=[],response=[],request_status='UNKNOWN',response_status='NOT_EVALUATED',first_request_stop=None,
             conditional_first_response_stop=None,session_status='UNKNOWN',authorization_status='NOT_EVALUATED',
             endpoint_policy_status='NOT_EVALUATED',tls_status='NOT_EVALUATED',live_observation=False,
             limitations=['Offline normalized snapshots and source-specific DNS assertions, not authenticated or live.',
                          'Explicit endpoint-specific DNS name and one IPv4 A answer only; no inferred private DNS, regional service DNS, DNS transport or multi-answer selection.',
                          'Same primary VPC direct TCP/443; no translation, middlebox, cross-VPC or service-side forwarding.',
                          'Ordinary EKS VPC CNI non-Pod egress policy under direct untranslated profile only.',
                          'Conditional response assumes delivered request and tracking; no TLS, endpoint policy, IAM or AWS API success.',
                          'No AWS API calls, DNS queries or packets.'])
    def unknown(reason):
        out['request']=[dict(stage='ENDPOINT_SCOPE',status='UNKNOWN',reason=reason,evaluation_mode='PREDICTED_PATH')]
        out['first_request_stop']='ENDPOINT_SCOPE'
        return dict(out,status='UNKNOWN',reason=reason)
    if cfg['status']!='VPC_ENDPOINT_CONFIGURATION_CANDIDATE': return unknown('ENDPOINT_CONFIGURATION_UNCONFIRMED')
    if cfg['endpoint_type']!='Interface': return unknown('INTERFACE_ENDPOINT_REQUIRED')
    if a is None: return unknown('ENDPOINT_SOURCE_UNCONFIRMED')
    if observation_raw is None: return unknown('ENDPOINT_DNS_ENI_EVIDENCE_MISSING')
    if not isinstance(observation_raw,bytes) or len(observation_raw)>5*1024*1024: raise ValueError('Invalid endpoint path evidence size')
    doc=_read(observation_raw)
    fields={'format','inventory_identity','endpoint_input_identity','collected_at','complete','endpoint_id','hostname','source_ip','source_eni_id','resolver_scope','resolved_at','ttl_seconds','answers','eni_id','direct_private_ipv4_no_translation'}
    if set(doc)!=fields or doc['format']!=FORMAT: raise ValueError('Expected normalized Interface Endpoint path evidence wrapper')
    if not isinstance(doc['answers'],list) or len(doc['answers'])>32 or any(not isinstance(ip,str) for ip in doc['answers']): raise ValueError('Invalid DNS answer list')
    times.extend((doc['collected_at'],doc['resolved_at']))
    stamps=[_timestamp(t) for t in times];gap=(max(stamps)-min(stamps)).total_seconds();out['time_gap_seconds']=gap
    out['dns_evidence']=dict(input_identity='sha256-interface-endpoint-path-v1:'+hashlib.sha256(observation_raw).hexdigest(),status='UNKNOWN')
    if doc['inventory_identity']!=identity or doc['endpoint_input_identity']!=cfg['endpoint_input_identity'] or doc['endpoint_id']!=endpoint_id or doc['source_ip']!=a['private_ip'] or doc['source_eni_id']!=a['eni_id']:
        return unknown('ENDPOINT_PATH_EVIDENCE_IDENTITY_MISMATCH')
    if doc['complete'] is not True or doc['resolver_scope']!='SOURCE_VPC_VIEW' or doc['direct_private_ipv4_no_translation'] is not True: return unknown('ENDPOINT_PATH_PROFILE_UNCONFIRMED')
    if not _explicit_name(doc['hostname'],cfg): return unknown('ENDPOINT_EXPLICIT_DNS_NAME_UNCONFIRMED')
    ttl=doc['ttl_seconds'];resolved=_timestamp(doc['resolved_at']);collected=_timestamp(doc['collected_at'])
    if gap>300: return unknown('SNAPSHOT_TIME_GAP')
    if type(ttl) is not int or not 1<=ttl<=86400 or resolved>collected or (max(stamps)-resolved).total_seconds()>=ttl: return unknown('ENDPOINT_DNS_TIME_SCOPE_UNCONFIRMED')
    if len(doc['answers'])!=1: return unknown('ENDPOINT_DNS_SINGLE_IPV4_UNCONFIRMED')
    try: ip=str(IPv4Address(doc['answers'][0]))
    except ValueError: return unknown('ENDPOINT_DNS_SINGLE_IPV4_UNCONFIRMED')
    candidates=[e for e in cfg['network_interfaces'] if e['private_ip']==ip and e['eni_id']==doc['eni_id']]
    if len(candidates)!=1: return unknown('ENDPOINT_DNS_ENI_MISMATCH')
    b=dict(candidates[0],hostname=doc['hostname'],port=443,endpoint_id=endpoint_id)
    if a['eni_id']==b['eni_id'] or a['private_ip']==b['private_ip']: return unknown('ENDPOINT_SOURCE_DESTINATION_OVERLAP')
    if source_kind=='ecs' and any(x.get('name')=='networkInterfaceId' and x.get('value')==b['eni_id'] for t in _read(ecs_raw)['tasks'] for att in rows(t.get('attachments',[])) for x in rows(att.get('details',[]))): return unknown('ENDPOINT_ENI_OWNERSHIP_CONFLICT')
    if source_kind=='eks' and any(obj(p.get('status',{})).get('podIP')==ip or any(x.get('ip')==ip for x in rows(obj(p.get('status',{})).get('podIPs',[]))) for p in eks['pods']): return unknown('ENDPOINT_ENI_OWNERSHIP_CONFLICT')
    primary=IPv4Network(inv['Vpcs'][0]['CidrBlock'])
    for item in (a,b):
        addr=IPv4Address(item['private_ip']);subnets=[s for s in inv['Subnets'] if addr in IPv4Network(s['CidrBlock'])]
        if len(subnets)!=1 or subnets[0]['SubnetId']!=item['subnet_id'] or subnets[0].get('State')!='available': return unknown('SUBNET_MISSING_OR_AMBIGUOUS')
        net=IPv4Network(subnets[0]['CidrBlock'])
        if not net.subnet_of(primary) or int(addr)-int(net.network_address)<4 or addr==net.broadcast_address: return unknown('ENDPOINT_SUBNET_ADDRESS_OUT_OF_SCOPE')
    out['destination_endpoint']=b
    out['dns_evidence'].update(status='ENDPOINT_DNS_ENI_CORRELATION_CANDIDATE',hostname=doc['hostname'],ip=ip,eni_id=b['eni_id'],resolved_at=doc['resolved_at'],ttl_seconds=ttl)
    out['path_kind']='SAME_SUBNET_DIRECT' if a['subnet_id']==b['subnet_id'] else 'CROSS_SUBNET_DIRECT'
    prefix,summary=load_prefix_lists(prefix_list_raw,identity,meta['region'],meta['collected_at'],additional_times=times[1:])
    if summary is not None: out['prefix_list_evidence']=summary
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
    evaluate_direct_service_tcp(out,inventory_raw,inv,a,b,443,source_port,prefix,np)
    return dict(out,status='INTERFACE_ENDPOINT_PATH_CONSTRAINTS_CANDIDATE',reason='STATIC_INTERFACE_ENDPOINT_ENI_ROUTE_AND_POLICY_CHECKS')
