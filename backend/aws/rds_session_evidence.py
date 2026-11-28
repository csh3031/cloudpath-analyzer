"""Conditional private RDS instance TCP constraints; submitted DNS/ENI assertions only."""
import hashlib
from ipaddress import IPv4Address, IPv4Network
from backend.aws.rds_evidence import inspect_rds_configuration
from backend.aws.endpoint_evidence import lookup_observed_endpoint
from backend.aws.ecs_task_evidence import inspect_ecs_task
from backend.aws.eks_pod_evidence import inspect_eks_pod, index, rows, obj
from backend.aws.eks_session_evidence import FORMAT as NP_FORMAT, PROFILE, policy_check
from backend.aws.peering_evidence import _load, _timestamp, _primary_only
from backend.aws.policy_evidence import _port, _result
from backend.aws.direct_service_tcp import evaluate_direct_service_tcp
from backend.aws.prefix_list_evidence import load_prefix_lists
from backend.iac.plan_adapter import _read

FORMAT='cloudpath-rds-instance-path-v1'
CLUSTER_FORMAT='cloudpath-rds-cluster-path-v1'


def analyze_rds_session(inventory_raw, rds_raw, observation_raw, identifier, source_kind, source_port, *,
                        client_ip=None, ecs_raw=None, task_id=None, eks_raw=None, policy_raw=None,
                        namespace=None, pod_name=None, prefix_list_raw=None, endpoint_kind=None):
    """One instance or cluster endpoint, explicit source DNS view, no live DNS or packets.

    The binding is a normalized assertion, not proof of RDS ownership or DNS authenticity.
    No runtime target selection, failover, TLS, database authentication or SQL evaluation.
    """
    if not _port(source_port) or source_kind not in ('ec2','ecs','eks'):
        raise ValueError('Expected explicit TCP source port and source kind')
    if endpoint_kind not in (None,'WRITER','READER'):
        raise ValueError('Expected WRITER or READER cluster endpoint')
    cluster=endpoint_kind is not None
    identity,meta,inv=_load(inventory_raw)
    cfg=inspect_rds_configuration(inventory_raw,rds_raw,'cluster' if cluster else 'instance',identifier)
    times=[meta['collected_at'],_read(rds_raw)['collected_at']]
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
    out=dict(analysis_type='STATIC_AWS_RDS_INSTANCE_TCP_CONSTRAINTS',input_identity=identity,
             rds_configuration=cfg,source_endpoint=source,destination_endpoint=None,dns_evidence=None,
             scenario=dict(source_kind=source_kind,identifier=identifier,protocol='tcp',source_port=source_port,destination_port=None),
             request=[],response=[],request_status='UNKNOWN',response_status='NOT_EVALUATED',first_request_stop=None,
             conditional_first_response_stop=None,session_status='UNKNOWN',authentication_status='NOT_EVALUATED',
             tls_status='NOT_EVALUATED',live_observation=False,
             limitations=['Offline normalized DNS view and RDS ENI association assertions, not authenticated DNS or service ownership.',
                          'One private IPv4 instance endpoint, one source-specific A answer, same primary VPC, no translation or middlebox; no cluster endpoint or failover selection.',
                          'EKS external non-Pod destination: ordinary VPC CNI, settled standard NetworkPolicy, numeric TCP ports, IPv4 ipBlock/except only under direct untranslated assumption.',
                          'Conditional reply requires delivered request and connection tracking; DNS resolution availability, TLS, DB listeners, credentials and SQL unverified.',
                          'No AWS API, DNS query or packet transmission.'])
    if cluster:
        out.update(analysis_type='STATIC_AWS_RDS_CLUSTER_TCP_CONSTRAINTS',member_selection=None)
        out['scenario']['endpoint_kind']=endpoint_kind
        out['limitations'][1]='One submitted private IPv4 cluster DNS answer and matching member DNS answer, same primary VPC, no translation or middlebox. Not actual target selection or all-reader reachability.'
    def unknown(reason):
        out['request']=[dict(stage='RDS_SCOPE',status='UNKNOWN',reason=reason,evaluation_mode='PREDICTED_PATH')]
        out['first_request_stop']='RDS_SCOPE';return dict(out,status='UNKNOWN',reason=reason)
    if cfg['status']!='RDS_CONFIGURATION_CANDIDATE': return unknown('RDS_CONFIGURATION_UNCONFIRMED')
    if a is None: return unknown('RDS_SOURCE_ENDPOINT_UNCONFIRMED')
    ep=next(e for e in cfg['endpoints'] if not cluster or e['kind']==endpoint_kind); out['scenario']['destination_port']=ep['port']
    if observation_raw is None: return unknown('RDS_DNS_ENI_EVIDENCE_MISSING')
    if not isinstance(observation_raw,bytes) or len(observation_raw)>5*1024*1024: raise ValueError('Invalid RDS path evidence size')
    doc=_read(observation_raw)
    fields={'format','inventory_identity','rds_input_identity','collected_at','complete','identifier','hostname','source_ip','source_eni_id','resolver_scope','resolved_at','ttl_seconds','answers','eni_id','direct_private_ipv4_no_translation'}
    if cluster: fields.update(('member_identifier','member_hostname','member_answers','member_resolved_at','member_ttl_seconds'))
    if set(doc)!=fields or doc['format']!=(CLUSTER_FORMAT if cluster else FORMAT): raise ValueError('Expected normalized RDS path evidence wrapper')
    if not isinstance(doc['answers'],list) or len(doc['answers'])>32 or any(not isinstance(ip,str) for ip in doc['answers']): raise ValueError('Invalid DNS answer list')
    times.extend((doc['collected_at'],doc['resolved_at']))
    if cluster: times.append(doc['member_resolved_at'])
    stamps=[_timestamp(t) for t in times]; gap=(max(stamps)-min(stamps)).total_seconds();out['time_gap_seconds']=gap
    out['dns_evidence']=dict(input_identity=('sha256-rds-cluster-path-v1:' if cluster else 'sha256-rds-instance-path-v1:')+hashlib.sha256(observation_raw).hexdigest(),status='UNKNOWN',hostname=ep['hostname'])
    if doc['inventory_identity']!=identity or doc['rds_input_identity']!=cfg['rds_input_identity'] or doc['identifier']!=identifier or doc['hostname']!=ep['hostname'] or doc['source_ip']!=a['private_ip'] or doc['source_eni_id']!=a['eni_id']:
        return unknown('RDS_PATH_EVIDENCE_IDENTITY_MISMATCH')
    if doc['complete'] is not True or doc['resolver_scope']!='SOURCE_VPC_VIEW' or doc['direct_private_ipv4_no_translation'] is not True: return unknown('RDS_PATH_PROFILE_UNCONFIRMED')
    ttl=doc['ttl_seconds']; resolved=_timestamp(doc['resolved_at']); collected=_timestamp(doc['collected_at'])
    if gap>300: return unknown('SNAPSHOT_TIME_GAP')
    if type(ttl) is not int or not 1<=ttl<=86400 or resolved>collected or (max(stamps)-resolved).total_seconds()>=ttl: return unknown('RDS_DNS_TIME_SCOPE_UNCONFIRMED')
    if len(doc['answers'])!=1: return unknown('RDS_DNS_SINGLE_IPV4_UNCONFIRMED')
    try: ip=str(IPv4Address(doc['answers'][0]))
    except ValueError: return unknown('RDS_DNS_SINGLE_IPV4_UNCONFIRMED')
    db=cfg['configuration']
    if cluster:
        if not db['engine'].startswith('aurora-') and (len(cfg['members'])!=3 or len({m['availability_zone'] for m in cfg['members']})!=3): return unknown('RDS_MULTI_AZ_CLUSTER_SCOPE_UNCONFIRMED')
        member=next((m for m in cfg['members'] if m['identifier']==doc['member_identifier']),None)
        if member is None or member['endpoint']['hostname']!=doc['member_hostname']: return unknown('RDS_CLUSTER_MEMBER_EVIDENCE_MISMATCH')
        fallback=endpoint_kind=='READER' and db['engine'].startswith('aurora-') and not any(m['role']=='READER' for m in cfg['members'])
        if member['role']!=('WRITER' if fallback else endpoint_kind): return unknown('RDS_CLUSTER_ENDPOINT_ROLE_UNCONFIRMED')
        if doc['member_answers']!=[ip]: return unknown('RDS_CLUSTER_MEMBER_DNS_MISMATCH')
        mt=doc['member_ttl_seconds']; mr=_timestamp(doc['member_resolved_at'])
        if type(mt) is not int or not 1<=mt<=86400 or mr>collected or (max(stamps)-mr).total_seconds()>=mt: return unknown('RDS_CLUSTER_MEMBER_DNS_TIME_UNCONFIRMED')
        db=member
    vpc=inv['Vpcs'][0]
    if vpc.get('State')!='available' or not _primary_only(vpc): return unknown('RDS_PRIMARY_VPC_SCOPE_UNCONFIRMED')
    owners=[e for e in inv['NetworkInterfaces'] if e.get('PrivateIpAddress')==ip or any(x.get('PrivateIpAddress')==ip for x in e.get('PrivateIpAddresses',[]))]
    if len(owners)!=1 or owners[0]['NetworkInterfaceId']!=doc['eni_id']: return unknown('RDS_ENI_IP_OWNER_UNCONFIRMED')
    e=owners[0]; addresses=e.get('PrivateIpAddresses',[]); insts=[i for r in inv['Reservations'] for i in r['Instances']]
    if e.get('Status')!='in-use' or e.get('RequesterManaged') is not True or e.get('InterfaceType')!='interface' or e.get('Attachment',{}).get('InstanceId') or e.get('PrivateIpAddress')!=ip or len(addresses)!=1 or addresses[0].get('Primary') is not True or addresses[0].get('PrivateIpAddress')!=ip or e.get('Association') or addresses[0].get('Association') or any(i.get('PrivateIpAddress')==ip or any(x['NetworkInterfaceId']==e['NetworkInterfaceId'] for x in i.get('NetworkInterfaces',[])) for i in insts): return unknown('RDS_ENI_PROFILE_UNCONFIRMED')
    if any(x.get('NetworkInterfaceId')==e['NetworkInterfaceId'] for n in inv['NatGateways'] for x in n.get('NatGatewayAddresses',[])):
        return unknown('RDS_ENI_OWNERSHIP_CONFLICT')
    if source_kind=='ecs' and any(x.get('name')=='networkInterfaceId' and x.get('value')==e['NetworkInterfaceId'] for t in _read(ecs_raw)['tasks'] for att in rows(t.get('attachments',[])) for x in rows(att.get('details',[]))):
        return unknown('RDS_ENI_OWNERSHIP_CONFLICT')
    if source_kind=='eks' and any(obj(p.get('status',{})).get('podIP')==ip or any(x.get('ip')==ip for x in rows(obj(p.get('status',{})).get('podIPs',[]))) for p in eks['pods']):
        return unknown('RDS_ENI_OWNERSHIP_CONFLICT')
    group_ids=[g['GroupId'] for g in e['Groups']]; subs={x['subnet_id']:x['availability_zone'] for x in db['subnets']}
    if sorted(group_ids)!=db['security_group_ids'] or subs.get(e['SubnetId'])!=db['availability_zone'] or e.get('VpcId')!=meta['vpc_id']: return unknown('RDS_ENI_CONFIGURATION_CONFLICT')
    b=dict(kind='RDS_INSTANCE',identifier=identifier,hostname=ep['hostname'],port=ep['port'],private_ip=ip,eni_id=e['NetworkInterfaceId'],subnet_id=e['SubnetId'],security_group_ids=group_ids,availability_zone=db['availability_zone'])
    if a['eni_id']==b['eni_id'] or a['private_ip']==b['private_ip']: return unknown('RDS_SOURCE_DESTINATION_OVERLAP')
    primary=IPv4Network(vpc['CidrBlock'])
    for item in (a,b):
        addr=IPv4Address(item['private_ip']); candidates=[s for s in inv['Subnets'] if addr in IPv4Network(s['CidrBlock'])]
        if len(candidates)!=1 or candidates[0]['SubnetId']!=item['subnet_id'] or candidates[0].get('State')!='available': return unknown('SUBNET_MISSING_OR_AMBIGUOUS')
        net=IPv4Network(candidates[0]['CidrBlock'])
        if not net.subnet_of(primary) or int(addr)-int(net.network_address)<4 or addr==net.broadcast_address: return unknown('RDS_SUBNET_ADDRESS_OUT_OF_SCOPE')
    out['destination_endpoint']=b;out['dns_evidence'].update(status='RDS_DNS_ENI_CORRELATION_CANDIDATE',ip=ip,eni_id=b['eni_id'],resolved_at=doc['resolved_at'],ttl_seconds=ttl)
    if cluster:
        b.update(identifier=member['identifier'],cluster_identifier=identifier,cluster_endpoint_kind=endpoint_kind,member_hostname=member['endpoint']['hostname'])
        out['member_selection']=dict(status='DNS_MEMBER_CORRELATION_CANDIDATE',identifier=member['identifier'],role=member['role'],reader_primary_fallback=fallback,eligible_member_ids=[m['identifier'] for m in cfg['members'] if m['role']==('WRITER' if fallback else endpoint_kind)],actual_selection='NOT_EVALUATED')
        out['dns_evidence'].update(member_hostname=doc['member_hostname'],member_resolved_at=doc['member_resolved_at'],member_ttl_seconds=mt)
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
            try: np=policy_check(policies,selected,None,namespaces,'Egress',None,ep['port'],external_ip=ip)
            except ValueError: np=_result('UNKNOWN','POLICY_SYNTAX_UNSUPPORTED')
        out['policy_input_identity']='sha256-eks-network-policy-v1:'+hashlib.sha256(policy_raw).hexdigest()
    evaluate_direct_service_tcp(out, inventory_raw, inv, a, b, ep['port'], source_port, prefix, np)
    return dict(out,status='RDS_CLUSTER_PATH_CONSTRAINTS_CANDIDATE' if cluster else 'RDS_INSTANCE_PATH_CONSTRAINTS_CANDIDATE',reason='STATIC_RDS_ENI_ROUTE_AND_POLICY_CHECKS')
