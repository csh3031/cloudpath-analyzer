"""Bounded direct Pod IPv4 TCP configuration checks, not CNI runtime evidence."""
import hashlib
from ipaddress import IPv4Address, IPv4Network
from backend.aws.eks_pod_evidence import inspect_eks_pod, index, obj, rows, name
from backend.aws.eks_service_evidence import labels
from backend.aws.peering_evidence import _load, _timestamp
from backend.aws.prefix_list_evidence import load_prefix_lists
from backend.aws.policy_evidence import _port, _sg, _acl, _result
from backend.aws.local_delivery_evidence import same_subnet_delivery, subnet_policy
from backend.aws.route_evidence import lookup_observed_route
from backend.iac.plan_adapter import _read

FORMAT = 'cloudpath-eks-network-policy-v1'
PROFILE = {'plugin':'aws-vpc-cni', 'network_policy_enabled':True,
           'enforcing_mode':'standard', 'settled':True, 'standard_policies_only':True,
           'primary_interface_only':True, 'no_other_policy_engine':True,
           'controller_limits_verified':True, 'direct_pod_ip_no_translation':True}


def selector(spec, labs):
    spec = obj(spec)
    if set(spec)-{'matchLabels','matchExpressions'}: raise ValueError('Unsupported label selector')
    tests = [labs.get(k)==v for k,v in labels(spec.get('matchLabels',{})).items()]
    for exp in rows(spec.get('matchExpressions',[])):
        k,op,values=exp.get('key'),exp.get('operator'),exp.get('values',[])
        if set(exp)-{'key','operator','values'} or not isinstance(k,str) or not k or not isinstance(values,list) or any(not isinstance(v,str) for v in values):
            raise ValueError('Invalid label expression')
        if op in ('In','NotIn') and values:
            tests.append(labs.get(k) in values if op=='In' else labs.get(k) not in values)
        elif op in ('Exists','DoesNotExist') and not values:
            tests.append((k in labs)==(op=='Exists'))
        else: raise ValueError('Unsupported label expression')
    return all(tests)


def peer_match(peer, other, namespaces, policy_ns, *, external_ip=None):
    if not peer: return True
    if external_ip is not None:
        # Only callers with a correlated, non-Pod, untranslated IPv4 destination
        # may opt in. Existing Pod-to-Pod CIDR semantics remain unresolved.
        if 'ipBlock' in peer:
            if set(peer)!={'ipBlock'}: return None
            block=peer['ipBlock']
            if not isinstance(block,dict) or set(block)-{'cidr','except'} or not isinstance(block.get('cidr'),str): return None
            try:
                net=IPv4Network(block['cidr']); exceptions=block.get('except',[])
                if not isinstance(exceptions,list) or any(not isinstance(x,str) for x in exceptions): return None
                exclusions=[IPv4Network(x) for x in exceptions]
                if any(not x.subnet_of(net) or x==net for x in exclusions): return None
                ip=IPv4Address(external_ip)
                return ip in net and not any(ip in x for x in exclusions)
            except ValueError: return None
        if set(peer)-{'podSelector','namespaceSelector'}: return None
        for key in peer: selector(peer[key],{})
        return False # RDS is not a Kubernetes Pod or namespace member.
    if 'ipBlock' in peer: return None # Pod IP CIDR semantics not portable; no inference.
    if set(peer)-{'podSelector','namespaceSelector'}: return None
    ns=other['metadata']['namespace']
    ns_match=selector(peer['namespaceSelector'],labels(namespaces[ns]['metadata'].get('labels',{}))) if 'namespaceSelector' in peer else ns==policy_ns
    pod_match=selector(peer['podSelector'],labels(other['metadata'].get('labels',{}))) if 'podSelector' in peer else True
    return ns_match and pod_match


def port_match(rule, destination, port):
    if set(rule)-{'protocol','port','endPort'}: return None
    proto=rule.get('protocol','TCP')
    if proto in ('UDP','SCTP'): return False
    if proto!='TCP': return None
    if 'port' not in rule: return True if 'endPort' not in rule else None
    p=rule['port']; end=rule.get('endPort',p)
    if _port(p) and _port(end) and end>=p: return p<=port<=end
    # Named policy ports and malformed/unsupported ranges are not inferred.
    return None


def any3(values):
    return True if True in values else None if None in values else False


def rule_match(rule, other, namespaces, ns, direction, destination, port, *, external_ip=None):
    key='from' if direction=='Ingress' else 'to'
    if set(rule)-{key,'ports'}: return None
    peers=rows(rule.get(key,[])); ports=rows(rule.get('ports',[]))
    a=any3([peer_match(p,other,namespaces,ns,external_ip=external_ip) for p in peers]) if peers else True
    b=any3([port_match(p,destination,port) for p in ports]) if ports else True
    return False if False in (a,b) else None if None in (a,b) else True


def policy_check(policies, selected, other, namespaces, direction, destination, port, *, external_ip=None):
    ns=selected['metadata']['namespace']; lab=labels(selected['metadata'].get('labels',{}))
    applicable=[]; matches=[]; unresolved=[]
    for (pns,pname),p in policies.items():
        if pns!=ns: continue
        spec=obj(p.get('spec'))
        if p.get('kind')!='NetworkPolicy' or p.get('apiVersion')!='networking.k8s.io/v1' or p['metadata'].get('deletionTimestamp') is not None or set(spec)-{'podSelector','policyTypes','ingress','egress'} or 'podSelector' not in spec:
            return _result('UNKNOWN','POLICY_OBJECT_UNCONFIRMED')
        if not selector(spec['podSelector'],lab): continue
        types=spec.get('policyTypes',['Ingress']+(['Egress'] if spec.get('egress') else []))
        if not isinstance(types,list) or not types or any(t not in ('Ingress','Egress') for t in types) or len(set(types))!=len(types):
            return _result('UNKNOWN','POLICY_TYPES_UNCONFIRMED')
        if direction not in types:
            if spec.get(direction.lower()): return _result('UNKNOWN','POLICY_TYPES_RULE_MISMATCH')
            continue
        applicable.append(pname)
        for i,r in enumerate(rows(spec.get(direction.lower(),[]))):
            matched=rule_match(r,other,namespaces,ns,direction,destination,port,external_ip=external_ip)
            if matched is True: matches.append({'policy':pname,'rule_index':i})
            elif matched is None: unresolved.append({'policy':pname,'rule_index':i})
    detail=dict(namespace=ns,selected_policies=applicable,matching_rules=matches,unresolved_rules=unresolved)
    if matches: return _result('ALLOW_CANDIDATE','ADDITIVE_POLICY_ALLOW_MATCH',**detail)
    if not applicable: return _result('ALLOW_CANDIDATE','NO_POLICY_ISOLATION',**detail)
    if unresolved: return _result('UNKNOWN','POLICY_RULE_UNRESOLVED',**detail)
    return _result('BLOCKED','ISOLATED_NO_MATCHING_ALLOW',**detail)


def analyze_eks_pod_session(inventory_raw, eks_raw, policy_raw, source_namespace, source_pod,
                            destination_namespace, destination_pod, source_port, destination_port, *, prefix_list_raw=None):
    if not _port(source_port) or not _port(destination_port): raise ValueError('Explicit TCP ports required')
    identity,meta,inv=_load(inventory_raw); eks=_read(eks_raw); doc=_read(policy_raw)
    if set(doc)!={'format','collected_at','eks_input_identity','complete','profile','networkPolicies'} or doc['format']!=FORMAT:
        raise ValueError('Expected normalized NetworkPolicy evidence wrapper')
    src=inspect_eks_pod(inventory_raw,eks_raw,source_namespace,source_pod)
    dst=inspect_eks_pod(inventory_raw,eks_raw,destination_namespace,destination_pod)
    times=[_timestamp(x) for x in (meta['collected_at'],eks['collected_at'],doc['collected_at'])]
    out=dict(analysis_type='STATIC_AWS_EKS_DIRECT_POD_TCP_CONSTRAINTS',input_identity=identity,
             eks_input_identity=src['eks_input_identity'],policy_input_identity='sha256-eks-network-policy-v1:'+hashlib.sha256(policy_raw).hexdigest(),
             time_gap_seconds=(max(times)-min(times)).total_seconds(),source_endpoint=src,destination_endpoint=dst,
             scenario=dict(source_namespace=source_namespace,source_pod=source_pod,destination_namespace=destination_namespace,destination_pod=destination_pod,protocol='TCP',source_port=source_port,destination_port=destination_port),
             request=[],response=[],request_status='UNKNOWN',response_status='NOT_EVALUATED',first_request_stop=None,conditional_first_response_stop=None,
             session_status='UNKNOWN',service_translation_status='NOT_EVALUATED',live_observation=False,
             limitations=['Offline asserted snapshots; CNI enforcement and completeness not authenticated.',
                          'Direct same-VPC IPv4 TCP; same-node delivery conditional on ordinary CNI profile and local host routing; no Service VIP/DNAT, mesh, host firewall or runtime listener.',
                          'Standard NetworkPolicy only; numeric TCP ports and label selectors; ipBlock and named policy ports unresolved.',
                          'CNI profile, controller-managed Pods and policy limits are asserted, not runtime proof; no admin policies or alternate enforcement.',
                          'AWS IPv4 CIDR SG/NACL and direct private ENI SG references; other references and missing/unsupported prefix list evidence unresolved; reply assumes delivered request and tracked connection. No AWS/Kubernetes calls or packets.'])
    prefix_lists,prefix_summary=load_prefix_lists(prefix_list_raw,identity,meta['region'],meta['collected_at'],additional_times=(eks['collected_at'],doc['collected_at']))
    if prefix_summary is not None: out['prefix_list_evidence']=prefix_summary
    def unknown(reason):
        out['request']=[dict(stage='EKS_SCOPE',status='UNKNOWN',reason=reason,evaluation_mode='PREDICTED_PATH')];out['first_request_stop']='EKS_SCOPE'
        return dict(out,status='UNKNOWN',reason=reason)
    if doc['eks_input_identity']!=src['eks_input_identity']: return unknown('EKS_IDENTITY_MISMATCH')
    if doc['complete'] is not True: return unknown('POLICY_EVIDENCE_INCOMPLETE')
    if out['time_gap_seconds']>300: return unknown('SNAPSHOT_TIME_GAP')
    if src['status']!='POD_ENDPOINT_CANDIDATE' or dst['status']!='POD_ENDPOINT_CANDIDATE': return unknown('POD_ENDPOINT_NOT_CONFIRMED')
    a,b=(dict(x['endpoint'],security_group_ids=x['endpoint']['eni_security_group_ids']) for x in (src,dst))
    if a['private_ip']==b['private_ip']: return unknown('SAME_POD_CONTAINER_LISTENER_NOT_MODELED')
    same_node=a['node_instance_id']==b['node_instance_id']
    if same_node and a['subnet_id']!=b['subnet_id']: return unknown('NODE_SUBNET_INCONSISTENT')
    out['path_kind']='SAME_NODE_POD_DIRECT' if same_node else 'SAME_SUBNET_DIRECT' if a['subnet_id']==b['subnet_id'] else 'CROSS_SUBNET_DIRECT'
    vpc=inv['Vpcs'][0]
    if vpc.get('State')!='available': return unknown('VPC_STATE_NOT_AVAILABLE')
    primary=IPv4Network(vpc['CidrBlock'])
    for e in (a,b):
        ip=IPv4Address(e['private_ip']); matches=[s for s in inv['Subnets'] if ip in IPv4Network(s['CidrBlock'])]
        if len(matches)!=1 or matches[0]['SubnetId']!=e['subnet_id']: return unknown('SUBNET_MISSING_OR_AMBIGUOUS')
        net=IPv4Network(matches[0]['CidrBlock'])
        if not net.subnet_of(primary) or int(ip)-int(net.network_address)<4 or ip==net.broadcast_address: return unknown('POD_SUBNET_ADDRESS_OUT_OF_SCOPE')
    if not same_node and a['subnet_id']==b['subnet_id'] and any(same_subnet_delivery(inv,x,y)['status']!='ALLOW_CANDIDATE' for x,y in ((a,b),(b,a))): return unknown('SAME_SUBNET_NORMAL_LOCAL_CONFIGURATION_UNCONFIRMED')
    namespaces=index(eks['namespaces']); pods=index(eks['pods'],True); policies=index(doc['networkPolicies'],True)
    sp=pods[(source_namespace,source_pod)]; dp=pods[(destination_namespace,destination_pod)]
    if any(ns not in namespaces for ns,_ in policies): return unknown('POLICY_NAMESPACE_UNCONFIRMED')
    profile=obj(doc['profile']); profile_ok=set(profile)==set(PROFILE) and all(type(profile[k]) is type(v) and profile[k]==v for k,v in PROFILE.items())
    managed=all(any(o.get('controller') is True and o.get('kind') in ('ReplicaSet','StatefulSet','DaemonSet','Job') and isinstance(o.get('uid'),str) and o['uid'] for o in rows(p['metadata'].get('ownerReferences',[]))) for p in (sp,dp))
    def np(selected,other,direction):
        if not profile_ok or not managed: return _result('UNKNOWN','CNI_POLICY_APPLICABILITY_UNCONFIRMED')
        try: return policy_check(policies,selected,other,namespaces,direction,dp,destination_port)
        except ValueError: return _result('UNKNOWN','POLICY_SYNTAX_UNSUPPORTED')
    groups={g['GroupId']:g for g in inv['SecurityGroups']}; acls=inv['NetworkAcls']
    def direction(start,end,port,reply,enabled):
        conditional=_result('CONDITIONAL','REQUIRES_ESTABLISHED_TRACKED_REQUEST')
        np_reply=_result('CONDITIONAL','REPLY_TO_ALLOWED_CONNECTION_ASSUMED')
        if same_node:
            skip=_result('NOT_APPLICABLE','CONDITIONAL_NODE_LOCAL_NO_VPC_BOUNDARY') if profile_ok and managed else _result('UNKNOWN','NODE_LOCAL_PROFILE_UNCONFIRMED')
            node_route=_result('ALLOW_CANDIDATE','CONDITIONAL_NODE_LOCAL_DELIVERY',assumptions=['NODE_LOCAL_DIRECT_VETH_ROUTING_ASSUMED','HOST_NETWORK_CONFIGURATION_UNVERIFIED']) if profile_ok and managed else _result('UNKNOWN','NODE_LOCAL_PROFILE_UNCONFIRMED')
            checks=[('SOURCE_NETWORK_POLICY_EGRESS',np_reply if reply else np(sp,dp,'Egress'),start),('SOURCE_SG_EGRESS',skip,start),('SOURCE_NACL_EGRESS',skip,start),('LOCAL_ROUTE',node_route,start),('DESTINATION_NACL_INGRESS',skip,end),('DESTINATION_SG_INGRESS',skip,end),('DESTINATION_NETWORK_POLICY_INGRESS',np_reply if reply else np(dp,sp,'Ingress'),end)]
        else:
            same=start['subnet_id']==end['subnet_id']
            local=same_subnet_delivery(inv,start,end) if same else {}
            route=lookup_observed_route(inventory_raw,start['subnet_id'],end['private_ip']) if not same else local
            direct = route['status'] in ('LOCAL_CANDIDATE','ALLOW_CANDIDATE') and not any(t.get('PropagatingVgws') for t in inv['RouteTables'] if t['RouteTableId']==route.get('route_table_id'))
            route_status={'LOCAL_CANDIDATE':'ALLOW_CANDIDATE','ALLOW_CANDIDATE':'ALLOW_CANDIDATE','BLOCKED':'BLOCKED'}.get(route['status'],'UNKNOWN')
            checks=[('SOURCE_NETWORK_POLICY_EGRESS',np_reply if reply else np(sp,dp,'Egress'),start),
                ('SOURCE_SG_EGRESS',conditional if reply else _sg(groups,start,end,True,port,direct_same_vpc=direct,prefix_lists=prefix_lists),start),
                ('SOURCE_NACL_EGRESS',subnet_policy(_acl,inv,start,end,True,port,local),start),
                ('LOCAL_ROUTE',_result(route_status,route['reason'],route_evidence=route),start),
                ('DESTINATION_NACL_INGRESS',subnet_policy(_acl,inv,end,start,False,port,local),end),
                ('DESTINATION_SG_INGRESS',conditional if reply else _sg(groups,end,start,False,port,direct_same_vpc=direct,prefix_lists=prefix_lists),end),
                ('DESTINATION_NETWORK_POLICY_INGRESS',np_reply if reply else np(dp,sp,'Ingress'),end)]
        active=enabled;stop=None;status='CONDITIONAL_CANDIDATE' if enabled else 'NOT_EVALUATED'; result=[]
        for stage,detail,ep in checks:
            result.append(dict(detail,stage=stage,eni_id=ep['eni_id'],subnet_id=ep['subnet_id'],evaluation_mode=('CONDITIONAL_CHECK' if reply else 'PREDICTED_PATH') if active else 'INDEPENDENT_CHECK'))
            if active and not (detail['status'] in ('ALLOW_CANDIDATE','NOT_APPLICABLE') or (reply and detail['status']=='CONDITIONAL')):
                stop=stage;status='BLOCKED' if detail['status']=='BLOCKED' else 'UNKNOWN';active=False
        return result,status,stop
    out['request'],out['request_status'],out['first_request_stop']=direction(a,b,destination_port,False,True)
    out['response'],out['response_status'],out['conditional_first_response_stop']=direction(b,a,source_port,True,out['request_status']=='CONDITIONAL_CANDIDATE')
    if out['request_status']=='BLOCKED': out['session_status']='BLOCKED'
    return dict(out,status='EKS_POD_PATH_CONSTRAINTS_CANDIDATE',reason='STATIC_DIRECT_POD_ROUTE_AND_POLICY_CHECKS')
