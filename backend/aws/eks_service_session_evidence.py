"""Offline ClusterIP translation scenarios; never attest kube-proxy or CNI runtime state."""
import hashlib
from backend.aws.eks_pod_evidence import inspect_eks_pod, obj
from backend.aws.eks_service_evidence import inspect_eks_service
from backend.aws.eks_session_evidence import analyze_eks_pod_session, FORMAT as POLICY_FORMAT
from backend.aws.peering_evidence import _load, _timestamp
from backend.aws.policy_evidence import _port
from backend.iac.plan_adapter import _read

FORMAT = 'cloudpath-eks-service-translation-v1'
PROFILE = {'proxy_mode':'iptables', 'cluster_internal_ipv4':True,
           'proxy_rules_assumed_current':True, 'no_alternate_proxy_or_mesh':True,
           'cross_node_source_ip_and_port_preserved':True,
           'policy_backend_tuple_assumed':True, 'reverse_conntrack_assumed':True}
MAX_BACKENDS = 32


def fingerprint(prefix, raw):
    return prefix + ':' + hashlib.sha256(raw).hexdigest()


def analyze_eks_service_session(inventory_raw, eks_raw, service_raw, policy_raw, translation_raw,
                                source_namespace, source_pod, service_namespace, service_name,
                                source_port, service_port):
    if not _port(source_port) or not _port(service_port):
        raise ValueError('Explicit TCP ports required')
    identity, meta, _ = _load(inventory_raw)
    eks, svc_doc, policy, doc = map(_read, (eks_raw, service_raw, policy_raw, translation_raw))
    if set(doc) != {'format','collected_at','eks_input_identity','service_input_identity','policy_input_identity','source_pod_uid','complete','profile'} or doc['format'] != FORMAT:
        raise ValueError('Expected normalized Service translation assumptions wrapper')
    if set(policy) != {'format','collected_at','eks_input_identity','complete','profile','networkPolicies'} or policy['format'] != POLICY_FORMAT:
        raise ValueError('Expected normalized NetworkPolicy evidence wrapper')
    service = inspect_eks_service(inventory_raw, eks_raw, service_raw, service_namespace, service_name, service_port)
    source = inspect_eks_pod(inventory_raw, eks_raw, source_namespace, source_pod)
    times = [_timestamp(x['collected_at']) for x in (meta, eks, svc_doc, policy, doc)]
    policy_id = fingerprint('sha256-eks-network-policy-v1', policy_raw)
    out = dict(analysis_type='STATIC_AWS_EKS_SERVICE_TRANSLATION_SCENARIOS', input_identity=identity,
               eks_input_identity=source['eks_input_identity'], service_input_identity=service['service_input_identity'],
               policy_input_identity=policy_id, translation_input_identity=fingerprint('sha256-eks-service-translation-v1',translation_raw),
               time_gap_seconds=(max(times)-min(times)).total_seconds(),
               source_endpoint=source, service_correlation=service,
               scenario=dict(source_namespace=source_namespace,source_pod=source_pod,service_namespace=service_namespace,
                             service_name=service_name,protocol='TCP',source_port=source_port,service_port=service_port),
               branches=[], backend_summary='NOT_EVALUATED', target_selection='NOT_EVALUATED',
               translation_status='NOT_EVALUATED', session_status='UNKNOWN', live_observation=False,
               limitations=['Offline assertions only; no observed kube-proxy rules, conntrack, CNI enforcement or actual target selection.',
                            'Single-stack ClusterIP TCP, iptables model; conditional backend tuple assumes no SNAT or source port change and reverse conntrack.',
                            'Cross-node only; same-subnet direct candidate supported; same-node, hairpin, unequal Service/container port with VPC CNI policy, and alternate proxy unresolved.',
                            'Backend direct-Pod constraints are counterfactual checks, not proof of a delivered Service packet. No AWS/Kubernetes calls or packets.'])
    def unknown(reason): return dict(out,status='UNKNOWN',reason=reason)
    if doc['complete'] is not True or policy['complete'] is not True: return unknown('EVIDENCE_INCOMPLETE')
    if (doc['eks_input_identity']!=out['eks_input_identity'] or policy['eks_input_identity']!=out['eks_input_identity'] or
        doc['service_input_identity']!=out['service_input_identity'] or doc['policy_input_identity']!=policy_id):
        return unknown('EVIDENCE_IDENTITY_MISMATCH')
    if out['time_gap_seconds']>300: return unknown('SNAPSHOT_TIME_GAP')
    if source['status']!='POD_ENDPOINT_CANDIDATE': return unknown('SOURCE_POD_UNCONFIRMED')
    if doc['source_pod_uid']!=source['pod']['uid']: return unknown('SOURCE_POD_UID_MISMATCH')
    if service['status']!='SERVICE_ENDPOINT_CORRELATION_CANDIDATE': return unknown('SERVICE_CORRELATION_UNCONFIRMED')
    ready=[x for x in service['registrations'] if x['status']=='READY_ENDPOINT_CANDIDATE']
    if not ready or len(ready)>MAX_BACKENDS: return unknown('BACKEND_COUNT_OUT_OF_SCOPE')
    profile=obj(doc['profile'])
    supported=set(profile)==set(PROFILE) and all(type(profile[k]) is type(v) and profile[k]==v for k,v in PROFILE.items())
    a=source['endpoint']; vip=service['service']['cluster_ip']
    for reg in ready:
        b=reg['endpoint']; port=reg['registered_port']
        row=dict(pod_name=reg['pod_name'],pod_uid=reg['pod_uid'],endpoint=b,
                 original_destination=dict(ip=vip,port=service_port),
                 candidate_destination=dict(ip=b['private_ip'],port=port),
                 translation_status='CONFIGURED_MAPPING_ONLY', request_tuple=None, conditional_reply_tuple=None,
                 backend_check=None, status='UNKNOWN',reason='TRANSLATION_PROFILE_UNCONFIRMED')
        if not supported: pass
        elif a['node_instance_id']==b['node_instance_id'] or a['private_ip']==b['private_ip']:
            row['reason']='CROSS_NODE_SUBNET_REQUIRED'
        else:
            row.update(translation_status='CONDITIONAL_DNAT_CANDIDATE',
                       request_tuple=dict(source_ip=a['private_ip'],source_port=source_port,destination_ip=b['private_ip'],destination_port=port),
                       conditional_reply_tuple=dict(backend_source_ip=b['private_ip'],backend_source_port=port,
                         client_visible_source_ip=vip,client_visible_source_port=service_port,destination_ip=a['private_ip'],destination_port=source_port))
            if port!=service_port:
                row['reason']='VPC_CNI_SERVICE_CONTAINER_PORT_MISMATCH'
            elif isinstance(service['service']['target_port'],str) and service['service']['target_port']!=service['service']['port_name']:
                row['reason']='VPC_CNI_NAMED_PORT_MISMATCH'
            else:
                leg=analyze_eks_pod_session(inventory_raw,eks_raw,policy_raw,source_namespace,source_pod,service_namespace,reg['pod_name'],source_port,port)
                row['backend_check']=dict(leg,scope='COUNTERFACTUAL_DIRECT_BACKEND_LEG')
                if leg['request_status']=='BLOCKED' or leg['response_status']=='BLOCKED':
                    row.update(status='BACKEND_CONSTRAINT_BLOCK_CANDIDATE',reason='STATIC_BACKEND_LEG_BLOCKED')
                elif leg['request_status']==leg['response_status']=='CONDITIONAL_CANDIDATE':
                    row.update(status='BACKEND_PATH_CANDIDATE',reason='STATIC_BACKEND_LEG_CONDITIONAL')
                else: row['reason']='BACKEND_LEG_UNRESOLVED'
        out['branches'].append(row)
    statuses={x['status'] for x in out['branches']}
    out['translation_status']='CONDITIONAL_DNAT_CANDIDATE' if all(x['translation_status']=='CONDITIONAL_DNAT_CANDIDATE' for x in out['branches']) else 'PARTIAL_OR_UNCONFIRMED'
    if 'UNKNOWN' in statuses: out['backend_summary']='UNRESOLVED_BACKEND_PRESENT'
    elif statuses=={'BACKEND_PATH_CANDIDATE'}: out['backend_summary']='ALL_BACKEND_CHECKS_CONDITIONAL'
    elif statuses=={'BACKEND_CONSTRAINT_BLOCK_CANDIDATE'}: out['backend_summary']='ALL_BACKEND_CHECKS_BLOCKED'
    else: out['backend_summary']='MIXED_BACKEND_CHECKS'
    if 'UNKNOWN' in statuses: return unknown('ONE_OR_MORE_BACKENDS_UNRESOLVED')
    return dict(out,status='SERVICE_PATH_CONSTRAINTS_CANDIDATE',reason='CONDITIONAL_DNAT_AND_BACKEND_CHECKS')
