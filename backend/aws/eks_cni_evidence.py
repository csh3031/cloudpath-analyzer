"""Compare declared policy with uploaded, historical node-local CNI evidence.
No live access, no proof of enforcement or end-to-end reachability.
"""
import hashlib
from backend.aws.eks_session_evidence import analyze_eks_pod_session
from backend.aws.eks_pod_evidence import obj, rows, index
from backend.aws.peering_evidence import _load, _timestamp
from backend.iac.plan_adapter import _read

FORMAT = 'cloudpath-eks-cni-observation-v1'
STAGES = ('SOURCE_NETWORK_POLICY_EGRESS', 'DESTINATION_NETWORK_POLICY_INGRESS')


def inspect_eks_cni(inventory_raw, eks_raw, policy_raw, observation_raw, source_namespace,
                    source_pod, destination_namespace, destination_pod, source_port, destination_port):
    static = analyze_eks_pod_session(inventory_raw, eks_raw, policy_raw, source_namespace,
                                     source_pod, destination_namespace, destination_pod, source_port, destination_port)
    _, meta, _ = _load(inventory_raw)
    eks, policy, doc = map(_read, (eks_raw, policy_raw, observation_raw))
    keys = {'format','collected_at','eks_input_identity','policy_input_identity','cluster_arn',
            'complete','nodes','policyEndpoints','events'}
    if set(doc) != keys or doc['format'] != FORMAT:
        raise ValueError('Expected normalized CNI observation wrapper')
    now = _timestamp(doc['collected_at'])
    times = [now] + [_timestamp(x['collected_at']) for x in (meta, eks, policy)]
    out = dict(analysis_type='STATIC_EKS_CNI_EVIDENCE_COMPARISON',
               observation_input_identity='sha256-eks-cni-observation-v1:'+hashlib.sha256(observation_raw).hexdigest(),
               static_analysis=static, time_gap_seconds=(max(times)-min(times)).total_seconds(),
               comparisons=[], enforcement_status='UNKNOWN', session_status='UNKNOWN', live_observation=False,
               limitations=['Uploaded normalized assertions, not authenticated live CNI state or a raw PolicyEndpoint export.',
                            'Node-local historical decision log only; node attribution does not establish an eBPF hook or end-to-end delivery.',
                            'Exact direct IPv4 TCP tuple, source/destination node and Pod UID; no Service DNAT, reply or connection identity proof.',
                            'Controller correlation, agent readiness and eBPF attachment assertions are independent; no evidence means UNKNOWN.',
                            '300-second total time window is heuristic; no proof of current policy, completeness or future enforcement.'])
    def unknown(reason): return dict(out,status='UNKNOWN',reason=reason)
    if doc['eks_input_identity']!=static['eks_input_identity'] or doc['policy_input_identity']!=static['policy_input_identity'] or doc['cluster_arn']!=eks['cluster']['arn']:
        return unknown('OBSERVATION_IDENTITY_MISMATCH')
    if doc['complete'] is not True: return unknown('OBSERVATION_INCOMPLETE')
    if out['time_gap_seconds']>300: return unknown('SNAPSHOT_TIME_GAP')
    if static['status']!='EKS_POD_PATH_CONSTRAINTS_CANDIDATE': return unknown('STATIC_SCOPE_UNCONFIRMED')
    if static.get('path_kind')=='SAME_NODE_POD_DIRECT': return unknown('SAME_NODE_EVENT_DIRECTION_UNCONFIRMED')
    nodes={}; endpoints={}; events=rows(doc['events'])
    for n in rows(doc['nodes']):
        if set(n)!={'node_uid','agent_ready','policy_enabled','event_logging_enabled','attached_pod_uids'} or not isinstance(n['node_uid'],str) or n['node_uid'] in nodes:
            raise ValueError('Invalid or duplicate node evidence')
        ids=n['attached_pod_uids']
        if not isinstance(ids,list) or len(ids)>300 or any(not isinstance(x,str) for x in ids) or len(set(ids))!=len(ids): raise ValueError('Invalid attachment evidence')
        nodes[n['node_uid']]=n
    for e in rows(doc['policyEndpoints']):
        if set(e)!={'namespace','policy_uid','pod_uid','endpoint_uid'} or any(not isinstance(v,str) or not v for v in e.values()): raise ValueError('Invalid normalized PolicyEndpoint association')
        key=(e['namespace'],e['policy_uid'],e['pod_uid'])
        if key in endpoints: raise ValueError('Duplicate normalized PolicyEndpoint association')
        endpoints[key]=e['endpoint_uid']
    src,dst=static['source_endpoint'],static['destination_endpoint']
    policies=index(policy['networkPolicies'],True)
    tuple_fields={'Src IP':src['endpoint']['private_ip'],'Src Port':source_port,'Dest IP':dst['endpoint']['private_ip'],'Dest Port':destination_port,'Proto':'TCP'}
    for stage,ep in zip(STAGES,(src,dst)):
        step=next(x for x in static['request'] if x['stage']==stage)
        node_uid,pod_uid,ns=ep['node']['uid'],ep['pod']['uid'],ep['pod']['namespace']
        expected={'ALLOW_CANDIDATE':'ACCEPT','BLOCKED':'DENY'}.get(step['status'])
        n=nodes.get(node_uid)
        selected=step.get('selected_policies',[])
        controller=[p for p in selected if (ns,policies[(ns,p)]['metadata']['uid'],pod_uid) in endpoints]
        record=dict(stage=stage,node_uid=node_uid,pod_uid=pod_uid,declared_status=step['status'],expected_verdict=expected,
                    static_evaluation_mode=step['evaluation_mode'],selected_policies=selected,correlated_policies=controller,
                    matched_events=[],status='UNKNOWN',reason='')
        out['comparisons'].append(record)
        if expected is None: record['reason']='DECLARATION_UNRESOLVED'; continue
        if n is None: record['reason']='NODE_AGENT_EVIDENCE_MISSING'; continue
        if n['policy_enabled'] is False: record['reason']='CNI_POLICY_REPORTED_DISABLED'; continue
        if n['policy_enabled'] is not True or n['agent_ready'] is not True: record['reason']='NODE_AGENT_STATE_UNCONFIRMED'; continue
        if len(controller)!=len(selected): record['reason']='POLICY_ENDPOINT_ASSOCIATION_MISSING'; continue
        if pod_uid not in n['attached_pod_uids']: record['reason']='POD_ATTACHMENT_EVIDENCE_MISSING'; continue
        if n['event_logging_enabled'] is not True: record['reason']='EVENT_LOGGING_UNCONFIRMED'; continue
        for event in events:
            if set(event)!={'node_uid','pod_uid','log'}: raise ValueError('Invalid event envelope')
            if event['node_uid']!=node_uid or event['pod_uid']!=pod_uid: continue
            log=obj(event['log'])
            if log.get('msg')!='Flow Info: ' or not all(type(log.get(k)) is type(v) and log[k]==v for k,v in tuple_fields.items()): continue
            verdict=log.get('Verdict')
            if verdict not in ('ACCEPT','DENY'): continue
            t=_timestamp(log.get('timestamp',log.get('ts')))
            if t>now or (max(times+[t])-min(times+[t])).total_seconds()>300: continue
            record['matched_events'].append(dict(timestamp=t.isoformat(),verdict=verdict))
        verdicts={e['verdict'] for e in record['matched_events']}
        if not verdicts: record['reason']='NO_MATCHING_HISTORICAL_EVENT'
        elif len(verdicts)>1: record['reason']='CONFLICTING_HISTORICAL_EVENTS'
        elif expected not in verdicts: record.update(status='DISCREPANCY_CANDIDATE',reason='DECLARATION_EVENT_MISMATCH')
        else: record.update(status='CONSISTENT_EVENT_CANDIDATE',reason='DECLARATION_EVENT_MATCH')
    states={r['status'] for r in out['comparisons']}
    status='CNI_EVIDENCE_DISCREPANCY_CANDIDATE' if 'DISCREPANCY_CANDIDATE' in states else 'CNI_EVIDENCE_CONSISTENT_CANDIDATE' if states=={'CONSISTENT_EVENT_CANDIDATE'} else 'UNKNOWN'
    return dict(out,status=status,reason='NODE_LOCAL_HISTORICAL_COMPARISON')
