"""Offline selector-backed ClusterIP / EndpointSlice / EKS Pod correlation."""
import hashlib
from ipaddress import IPv4Address, IPv4Network
from backend.aws.eks_pod_evidence import inspect_eks_pod, index, name, obj, rows, FORMAT as POD_FORMAT
from backend.aws.peering_evidence import _load, _timestamp
from backend.iac.plan_adapter import _read
from backend.aws.policy_evidence import _port

FORMAT = 'cloudpath-eks-service-evidence-v1'


def labels(value):
    value = obj(value)
    if any(not isinstance(k, str) or not k or not isinstance(v, str) for k, v in value.items()):
        raise ValueError('Invalid Kubernetes labels')
    return value


def target_port(spec, pod):
    target = spec.get('targetPort', spec['port'])
    if _port(target):
        return target
    if not name(target):
        return None
    matches = [p.get('containerPort') for c in rows(obj(pod.get('spec')).get('containers', []))
               for p in rows(c.get('ports', [])) if p.get('name') == target and p.get('protocol', 'TCP') == 'TCP']
    return matches[0] if len(matches) == 1 and _port(matches[0]) else None


def inspect_eks_service(inventory_raw, eks_raw, service_raw, namespace, service_name, service_port):
    if not name(namespace) or not name(service_name) or not _port(service_port):
        raise ValueError('Expected namespace, Service name and numeric TCP port')
    identity, meta, inv = _load(inventory_raw)
    eks = _read(eks_raw)
    doc = _read(service_raw)
    if set(eks) != {'format','collected_at','inventory_identity','complete','cluster','cni','namespaces','nodes','pods'} or eks['format'] != POD_FORMAT:
        raise ValueError('Expected normalized EKS Pod evidence wrapper')
    if set(doc) != {'format','collected_at','eks_input_identity','complete','services','endpointSlices'} or doc['format'] != FORMAT:
        raise ValueError('Expected normalized EKS Service evidence wrapper')
    services = index(doc['services'], True)
    slices = index(doc['endpointSlices'], True)
    pods = index(eks.get('pods'), True)
    eks_identity = 'sha256-eks-pod-v1:' + hashlib.sha256(eks_raw).hexdigest()
    times = [_timestamp(x) for x in (meta['collected_at'], eks['collected_at'], doc['collected_at'])]
    gap = (max(times)-min(times)).total_seconds()
    out = dict(analysis_type='STATIC_AWS_EKS_SERVICE_ENDPOINT_CORRELATION', input_identity=identity,
               eks_input_identity=eks_identity, service_input_identity='sha256-eks-service-v1:'+hashlib.sha256(service_raw).hexdigest(),
               namespace=namespace, service_name=service_name, service_port=service_port, time_gap_seconds=gap,
               service=None, selected_pods=[], registrations=[], target_selection='NOT_EVALUATED',
               route_status='NOT_EVALUATED', policy_status='NOT_EVALUATED', session_status='UNKNOWN', live_observation=False,
               limitations=['Offline normalized snapshots; membership, completeness and authenticity unverified.',
                            'Selector-backed single-stack IPv4 ClusterIP TCP only; Cluster traffic policy, no session affinity or traffic distribution.',
                            'Explicit EndpointSlice owner UID, controller identity, Pod targetRef and address/port correlation only; Service CIDR is not attested.',
                            'Ready conditions are snapshot evidence, not delivery or runtime selection; no Service DNAT, NetworkPolicy, SG/NACL, DNS or application verification.',
                            'No AWS or Kubernetes API calls or packets.'])
    def unknown(reason): return dict(out, status='UNKNOWN', reason=reason)
    if doc['eks_input_identity'] != eks_identity: return unknown('EKS_IDENTITY_MISMATCH')
    if eks['inventory_identity'] != identity: return unknown('INVENTORY_IDENTITY_MISMATCH')
    if doc['complete'] is not True or eks.get('complete') is not True: return unknown('EVIDENCE_INCOMPLETE')
    if gap > 300: return unknown('SNAPSHOT_TIME_GAP')
    svc = services.get((namespace, service_name))
    if not svc: return unknown('SERVICE_NOT_FOUND')
    if svc.get('kind')!='Service' or svc.get('apiVersion')!='v1': return unknown('SERVICE_API_UNSUPPORTED')
    sm, spec = svc['metadata'], obj(svc.get('spec'))
    if sm.get('deletionTimestamp') is not None: return unknown('SERVICE_TERMINATING')
    if (spec.get('type','ClusterIP')!='ClusterIP' or spec.get('internalTrafficPolicy','Cluster')!='Cluster'
        or spec.get('sessionAffinity','None')!='None' or spec.get('trafficDistribution') is not None
        or spec.get('publishNotReadyAddresses',False) is not False or spec.get('externalIPs')
        or spec.get('ipFamilies')!=['IPv4'] or spec.get('ipFamilyPolicy','SingleStack')!='SingleStack'):
        return unknown('SERVICE_PROFILE_UNSUPPORTED')
    ip = spec.get('clusterIP')
    try:
        if not isinstance(ip,str): raise ValueError()
        vip=IPv4Address(ip)
    except ValueError: return unknown('CLUSTER_IP_UNCONFIRMED')
    if spec.get('clusterIPs')!=[ip] or vip.is_unspecified or vip.is_loopback or vip.is_multicast or vip.is_link_local or vip.is_reserved or vip in IPv4Network(inv['Vpcs'][0]['CidrBlock']):
        return unknown('CLUSTER_IP_SCOPE_UNSUPPORTED')
    if any(s is not svc and obj(s.get('spec')).get('clusterIP')==ip for s in services.values()): return unknown('CLUSTER_IP_AMBIGUOUS')
    selector=labels(spec.get('selector',{}))
    if not selector: return unknown('SELECTORLESS_SERVICE_UNSUPPORTED')
    ports=[p for p in rows(spec.get('ports',[])) if p.get('protocol','TCP')=='TCP' and p.get('port')==service_port and _port(p.get('port'))]
    if len(ports)!=1: return unknown('SERVICE_TCP_PORT_UNCONFIRMED')
    port=ports[0]; port_name=port.get('name')
    if port_name is not None and not name(port_name): return unknown('SERVICE_PORT_NAME_UNCONFIRMED')
    out['service']=dict(uid=sm['uid'],cluster_ip=ip,protocol='TCP',port=service_port,port_name=port_name,target_port=port.get('targetPort',service_port),selector=selector)
    selected={key: p for key,p in pods.items() if key[0]==namespace and all(labels(p['metadata'].get('labels',{})).get(k)==v for k,v in selector.items())}
    if not selected: return unknown('NO_SELECTOR_MATCH')
    for key,p in selected.items():
        resolved=inspect_eks_pod(inventory_raw,eks_raw,*key)
        tp=target_port(port,p)
        out['selected_pods'].append(dict(name=key[1],uid=p['metadata']['uid'],target_port=tp,endpoint=resolved['endpoint'],endpoint_status=resolved['status'],endpoint_reason=resolved['reason']))
    by_uid={p['uid']:p for p in out['selected_pods']}
    matched=set(); bad=False; ready=0; relevant=0
    for (ns,slice_name),sl in slices.items():
        m=sl['metadata']; labs=labels(m.get('labels',{}))
        if ns!=namespace or labs.get('kubernetes.io/service-name')!=service_name: continue
        relevant+=1
        owners=[o for o in rows(m.get('ownerReferences',[])) if o.get('kind')=='Service' and o.get('apiVersion')=='v1' and o.get('name')==service_name and o.get('uid')==sm['uid'] and o.get('controller') is True]
        if (sl.get('apiVersion')!='discovery.k8s.io/v1' or sl.get('kind')!='EndpointSlice' or sl.get('addressType')!='IPv4' or m.get('deletionTimestamp') is not None
            or labs.get('endpointslice.kubernetes.io/managed-by')!='endpointslice-controller.k8s.io' or len(owners)!=1 or len(rows(m.get('ownerReferences',[])))!=1):
            out['registrations'].append(dict(slice_name=slice_name,status='UNKNOWN',reason='SLICE_OWNERSHIP_OR_PROFILE_UNCONFIRMED')); bad=True; continue
        sp=[p for p in rows(sl.get('ports',[])) if (p.get('name') or None)==port_name and p.get('protocol','TCP')=='TCP']
        if len(sp)!=1 or not _port(sp[0].get('port')):
            out['registrations'].append(dict(slice_name=slice_name,status='UNKNOWN',reason='SLICE_PORT_UNCONFIRMED')); bad=True; continue
        for e in rows(sl.get('endpoints',[])):
            ref=obj(e.get('targetRef',{})); uid=ref.get('uid'); p=by_uid.get(uid) if isinstance(uid,str) else None
            c=obj(e.get('conditions',{})); addr=e.get('addresses'); ep=p['endpoint'] if p else None
            row=dict(slice_name=slice_name,pod_name=p['name'] if p else None,pod_uid=uid if isinstance(uid,str) else None,
                     registered_port=sp[0]['port'],conditions={k:c.get(k) for k in ('ready','serving','terminating')},endpoint=ep)
            if (not p or not ep or ref.get('kind')!='Pod' or ref.get('apiVersion','v1')!='v1' or ref.get('namespace')!=namespace or ref.get('name')!=p['name']
                or addr!=[ep['private_ip']] or sp[0]['port']!=p['target_port'] or e.get('nodeName') not in (None,pods[(namespace,p['name'])]['spec']['nodeName'])):
                row.update(status='UNKNOWN',reason='POD_IP_PORT_OR_IDENTITY_MISMATCH'); bad=True
            elif uid in matched:
                row.update(status='UNKNOWN',reason='DUPLICATE_POD_REGISTRATION'); bad=True
            else:
                matched.add(uid)
                if c.get('ready') is True and c.get('serving') is True and c.get('terminating') is False:
                    row.update(status='READY_ENDPOINT_CANDIDATE',reason='MATCHED_SELECTOR_POD_UID_IP_AND_PORT'); ready+=1
                elif c.get('ready') is False and all(c.get(k) is None or type(c[k]) is bool for k in ('serving','terminating')):
                    row.update(status='NOT_READY_SNAPSHOT',reason='EXPLICIT_NOT_READY')
                else:
                    row.update(status='UNKNOWN',reason='ENDPOINT_CONDITIONS_UNCONFIRMED'); bad=True
            out['registrations'].append(row)
    out['ready_candidate_count']=ready
    out['unmatched_selected_pods']=sorted(set(by_uid)-matched)
    if not relevant: return unknown('ENDPOINT_SLICE_NOT_FOUND')
    if bad or out['unmatched_selected_pods']: return unknown('ENDPOINT_CORRELATION_INCOMPLETE')
    if not ready: return unknown('NO_READY_ENDPOINT_CANDIDATE')
    return dict(out,status='SERVICE_ENDPOINT_CORRELATION_CANDIDATE',reason='MATCHED_SERVICE_SELECTOR_AND_ENDPOINT_SLICES')
