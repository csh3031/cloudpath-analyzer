import copy
import hashlib
import json
from pathlib import Path
import pytest
from backend.aws.eks_service_evidence import inspect_eks_service

ROOT=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'

@pytest.fixture
def evidence():
    return (ROOT/'eks_pod_inventory.json').read_bytes(), json.loads((ROOT/'eks_service_pods.json').read_bytes()), json.loads((ROOT/'eks_service_evidence.json').read_bytes())

def analyze(evidence, port=80, namespace='demo', service='demo-web', bind=True):
    inv,eks,doc=copy.deepcopy(evidence)
    raw=json.dumps(eks).encode()
    if bind: doc['eks_input_identity']='sha256-eks-pod-v1:'+hashlib.sha256(raw).hexdigest()
    return inspect_eks_service(inv,raw,json.dumps(doc).encode(),namespace,service,port)


def test_named_ports_and_multiple_slices(evidence):
    result=analyze(evidence)
    assert result['status']=='SERVICE_ENDPOINT_CORRELATION_CANDIDATE'
    assert result['ready_candidate_count']==2
    assert [r['registered_port'] for r in result['registrations']]==[8080,8081]
    assert [r['endpoint']['private_ip'] for r in result['registrations']]==['10.0.1.70','10.0.2.70']
    assert result['session_status']=='UNKNOWN' and result['target_selection']=='NOT_EVALUATED' and result['live_observation'] is False
    assert result['route_status']==result['policy_status']=='NOT_EVALUATED'


def test_numeric_target_port_does_not_require_container_declaration(evidence):
    _,eks,doc=evidence
    doc['services'][0]['spec']['ports'][0]['targetPort']=8080
    doc['endpointSlices'][1]['ports'][0]['port']=8080
    eks['pods'][0]['spec']['containers'][0].pop('ports')
    assert analyze(evidence)['status']=='SERVICE_ENDPOINT_CORRELATION_CANDIDATE'


def test_default_target_port(evidence):
    _,_,doc=evidence
    del doc['services'][0]['spec']['ports'][0]['targetPort']
    for s in doc['endpointSlices']: s['ports'][0]['port']=80
    assert analyze(evidence)['status']=='SERVICE_ENDPOINT_CORRELATION_CANDIDATE'


@pytest.mark.parametrize('key,value,reason',[
    ('type','NodePort','SERVICE_PROFILE_UNSUPPORTED'),('type','LoadBalancer','SERVICE_PROFILE_UNSUPPORTED'),
    ('internalTrafficPolicy','Local','SERVICE_PROFILE_UNSUPPORTED'),('sessionAffinity','ClientIP','SERVICE_PROFILE_UNSUPPORTED'),
    ('publishNotReadyAddresses',True,'SERVICE_PROFILE_UNSUPPORTED'),('trafficDistribution','PreferClose','SERVICE_PROFILE_UNSUPPORTED'),
    ('ipFamilies',['IPv4','IPv6'],'SERVICE_PROFILE_UNSUPPORTED'),('externalIPs',['192.0.2.1'],'SERVICE_PROFILE_UNSUPPORTED'),
    ('clusterIP','None','CLUSTER_IP_UNCONFIRMED'),('clusterIP','10.0.1.20','CLUSTER_IP_SCOPE_UNSUPPORTED'),
    ('selector',{},'SELECTORLESS_SERVICE_UNSUPPORTED'),('selector',{'app':'other'},'NO_SELECTOR_MATCH')])
def test_service_profiles(evidence,key,value,reason):
    evidence[2]['services'][0]['spec'][key]=value
    r=analyze(evidence); assert r['status']=='UNKNOWN' and r['reason']==reason


@pytest.mark.parametrize('case', ['wrong_uid','wrong_ip','wrong_port','wrong_name','wrong_namespace','wrong_kind','wrong_owner','wrong_manager','wrong_family','duplicate','missing_slice','missing_named_port','ambiguous_named_port','unconfirmed_pod','missing_conditions','terminating_ready','wrong_node'])
def test_incomplete_correlations(evidence,case):
    _,eks,doc=evidence
    s=doc['endpointSlices'][0]; e=s['endpoints'][0]; p=eks['pods'][0]
    if case=='wrong_uid': e['targetRef']['uid']='other'
    elif case=='wrong_ip': e['addresses']=['10.0.1.71']
    elif case=='wrong_port': s['ports'][0]['port']=8088
    elif case=='wrong_name': e['targetRef']['name']='app-2'
    elif case=='wrong_namespace': e['targetRef']['namespace']='other'
    elif case=='wrong_kind': e['targetRef']['kind']='Node'
    elif case=='wrong_owner': s['metadata']['ownerReferences'][0]['uid']='other'
    elif case=='wrong_manager': s['metadata']['labels']['endpointslice.kubernetes.io/managed-by']='custom'
    elif case=='wrong_family': s['addressType']='IPv6'
    elif case=='duplicate': s['endpoints'].append(copy.deepcopy(e))
    elif case=='missing_slice': doc['endpointSlices'].pop(0)
    elif case=='missing_named_port': p['spec']['containers'][0]['ports']=[]
    elif case=='ambiguous_named_port': p['spec']['containers'][0]['ports'].append({'name':'http','containerPort':9000})
    elif case=='unconfirmed_pod': p['spec']['hostNetwork']=True
    elif case=='missing_conditions': e['conditions']={}
    elif case=='terminating_ready': e['conditions']['terminating']=True
    elif case=='wrong_node': e['nodeName']='node-2'
    r=analyze(evidence); assert r['status']=='UNKNOWN' and r['reason']=='ENDPOINT_CORRELATION_INCOMPLETE'
    assert r['session_status']=='UNKNOWN'


def test_not_ready_is_not_candidate(evidence):
    e=evidence[2]['endpointSlices'][0]['endpoints'][0]; e['conditions']={'ready':False,'serving':False,'terminating':False}
    r=analyze(evidence); assert r['status']=='SERVICE_ENDPOINT_CORRELATION_CANDIDATE' and r['ready_candidate_count']==1
    assert r['registrations'][0]['status']=='NOT_READY_SNAPSHOT'


def test_no_ready(evidence):
    for s in evidence[2]['endpointSlices']: s['endpoints'][0]['conditions']={'ready':False,'serving':False,'terminating':False}
    assert analyze(evidence)['reason']=='NO_READY_ENDPOINT_CANDIDATE'


def test_missing_service(evidence): assert analyze(evidence,service='missing')['reason']=='SERVICE_NOT_FOUND'
def test_missing_port(evidence): assert analyze(evidence,port=81)['reason']=='SERVICE_TCP_PORT_UNCONFIRMED'
def test_identity(evidence): assert analyze(evidence,bind=False)['reason']=='EKS_IDENTITY_MISMATCH'
def test_incomplete(evidence):
    evidence[2]['complete']=False; assert analyze(evidence)['reason']=='EVIDENCE_INCOMPLETE'
def test_time_span(evidence):
    evidence[2]['collected_at']='2026-11-25T11:05:01+00:00'; assert analyze(evidence)['reason']=='SNAPSHOT_TIME_GAP'
def test_empty_slices(evidence):
    evidence[2]['endpointSlices']=[]; assert analyze(evidence)['reason']=='ENDPOINT_SLICE_NOT_FOUND'
def test_duplicate_service(evidence):
    evidence[2]['services'].append(copy.deepcopy(evidence[2]['services'][0]))
    with pytest.raises(ValueError): analyze(evidence)
def test_malformed_port(evidence):
    with pytest.raises(ValueError): analyze(evidence,port=0)


def test_inventory_identity_mismatch(evidence):
    evidence[1]['inventory_identity']='wrong'; assert analyze(evidence)['reason']=='INVENTORY_IDENTITY_MISMATCH'

def test_invalid_pod_wrapper(evidence):
    evidence[1].pop('collected_at')
    with pytest.raises(ValueError): analyze(evidence)

def test_invalid_conditions_not_coerced(evidence):
    evidence[2]['endpointSlices'][0]['endpoints'][0]['conditions']={'ready':False,'serving':1,'terminating':False}
    assert analyze(evidence)['reason']=='ENDPOINT_CORRELATION_INCOMPLETE'
