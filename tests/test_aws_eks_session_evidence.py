import copy,hashlib,json
from pathlib import Path
import pytest
from backend.aws.eks_session_evidence import analyze_eks_pod_session, selector

ROOT=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
@pytest.fixture
def evidence():
    return [ (ROOT/'eks_pod_inventory.json').read_bytes(), json.loads((ROOT/'eks_policy_pods.json').read_bytes()),json.loads((ROOT/'eks_network_policy_evidence.json').read_bytes()) ]

def run(e,port=443,source_port=50000,bind=True,source='app-1',dest='app-2'):
    inv,eks,doc=copy.deepcopy(e); raw=json.dumps(eks).encode()
    if bind: doc['eks_input_identity']='sha256-eks-pod-v1:'+hashlib.sha256(raw).hexdigest()
    return analyze_eks_pod_session(inv,raw,json.dumps(doc).encode(),'demo',source,'demo',dest,source_port,port)

def check(r,stage): return next(x for x in r['request'] if x['stage']==stage)

def test_allow(evidence):
    r=run(evidence); assert r['request_status']==r['response_status']=='CONDITIONAL_CANDIDATE'
    assert r['session_status']=='UNKNOWN' and not r['live_observation'] and r['service_translation_status']=='NOT_EVALUATED'
    assert all(x['evaluation_mode']=='CONDITIONAL_CHECK' for x in r['response'])
    assert check(r,'SOURCE_SG_EGRESS')['eni_id']=='eni-12345678'
    assert check(r,'DESTINATION_SG_INGRESS')['eni_id']=='eni-87654321'

def test_np_block(evidence):
    r=run(evidence,8080); assert r['first_request_stop']=='SOURCE_NETWORK_POLICY_EGRESS'
    assert r['session_status']=='BLOCKED' and r['response_status']=='NOT_EVALUATED'
    assert all(x['evaluation_mode']=='INDEPENDENT_CHECK' for x in r['request'][1:]+r['response'])

def test_aws_block_despite_np_allow(evidence):
    r=run(evidence,8443); assert r['first_request_stop']=='DESTINATION_SG_INGRESS'
    assert check(r,'DESTINATION_NETWORK_POLICY_INGRESS')['status']=='ALLOW_CANDIDATE'
    assert check(r,'DESTINATION_NETWORK_POLICY_INGRESS')['evaluation_mode']=='INDEPENDENT_CHECK'

def test_ingress_block(evidence):
    evidence[2]['networkPolicies'][1]['spec']['ingress']=[]
    assert run(evidence)['first_request_stop']=='DESTINATION_NETWORK_POLICY_INGRESS'

def test_default_allow(evidence):
    evidence[2]['networkPolicies']=[]; r=run(evidence)
    assert check(r,'SOURCE_NETWORK_POLICY_EGRESS')['reason']=='NO_POLICY_ISOLATION'
    assert r['request_status']=='CONDITIONAL_CANDIDATE'

def test_additive(evidence):
    p=copy.deepcopy(evidence[2]['networkPolicies'][0]); p['metadata'].update(name='deny',uid='00000000-0000-0000-0000-000000000043'); p['spec']['egress']=[]
    evidence[2]['networkPolicies'].insert(0,p); r=run(evidence)
    assert r['request_status']=='CONDITIONAL_CANDIDATE'
    assert check(r,'SOURCE_NETWORK_POLICY_EGRESS')['selected_policies']==['deny','source-egress']

@pytest.mark.parametrize('key,value', [('network_policy_enabled',False),('settled',False),('standard_policies_only',False),('no_other_policy_engine',False),('enforcing_mode','strict'),('controller_limits_verified',False),('primary_interface_only',False),('direct_pod_ip_no_translation',False)])
def test_profile_unknown(evidence,key,value):
    evidence[2]['profile'][key]=value;r=run(evidence)
    assert r['request_status']=='UNKNOWN' and r['first_request_stop']=='SOURCE_NETWORK_POLICY_EGRESS' and r['response_status']=='NOT_EVALUATED'

def test_standalone(evidence):
    evidence[1]['pods'][0]['metadata'].pop('ownerReferences'); assert run(evidence)['request_status']=='UNKNOWN'

def test_identity(evidence): assert run(evidence,bind=False)['reason']=='EKS_IDENTITY_MISMATCH'

def test_incomplete(evidence):
    evidence[2]['complete']=False; assert run(evidence)['reason']=='POLICY_EVIDENCE_INCOMPLETE'

def test_stale(evidence):
    evidence[2]['collected_at']='2026-11-25T11:05:01+00:00'; assert run(evidence)['reason']=='SNAPSHOT_TIME_GAP'

def test_same_pod(evidence): assert run(evidence,dest='app-1')['reason']=='SAME_POD_CONTAINER_LISTENER_NOT_MODELED'

def test_missing_pod(evidence): assert run(evidence,dest='missing')['reason']=='POD_ENDPOINT_NOT_CONFIRMED'

@pytest.mark.parametrize('p',[0,65536,True,'443'])
def test_invalid_port(evidence,p):
    with pytest.raises(ValueError): run(evidence,p)

@pytest.mark.parametrize('op,values,labs,expected',[('In',['x'],{'a':'x'},True),('In',['x'],{},False),('NotIn',['x'],{},True),('NotIn',['x'],{'a':'x'},False),('Exists',[],{'a':''},True),('Exists',[],{},False),('DoesNotExist',[],{},True),('DoesNotExist',[],{'a':''},False)])
def test_selector(op,values,labs,expected): assert selector({'matchExpressions':[{'key':'a','operator':op,'values':values}]},labs) is expected

def test_and_peer(evidence):
    evidence[2]['networkPolicies'][1]['spec']['ingress'][0]['from'][0]['namespaceSelector']['matchLabels']['team']='other'
    assert run(evidence)['first_request_stop']=='DESTINATION_NETWORK_POLICY_INGRESS'

def test_or_peer(evidence):
    r=evidence[2]['networkPolicies'][1]['spec']['ingress'][0];r['from']=[{'namespaceSelector':{'matchLabels':{'team':'other'}}},{'podSelector':{'matchLabels':{'role':'frontend'}}}]
    assert run(evidence)['request_status']=='CONDITIONAL_CANDIDATE'

def test_ipblock_unknown(evidence):
    evidence[2]['networkPolicies'][0]['spec']['egress'][0]['to']=[{'ipBlock':{'cidr':'10.0.0.0/16'}}]
    assert run(evidence)['request_status']=='UNKNOWN'

def test_named_port_unknown(evidence):
    evidence[2]['networkPolicies'][0]['spec']['egress'][0]['ports']=[{'port':'http'}]
    assert run(evidence)['request_status']=='UNKNOWN'

def test_numeric_range(evidence):
    evidence[2]['networkPolicies'][0]['spec']['egress'][0]['ports']=[{'port':440,'endPort':450}]
    assert run(evidence)['request_status']=='CONDITIONAL_CANDIDATE'

def test_empty_rule(evidence):
    evidence[2]['networkPolicies'][0]['spec']['egress']=[{}]; assert run(evidence)['request_status']=='CONDITIONAL_CANDIDATE'

def test_udp_only(evidence):
    evidence[2]['networkPolicies'][0]['spec']['egress'][0]['ports']=[{'protocol':'UDP','port':443}];assert run(evidence)['request_status']=='BLOCKED'

def test_default_policy_types(evidence):
    evidence[2]['networkPolicies'][0]['spec'].pop('policyTypes'); assert run(evidence)['request_status']=='CONDITIONAL_CANDIDATE'

def test_invalid_selector(evidence):
    evidence[2]['networkPolicies'][0]['spec']['podSelector']={'matchExpressions':[{'key':'role','operator':'Bad'}]}; assert run(evidence)['request_status']=='UNKNOWN'

def test_cross_namespace_and_scope(evidence):
    inv,eks,doc=evidence
    ns=copy.deepcopy(eks['namespaces'][0]);ns['metadata'].update(name='other',uid='00000000-0000-0000-0000-000000000002',labels={'team':'other'});eks['namespaces'].append(ns)
    eks['pods'][1]['metadata']['namespace']='other';doc['networkPolicies'][1]['metadata']['namespace']='other'
    raw=json.dumps(eks).encode();doc['eks_input_identity']='sha256-eks-pod-v1:'+hashlib.sha256(raw).hexdigest()
    def analyze(): return analyze_eks_pod_session(inv,raw,json.dumps(doc).encode(),'demo','app-1','other','app-2',50000,443)
    assert analyze()['first_request_stop']=='SOURCE_NETWORK_POLICY_EGRESS'
    doc['networkPolicies'][0]['spec']['egress'][0]['to'][0]['namespaceSelector']={'matchLabels':{'team':'other'}}
    assert analyze()['request_status']=='CONDITIONAL_CANDIDATE'

def test_response_nacl_block(evidence):
    inv=json.loads(evidence[0]); inv['inventory']['NetworkAcls'][0]['Entries'].append({'RuleNumber':10,'Protocol':'6','RuleAction':'deny','Egress':True,'CidrBlock':'10.0.1.0/24','PortRange':{'From':50000,'To':50000}})
    raw=json.dumps(inv).encode()
    # Identity is based on sanitized inventory, not raw serialized bytes.
    from backend.aws.peering_evidence import _load
    evidence[0]=raw;evidence[1]['inventory_identity']=_load(raw)[0]
    r=run(evidence);assert r['request_status']=='CONDITIONAL_CANDIDATE' and r['response_status']=='BLOCKED'
    assert r['conditional_first_response_stop']=='SOURCE_NACL_EGRESS' and r['session_status']=='UNKNOWN'

def test_unsupported_cni(evidence):
    evidence[1]['cni']['prefix_delegation']=True;assert run(evidence)['reason']=='POD_ENDPOINT_NOT_CONFIRMED'
