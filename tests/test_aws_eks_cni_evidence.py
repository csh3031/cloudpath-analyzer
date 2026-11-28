import json
from pathlib import Path
import pytest
from backend.aws.eks_cni_evidence import inspect_eks_cni

P=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
INV=(P/'eks_pod_inventory.json').read_bytes()
EKS=(P/'eks_policy_pods.json').read_bytes()
POL=(P/'eks_network_policy_evidence.json').read_bytes()
OBS=(P/'eks_cni_observation.json').read_bytes()

def run(doc=None,port=443,source_port=50000):
    return inspect_eks_cni(INV,EKS,POL,OBS if doc is None else json.dumps(doc).encode(), 'demo','app-1','demo','app-2',source_port,port)

def fixture(): return json.loads(OBS)

def test_both_nodes_consistent():
    x=run(); assert x['status']=='CNI_EVIDENCE_CONSISTENT_CANDIDATE'
    assert all(r['status']=='CONSISTENT_EVENT_CANDIDATE' for r in x['comparisons'])
    assert x['enforcement_status']==x['session_status']=='UNKNOWN' and not x['live_observation']

def test_source_deny_no_destination_event():
    x=run(port=8080); assert x['status']=='UNKNOWN'
    assert x['comparisons'][0]['status']=='CONSISTENT_EVENT_CANDIDATE'
    assert x['comparisons'][1]['reason']=='NO_MATCHING_HISTORICAL_EVENT'
    assert x['static_analysis']['session_status']=='BLOCKED' and x['session_status']=='UNKNOWN'

def test_disagreement_with_source_policy():
    x=run(port=8443); assert x['status']=='CNI_EVIDENCE_DISCREPANCY_CANDIDATE'
    assert x['comparisons'][0]['reason']=='DECLARATION_EVENT_MISMATCH'
    assert x['static_analysis']['first_request_stop']=='DESTINATION_SG_INGRESS'

@pytest.mark.parametrize('field,value,reason',[
 ('eks_input_identity','wrong','OBSERVATION_IDENTITY_MISMATCH'),
 ('policy_input_identity','wrong','OBSERVATION_IDENTITY_MISMATCH'),
 ('cluster_arn','wrong','OBSERVATION_IDENTITY_MISMATCH'),
 ('complete',False,'OBSERVATION_INCOMPLETE'),('complete',1,'OBSERVATION_INCOMPLETE'),
 ('collected_at','2026-11-25T11:05:01Z','SNAPSHOT_TIME_GAP')])
def test_wrapper_guard(field,value,reason):
    d=fixture();d[field]=value;x=run(d);assert x['status']=='UNKNOWN' and x['reason']==reason and x['comparisons']==[]

@pytest.mark.parametrize('field,value,reason',[
 ('agent_ready',False,'NODE_AGENT_STATE_UNCONFIRMED'),('agent_ready',1,'NODE_AGENT_STATE_UNCONFIRMED'),
 ('policy_enabled',False,'CNI_POLICY_REPORTED_DISABLED'),('policy_enabled',None,'NODE_AGENT_STATE_UNCONFIRMED'),
 ('event_logging_enabled',False,'EVENT_LOGGING_UNCONFIRMED'),('attached_pod_uids',[],'POD_ATTACHMENT_EVIDENCE_MISSING')])
def test_node_guard(field,value,reason):
    d=fixture();d['nodes'][0][field]=value;x=run(d);assert x['status']=='UNKNOWN' and x['comparisons'][0]['reason']==reason

@pytest.mark.parametrize('change,reason',[
 ('node','NODE_AGENT_EVIDENCE_MISSING'),('endpoint','POLICY_ENDPOINT_ASSOCIATION_MISSING'),('uid','POLICY_ENDPOINT_ASSOCIATION_MISSING'),('namespace','POLICY_ENDPOINT_ASSOCIATION_MISSING'),('pod','POLICY_ENDPOINT_ASSOCIATION_MISSING')])
def test_missing_association(change,reason):
    d=fixture()
    if change=='node': d['nodes'].pop(0)
    elif change=='endpoint': d['policyEndpoints'].pop(0)
    else: d['policyEndpoints'][0][{'uid':'policy_uid','namespace':'namespace','pod':'pod_uid'}[change]]='other'
    x=run(d); assert x['status']=='UNKNOWN' and x['comparisons'][0]['reason']==reason

@pytest.mark.parametrize('field,value', [('Src IP','10.0.1.71'),('Dest IP','10.0.2.71'),('Src Port',50001),('Dest Port',444),('Proto','UDP'),('Verdict','DROP'),('Src Port','50000'),('msg','other'),('timestamp','2026-11-25T10:54:59Z'),('timestamp','2026-11-25T11:00:01Z')])
def test_wrong_event(field,value):
    d=fixture();d['events'][0]['log'][field]=value;x=run(d);assert x['status']=='UNKNOWN' and x['comparisons'][0]['reason']=='NO_MATCHING_HISTORICAL_EVENT'

@pytest.mark.parametrize('field', ['node_uid','pod_uid'])
def test_wrong_event_attribution(field):
    d=fixture();d['events'][0][field]='other';assert run(d)['comparisons'][0]['reason']=='NO_MATCHING_HISTORICAL_EVENT'

def test_conflicting_events():
    d=fixture();e=json.loads(json.dumps(d['events'][0]));e['log']['Verdict']='DENY';d['events'].append(e)
    x=run(d);assert x['status']=='UNKNOWN' and x['comparisons'][0]['reason']=='CONFLICTING_HISTORICAL_EVENTS'

def test_no_event_is_not_deny():
    d=fixture();d['events']=[];x=run(d);assert x['status']=='UNKNOWN' and all(r['reason']=='NO_MATCHING_HISTORICAL_EVENT' for r in x['comparisons'])

@pytest.mark.parametrize('key',['nodes','policyEndpoints'])
def test_duplicate(key):
    d=fixture();d[key].append(d[key][0]);
    with pytest.raises(ValueError): run(d)

def test_unexpected_wrapper():
    d=fixture();d['extra']=True
    with pytest.raises(ValueError): run(d)

def test_bad_timestamp():
    d=fixture();d['events'][0]['log']['timestamp']='no'
    with pytest.raises(ValueError): run(d)
