import copy,hashlib,json
from pathlib import Path
import pytest
from backend.aws.eks_service_session_evidence import analyze_eks_service_session, PROFILE
P=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'

def inputs(mixed=False):
    return [(P/'eks_pod_inventory.json').read_bytes(),*[json.loads((P/n).read_bytes()) for n in ('eks_service_session_pods.json','eks_service_session_mixed_services.json' if mixed else 'eks_service_session_services.json','eks_service_session_policy.json','eks_service_session_mixed_translation.json' if mixed else 'eks_service_translation_evidence.json')]]

def run(e=None,port=443,service=None,bind=True,source='app-1',source_port=50000):
    inv,eks,svc,pol,tr=copy.deepcopy(e if e is not None else inputs())
    def raw(d): return json.dumps(d).encode()
    def id(p,d): return p+':'+hashlib.sha256(raw(d)).hexdigest()
    if bind:
        tr['eks_input_identity']=svc['eks_input_identity']=pol['eks_input_identity']=id('sha256-eks-pod-v1',eks)
        tr['service_input_identity']=id('sha256-eks-service-v1',svc);tr['policy_input_identity']=id('sha256-eks-network-policy-v1',pol)
    return analyze_eks_service_session(inv,raw(eks),raw(svc),raw(pol),raw(tr),'demo',source,'demo',service or 'demo-tls-'+str(port),source_port,port)

def test_allow():
    r=run(); b=r['branches'][0]; assert r['status']=='SERVICE_PATH_CONSTRAINTS_CANDIDATE' and r['backend_summary']=='ALL_BACKEND_CHECKS_CONDITIONAL'
    assert b['original_destination']=={'ip':'172.20.0.11','port':443}
    assert b['request_tuple']==dict(source_ip='10.0.1.70',source_port=50000,destination_ip='10.0.2.70',destination_port=443)
    assert b['conditional_reply_tuple']['client_visible_source_ip']=='172.20.0.11' and b['conditional_reply_tuple']['destination_port']==50000
    assert b['backend_check']['scope']=='COUNTERFACTUAL_DIRECT_BACKEND_LEG' and r['session_status']=='UNKNOWN' and not r['live_observation'] and r['target_selection']=='NOT_EVALUATED'

def test_sg_block():
    r=run(port=8443); b=r['branches'][0]; assert b['backend_check']['first_request_stop']=='DESTINATION_SG_INGRESS' and r['backend_summary']=='ALL_BACKEND_CHECKS_BLOCKED' and r['session_status']=='UNKNOWN'

def test_np_block():
    e=inputs();e[3]['networkPolicies'][0]['spec']['egress']=[];r=run(e); assert r['branches'][0]['backend_check']['first_request_stop']=='SOURCE_NETWORK_POLICY_EGRESS'

def test_unequal_port_and_hairpin():
    r=run(inputs(True),80,'demo-web'); a,b=r['branches'];assert r['status']=='UNKNOWN' and r['backend_summary']=='UNRESOLVED_BACKEND_PRESENT'
    assert a['reason']=='CROSS_NODE_SUBNET_REQUIRED' and a['candidate_destination']['port']==8080 and a['request_tuple'] is None
    assert b['reason']=='VPC_CNI_SERVICE_CONTAINER_PORT_MISMATCH' and b['request_tuple']['destination_port']==8081 and b['backend_check'] is None

@pytest.mark.parametrize('key',list(PROFILE))
def test_profile_unknown(key):
    e=inputs();e[4]['profile'][key]='ipvs' if key=='proxy_mode' else False;r=run(e);assert r['status']=='UNKNOWN' and r['branches'][0]['translation_status']=='CONFIGURED_MAPPING_ONLY' and r['branches'][0]['backend_check'] is None

@pytest.mark.parametrize('i',[3,4])
def test_incomplete(i):
    e=inputs();e[i]['complete']=False;assert run(e)['reason']=='EVIDENCE_INCOMPLETE'

@pytest.mark.parametrize('i',[1,2,3,4])
def test_gap(i):
    e=inputs();e[i]['collected_at']='2026-11-25T11:06:00+00:00';assert run(e)['reason']=='SNAPSHOT_TIME_GAP'

def test_global_gap():
    e=inputs();e[2]['collected_at']='2026-11-25T10:56:00+00:00';e[3]['collected_at']='2026-11-25T11:04:00+00:00';assert run(e)['reason']=='SNAPSHOT_TIME_GAP'

def test_bad_binding(): assert run(bind=False)['reason']=='EVIDENCE_IDENTITY_MISMATCH'
def test_uid():
    e=inputs();e[4]['source_pod_uid']='wrong';assert run(e)['reason']=='SOURCE_POD_UID_MISMATCH'
def test_source_missing(): assert run(source='missing')['reason']=='SOURCE_POD_UNCONFIRMED'
def test_service_missing(): assert run(service='missing')['reason']=='SERVICE_CORRELATION_UNCONFIRMED'
def test_port_missing(): assert run(port=81,service='demo-tls-443')['reason']=='SERVICE_CORRELATION_UNCONFIRMED'
def test_not_ready():
    e=inputs();e[2]['endpointSlices'][0]['endpoints'][0]['conditions']['ready']=False;assert run(e)['reason']=='SERVICE_CORRELATION_UNCONFIRMED'
def test_mismatch_port():
    e=inputs();e[2]['endpointSlices'][0]['ports'][0]['port']=444;assert run(e)['reason']=='SERVICE_CORRELATION_UNCONFIRMED'
def test_policy_unknown():
    e=inputs();e[3]['profile']['settled']=False;r=run(e);assert r['branches'][0]['reason']=='BACKEND_LEG_UNRESOLVED' and r['status']=='UNKNOWN'
@pytest.mark.parametrize('port',[0,65536,True])
def test_invalid_ports(port):
    with pytest.raises(ValueError):run(source_port=port)
def test_unknown_format():
    e=inputs();e[4]['format']='wrong'
    with pytest.raises(ValueError):run(e)
def test_extra_profile():
    e=inputs();e[4]['profile']['unexpected']=True;assert run(e)['branches'][0]['reason']=='TRANSLATION_PROFILE_UNCONFIRMED'
def test_bound_demo_raw():
    raw=[(P/n).read_bytes() for n in ('eks_pod_inventory.json','eks_service_session_pods.json','eks_service_session_services.json','eks_service_session_policy.json','eks_service_translation_evidence.json')]
    assert analyze_eks_service_session(*raw,'demo','app-1','demo','demo-tls-443',50000,443)['backend_summary']=='ALL_BACKEND_CHECKS_CONDITIONAL'

def test_named_port_mismatch():
    e=inputs();e[2]['services'][0]['spec']['ports'][0]['targetPort']='tls';e[2]['services'][0]['spec']['ports'][0]['name']='other';e[2]['endpointSlices'][0]['ports'][0]['name']='other'
    r=run(e);assert r['branches'][0]['reason']=='VPC_CNI_NAMED_PORT_MISMATCH' and r['branches'][0]['backend_check'] is None

def test_named_port_match():
    e=inputs();e[2]['services'][0]['spec']['ports'][0]['targetPort']='tls';assert run(e)['backend_summary']=='ALL_BACKEND_CHECKS_CONDITIONAL'

def test_partial_branch_not_overwritten_by_allow():
    e=inputs(True);e[2]['services'][0]['spec']['ports'][0].update(port=443,name='http');
    for pod,sl in zip(e[1]['pods'],e[2]['endpointSlices']):
        pod['spec']['containers'][0]['ports'][0]['containerPort']=443;sl['ports'][0].update(name='http',port=443)
    r=run(e,443,'demo-web');assert r['status']=='UNKNOWN' and r['backend_summary']=='UNRESOLVED_BACKEND_PRESENT'
    assert [b['status'] for b in r['branches']]==['UNKNOWN','BACKEND_PATH_CANDIDATE']
