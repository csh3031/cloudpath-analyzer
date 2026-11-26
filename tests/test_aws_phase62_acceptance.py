"""Cross-layer acceptance against synthetic on-disk inventory; not a live AWS/browser test."""
import json
from pathlib import Path
import pytest
from backend.aws.session_evidence import analyze_observed_session
from test_aws_web_session import app, body
from test_aws_web_review import run_js

DEMO = Path('samples/aws/phase62_demo')

@pytest.mark.parametrize('name,pred,conditional,stop,reply_stop', [
    ('aws_static_tcp_example', 'UNKNOWN', 'REACHABLE', None, None),
    ('request_blocked', 'BLOCKED', 'NOT_EVALUATED', 'request:SOURCE_SG_EGRESS', None),
    ('response_blocked', 'UNKNOWN', 'BLOCKED', None, 'response:SOURCE_NACL_EGRESS'),
    ('unknown_then_blocked', 'UNKNOWN', 'NOT_EVALUATED', 'request:SOURCE_SG_EGRESS', None),
])
def test_demo_end_to_end_contract(name,pred,conditional,stop,reply_stop):
    d=json.loads((DEMO/(name+'.json')).read_text())
    a=app(d); result=a.analyze_aws(body(a))
    direct=analyze_observed_session(a._aws_raw, result['scenario']['source_ip'], result['scenario']['destination_ip'],50000,443)
    assert {k:v for k,v in result.items() if k!='findings'} == {k:v for k,v in direct.items() if k!='findings'}
    assert [{k:v for k,v in f.items() if k!='web_resource_ids'} for f in result['findings']] == direct['findings']
    assert (result['predicted_connectivity'],result['conditional_connectivity'])==(pred,conditional)
    assert result['request']['stopped_at']==stop and result['response']['stopped_at']==reply_stop
    assert result['live_observation'] is False
    assert run_js(result,'validateAwsResult(d); console.log(JSON.stringify(awsRequestReplay(d).map(f=>f.id)));')==result['request']['trace']
    if name in ('request_blocked','unknown_then_blocked'):
        f=next(f for f in result['findings'] if f['id']=='request:ROUTE_LOOKUP')
        assert f['status']=='BLOCKED' and f['evaluation_mode']=='INDEPENDENT_CHECK'
        assert result['first_blocker']==(stop if pred=='BLOCKED' else None)
        assert result['response']['trace']==[]
    assert 'SYNTHETIC_DEMO' not in json.dumps(result)

@pytest.mark.parametrize('fault,stage',[('missing_route','ROUTE_LOOKUP'),('missing_acl','SOURCE_NACL_EGRESS'),('stopped_ec2','ENDPOINT_SCOPE')])
def test_uncertain_input_through_web_contract(fault,stage):
    d=json.loads((DEMO/'aws_static_tcp_example.json').read_text()); inv=d['inventory']
    if fault=='missing_route': inv['RouteTables'][0]['Routes']=[]
    elif fault=='missing_acl': inv['NetworkAcls'][0]['Associations']=[]
    else: inv['Reservations'][0]['Instances'][0]['State']['Name']='stopped'
    a=app(d); r=a.analyze_aws(body(a))
    assert r['predicted_connectivity']=='UNKNOWN' and r['conditional_connectivity']=='NOT_EVALUATED'
    assert r['first_blocker'] is None and r['request']['stopped_at']=='request:'+stage
    assert run_js(r,'validateAwsResult(d); console.log(JSON.stringify(awsRequestReplay(d).map(f=>f.id)));')==r['request']['trace']

def test_changed_fixture_identity_disables_saved_graph_emphasis():
    a=app(json.loads((DEMO/'aws_static_tcp_example.json').read_text()))
    b=app(json.loads((DEMO/'request_blocked.json').read_text()))
    r=a.analyze_aws(body(a)); assert a.identity!=b.identity
    with pytest.raises(ValueError): b.analyze_aws(body(a))
    data={'result':r,'newIdentity':b.identity,'known':[x.id for x in b.resources]}
    assert run_js(data,'validateAwsResult(d.result); console.log(JSON.stringify(awsEvidenceIds(d.result,d.result.findings[0],d.newIdentity,new Set(d.known))));')==[]
