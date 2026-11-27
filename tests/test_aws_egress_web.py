"""Separate bounded internet-egress web contract; no AWS or packets."""
import base64
import json
import threading
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import pytest
from scripts.serve_cloudpath import load_web_app, create_server
from backend.aws.egress_session_evidence import analyze_internet_egress_session
from test_aws_web_review import run_js

DEMO=Path('samples/aws/phase7_demo')

def app(name='public_nat_egress_policy_candidate.json'):
    p=DEMO/name
    return load_web_app([{'name':p.name,'content_base64':base64.b64encode(p.read_bytes()).decode()}])

def body(a,**kw):
    return dict(source=next(i for i,e in enumerate(a.endpoints) if e['ip']=='10.0.1.10'),destination_ip='8.8.8.8',protocol='tcp',source_port=50000,destination_port=443,input_identity=a.identity)|kw

@pytest.mark.parametrize('name,status,stop', [('public_nat_egress_policy_candidate.json','UNKNOWN',None),('public_nat_egress_v2.json','BLOCKED','SOURCE_NACL_EGRESS')])
def test_api_same_as_cli(name,status,stop):
    a=app(name);b=body(a);ctx=a.context();r=a.analyze_aws_egress(b)
    assert r==analyze_internet_egress_session((DEMO/name).read_bytes(),'10.0.1.10','8.8.8.8',50000,443)
    assert r['session_status']==status and r['first_request_stop']==stop and a.context()==ctx
    assert ctx['snapshot']['aws_egress_available'] is True
    assert run_js(r,'validateEgressResult(d);console.log(JSON.stringify(classifyInputJson(d)))')=='AWS_EGRESS_RESULT'

@pytest.mark.parametrize('key,value',[('source',True),('source',999),('destination_ip','8.8.8.8\n'),('destination_ip','example.com'),('destination_ip','::1'),('protocol','udp'),('source_port',0),('destination_port',True),('input_identity','stale')])
def test_invalid_egress_request(key,value):
    a=app()
    with pytest.raises(ValueError):a.analyze_aws_egress(body(a,**{key:value}))

@pytest.mark.parametrize('dst',['10.0.2.10','224.0.0.1'])
def test_unsupported_dest_preserves_unknown(dst):
    a=app();r=a.analyze_aws_egress(body(a,destination_ip=dst))
    assert r['session_status']=='UNKNOWN' and not r['response']
    assert run_js(r,'validateEgressResult(d);console.log(true)') is True

def test_contract_and_evidence_identity():
    a=app('public_nat_egress_v2.json');b=body(a);r=a.analyze_aws_egress(b)
    assert run_js(dict(r=r,b=b,c=a.context()),'''const row=d.r.request[1],known=new Set(['aws_network_acl.'+row.acl_id]);console.log(JSON.stringify([sameEgressScenario(d.r,d.b,d.c),sameEgressScenario(d.r,{...d.b,destination_port:80},d.c),egressEvidenceIds(d.r,row,d.r.input_identity,known),egressEvidenceIds(d.r,row,'stale',known),explainEgressRow(row)]));''')==[True,False,['aws_network_acl.acl-12345678'],[],'네트워크 ACL 차단 · 규칙 32767 · MATCHING_ACL_RULE']
    r['request'][2]['evaluation_mode']='PREDICTED_PATH'
    assert run_js(r,'try{validateEgressResult(d);console.log(false)}catch(e){console.log(true)}') is True

def test_http_and_restriction():
    a=app();b=body(a)
    with create_server(a,0) as server:
        t=threading.Thread(target=server.serve_forever,daemon=True);t.start();base=f'http://127.0.0.1:{server.server_port}'
        def post(path,token):
            return urlopen(Request(base+path,data=json.dumps(b).encode(),headers={'Content-Type':'application/json','Origin':base,'X-CloudPath-Token':token}),timeout=5)
        try:
            with pytest.raises(HTTPError) as e:post('/api/aws-egress','wrong')
            assert e.value.code==403
            with post('/api/aws-egress',a.token) as response:assert json.load(response)['request_status']=='CONDITIONAL_CANDIDATE'
            for path in ['/api/analyze','/api/aws-analyze','/api/aws-evidence']:
                with pytest.raises(HTTPError) as e:post(path,a.token)
                assert e.value.code==400
        finally:server.shutdown();t.join(timeout=3)
