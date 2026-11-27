import base64
import json
import threading
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import pytest
from scripts.serve_cloudpath import load_web_app, create_server

DEMO = Path('samples/aws/phase63_demo')

def enc(b): return base64.b64encode(b).decode()

def app():
    p=Path('samples/aws/phase62_demo/aws_static_tcp_example.json')
    return load_web_app([{'name':p.name,'content_base64':enc(p.read_bytes())}])

def body(a):
    return dict(scenario=dict(source=next(i for i,e in enumerate(a.endpoints) if e['ip']=='10.0.1.10'),
        destination=next(i for i,e in enumerate(a.endpoints) if e['ip']=='10.0.2.10'),protocol='tcp',
        source_port=50000,destination_port=443,input_identity=a.identity),files={
        'paths':enc((DEMO/'reachability_paths.json').read_bytes()),
        'analyses':enc((DEMO/'reachability_analyses.json').read_bytes()),
        'logs':enc((DEMO/'flow_logs_v2.txt').read_bytes())})

def test_combined_and_original_unchanged():
    a=app(); b=body(a); before=a.analyze_aws(b['scenario']); ctx=a.context(); html=a.html
    r=a.compare_aws_evidence(b)
    assert r['reachability']['comparison']=='CONSISTENT_CANDIDATE'
    assert r['flow_logs']['observation']=='ACCEPT_RECORDS' and r['flow_logs']['matched_records']==4
    assert r['flow_logs']['coverage_warnings']=={'SKIPDATA':1}
    assert r['cloudpath_predicted']=='UNKNOWN' and r['cloudpath_conditional']=='REACHABLE'
    assert r['live_observation'] is False and r['input_identity']==a.identity
    assert a.context()==ctx and a.html==html and a.analyze_aws(b['scenario'])==before

@pytest.mark.parametrize('roles',[('paths','analyses'),('logs',)])
def test_optional_sources(roles):
    a=app();b=body(a);b['files']={k:v for k,v in b['files'].items() if k in roles};r=a.compare_aws_evidence(b)
    assert bool(r['reachability'])==('paths' in roles) and bool(r['flow_logs'])==('logs' in roles)

def test_changed_port_recomputed():
    a=app();b=body(a);b['scenario']['destination_port']=80;r=a.compare_aws_evidence(b)
    assert r['cloudpath_predicted']=='BLOCKED'
    assert r['reachability']['comparison']=='NOT_COMPARABLE'
    assert r['flow_logs']['observation']=='NO_MATCHING_RECORDS'

@pytest.mark.parametrize('bad',[{}, {'paths':'aA=='}, {'unexpected':'aA=='}, {'logs':'??'}, {'logs':''}, {'logs':enc(b'x'*(5*1024*1024+1))}])
def test_invalid_file_request(bad):
    a=app(); b=body(a); b['files']=bad
    with pytest.raises(ValueError):a.compare_aws_evidence(b)

@pytest.mark.parametrize('field,value',[('input_identity','stale'),('protocol','udp'),('source_port',True)])
def test_invalid_scenario(field,value):
    a=app();b=body(a);b['scenario'][field]=value
    with pytest.raises(ValueError):a.compare_aws_evidence(b)

def test_invalid_evidence_no_mutation():
    a=app(); b=body(a); b['files']['logs']=enc(b'not a log'); ctx=a.context()
    with pytest.raises(ValueError):a.compare_aws_evidence(b)
    assert a.context()==ctx

def test_http_token_and_result():
    a=app()
    with create_server(a,0) as server:
        t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
        base=f'http://127.0.0.1:{server.server_port}'
        def post(payload,token):
            return urlopen(Request(base+'/api/aws-evidence',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json','Origin':base,'X-CloudPath-Token':token}),timeout=5)
        try:
            with pytest.raises(HTTPError) as e:post(body(a),'wrong')
            assert e.value.code==403
            with post(body(a),a.token) as response:r=json.load(response)
            assert r['reachability']['comparison']=='CONSISTENT_CANDIDATE'
            assert r['flow_logs']['matched_records']==4
            b=body(a);b['scenario']['input_identity']='stale'
            with pytest.raises(HTTPError) as e:post(b,a.token)
            assert e.value.code==400
        finally:server.shutdown();t.join(timeout=3)
