import json
import threading
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import pytest
from scripts.serve_cloudpath import AnalysisApp, create_server, FLAGS
from test_session_analyzer import fixture

@pytest.fixture
def app():
    return AnalysisApp(fixture(), 'test-identity')

def payload(app, **kw):
    return dict(source=0,destination=1,protocol='tcp',source_port=49152,destination_port=443,
                input_identity=app.identity, **{k:k!='assume_unmodified_default_nacl' for k in FLAGS}) | kw

def test_web_context(app):
    assert [x['ip'] for x in app.context()['endpoints']]==['10.0.1.10','10.0.2.20']
    assert b'id="live-form"' in app.html

def test_web_allowed(app):
    r=app.analyze(payload(app));assert r['predicted_connectivity']=='REACHABLE' and r['input_identity']==app.identity

def test_web_request_blocked(app):
    r=app.analyze(payload(app,destination_port=5432));assert r['predicted_connectivity']=='BLOCKED' and r['first_blocker_step']=='REQ04'

def test_web_response_blocked(app):
    r=app.analyze(payload(app,source_port=49153));assert r['predicted_connectivity']=='BLOCKED' and r['first_blocker_step']=='RET02'

def test_web_missing_assumptions(app):
    r=app.analyze(payload(app,complete_config=False,complete_routing_config=False,assume_direct_private=False));assert r['predicted_connectivity']=='UNKNOWN'

@pytest.mark.parametrize('kw',[{'source':True},{'destination':0},{'source_port':0},{'destination_port':65536},{'protocol':'icmp'},{'input_identity':'stale'},{'complete_config':'true'},{'path':'/tmp/file'}])
def test_web_invalid(app,kw):
    with pytest.raises(ValueError): app.analyze(payload(app,**kw))

def test_http_contract(app):
    with create_server(app,0) as server:
        t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
        try:
            base=f'http://127.0.0.1:{server.server_port}'
            with urlopen(base+'/api/context',timeout=3) as response: c=json.load(response)
            assert c['input_identity']==app.identity
            data=json.dumps(payload(app)).encode()
            headers={'Content-Type':'application/json','Origin':base,'X-CloudPath-Token':c['token']}
            with urlopen(Request(base+'/api/analyze',data,headers),timeout=3) as response: assert json.load(response)['predicted_connectivity']=='REACHABLE'
            for bad in ({**headers,'Origin':'http://example.com'},{**headers,'X-CloudPath-Token':'wrong'}):
                with pytest.raises(HTTPError) as e: urlopen(Request(base+'/api/analyze',data,bad),timeout=3)
                assert e.value.code==403
            with pytest.raises(HTTPError) as e: urlopen(base+'/samples/terraform/session_demo.tf',timeout=3)
            assert e.value.code==404
        finally:
            server.shutdown();t.join(timeout=3)

def test_web_hcl_demo():
    from pathlib import Path
    from backend.iac.terraform_parser import parse_terraform
    from backend.iac.input_identity import input_identity
    p=Path('samples/terraform/session_demo.tf')
    a=AnalysisApp(parse_terraform(p),input_identity([p]))
    for sport,dport,status,first in [(49152,443,'REACHABLE',None),(49152,5432,'BLOCKED','REQ04'),(49153,443,'BLOCKED','RET02')]:
        r=a.analyze(payload(a,source_port=sport,destination_port=dport));assert (r['predicted_connectivity'],r['first_blocker_step'])==(status,first)
