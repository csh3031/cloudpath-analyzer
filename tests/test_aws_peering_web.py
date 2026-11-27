import base64,json,threading
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError
import pytest
from backend.aws.peering_web import analyze_peering_upload
from backend.aws.peering_session_evidence import analyze_peering_session
from scripts.serve_cloudpath import load_web_app,create_server

DEMO=Path('samples/aws/phase7_demo')
ROLES=('source_file','destination_file','peering_file')
def entry(name):
    return dict(name=name,content_base64=base64.b64encode((DEMO/name).read_bytes()).decode())
def body(blocked=False):
    suffix='' if blocked else '_policy_candidate'
    return dict(input_identity='current',source_file=entry('peering_source'+suffix+'.json'),destination_file=entry('peering_destination'+suffix+'.json'),peering_file=entry('peering_connections.json'),source_ip='10.0.1.10',destination_ip='10.1.2.10',source_port=50000,destination_port=443,protocol='tcp')
@pytest.mark.parametrize('blocked',[False,True])
def test_matches_cli(blocked):
    b=body(blocked);p=analyze_peering_upload(b,'current');r=p['result']
    assert r==analyze_peering_session(*(base64.b64decode(b[k]['content_base64']) for k in ROLES),b['source_ip'],b['destination_ip'],50000,443)
    assert r['session_status']==('BLOCKED' if blocked else 'UNKNOWN')
    assert [v['identity'] for v in p['vpcs']]==[r['source_input_identity'],r['destination_input_identity']]
    assert len(p['vpcs'][0]['instances'])==2
@pytest.mark.parametrize('key,value',[('input_identity','stale'),('source_port',True),('destination_port',0),('source_ip','::1'),('destination_ip','example.org'),('protocol','udp'),('source_file',{'name':'a.tf','content_base64':'eA=='}),('peering_file',{'name':'a.json','content_base64':'!'})])
def test_rejects_invalid(key,value):
    with pytest.raises(ValueError):analyze_peering_upload(body()|{key:value},'current')
def test_rejects_wrong_role():
    b=body();b['peering_file']=b['source_file']
    with pytest.raises(ValueError):analyze_peering_upload(b,'current')
def test_combined_limit(monkeypatch):
    monkeypatch.setattr('backend.aws.peering_web.MAX_BYTES',1)
    with pytest.raises(ValueError,match='Total'):analyze_peering_upload(body(),'current')
def test_http():
    a=load_web_app([entry('peering_source.json')]);before=a.context();b=body()|{'input_identity':a.identity}
    with create_server(a,0) as server:
        t=threading.Thread(target=server.serve_forever,daemon=True);t.start();base=f'http://127.0.0.1:{server.server_port}'
        def post(token,origin=base):return urlopen(Request(base+'/api/aws-peering',data=json.dumps(b).encode(),headers={'Content-Type':'application/json','Origin':origin,'X-CloudPath-Token':token}),timeout=5)
        try:
            with urlopen(base+'/peering',timeout=5) as f:assert b'id="diagram"' in f.read()
            assert b'href="/peering"' in a.html
            for token,origin in [('bad',base),(a.token,'http://example.org')]:
                with pytest.raises(HTTPError) as exc:post(token,origin)
                assert exc.value.code==403
            with post(a.token) as f:assert json.load(f)['result']['request_status']=='CONDITIONAL_CANDIDATE'
            with urlopen(base+'/api/context',timeout=5) as f:assert json.load(f)==before
        finally:server.shutdown();t.join(timeout=3)
