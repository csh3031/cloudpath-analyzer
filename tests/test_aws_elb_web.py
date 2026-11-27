import base64,json,threading
from pathlib import Path
from urllib.request import Request,urlopen
from urllib.error import HTTPError
import pytest
from backend.aws.elb_web import analyze_elb_upload,FILES
from backend.aws.elb_path_evidence import inspect_elb_paths
from scripts.serve_cloudpath import load_web_app,create_server

P=Path('samples/aws/phase7_demo')
def entry(n): return dict(name=n,content_base64=base64.b64encode((P/n).read_bytes()).decode())
def body(kind='alb'):
    a=kind=='alb'
    return dict(input_identity='current',kind=kind,inventory_file=entry('elbv2_inventory.json'),elbv2_file=entry('elbv2_rule_evidence.json' if a else 'elbv2_evidence.json'),health_file=entry(kind+'_target_health.json'),path_file=entry(kind+'_path_evidence.json'),rules_file=entry('alb_rules.json') if a else None,attributes_file=None if a else entry('nlb_attributes_translate.json'),load_balancer_id='1111111111111111' if a else '2222222222222222',host='api.example.com' if a else None,path='/api/items' if a else None,listener_port=443,client_ip='10.0.1.10',frontend_node_ip='10.0.2.50',backend_node_ip='10.0.1.50',client_port=50000,backend_source_port=51000,health_source_port=52000)
@pytest.mark.parametrize('kind',['alb','nlb'])
def test_matches_cli(kind):
    b=body(kind); p=analyze_elb_upload(b,'current');r=p['result'];raw=lambda k:base64.b64decode(b[k]['content_base64']) if b[k] else None
    assert r==inspect_elb_paths(*(raw(k) for k in FILES[:4]),b['load_balancer_id'],443,b['client_ip'],frontend_node_ip=b['frontend_node_ip'],backend_node_ip=b['backend_node_ip'],client_port=50000,backend_source_port=51000,health_source_port=52000,rules_raw=raw('rules_file'),attributes_raw=raw('attributes_file'),host=b['host'],path=b['path'])
    assert r['frontend']['request_status']=='CONDITIONAL_CANDIDATE' and r['targets'][0]['backend_status']=='RULE_BLOCK_CANDIDATE' and r['targets'][0]['health_check_status']=='CONDITIONAL_CANDIDATE'
    assert p['vpc']['identity']==r['input_identity'] and len(p['vpc']['subnets'])==2 and len(p['vpc']['instances'])==2
@pytest.mark.parametrize('k,v',[('input_identity','stale'),('kind','other'),('listener_port',True),('client_port',0),('backend_source_port',65536),('health_source_port','52000'),('client_ip','::1'),('frontend_node_ip','foo'),('backend_node_ip',None),('host',None),('rules_file',None),('inventory_file',{'name':'a.tf','content_base64':'eA=='}),('path_file',{'name':'a.json','content_base64':'!'})])
def test_invalid(k,v):
    with pytest.raises(ValueError):analyze_elb_upload(body()|{k:v},'current')
def test_unexpected_role():
    with pytest.raises(ValueError):analyze_elb_upload(body()|{'attributes_file':entry('nlb_attributes_translate.json')},'current')
def test_wrong_role():
    b=body();b['path_file']=b['health_file']
    with pytest.raises(ValueError):analyze_elb_upload(b,'current')
def test_limit(monkeypatch):
    monkeypatch.setattr('backend.aws.elb_web.MAX_BYTES',1)
    with pytest.raises(ValueError,match='Total'):analyze_elb_upload(body(),'current')
def test_preserved_nlb_not_composed():
    b=body('nlb');b['attributes_file']=entry('nlb_attributes_preserve.json');r=analyze_elb_upload(b,'current')['result'];assert r['targets'][0]['backend'] is None and r['targets'][0]['backend_status']=='UNKNOWN_PRESERVED_NLB_PATH_NOT_COMPOSED'
def test_unknown_scope():
    r=analyze_elb_upload(body()|{'frontend_node_ip':'10.0.1.10'},'current')['result'];assert r['frontend'] is None and r['session_status']=='UNKNOWN'
def test_http():
    a=load_web_app([entry('elbv2_inventory.json')]);before=a.context();b=body()|{'input_identity':a.identity}
    with create_server(a,0) as server:
        t=threading.Thread(target=server.serve_forever,daemon=True);t.start();base=f'http://127.0.0.1:{server.server_port}'
        def post(token,origin=base):return urlopen(Request(base+'/api/aws-elb',data=json.dumps(b).encode(),headers={'Content-Type':'application/json','Origin':origin,'X-CloudPath-Token':token}),timeout=5)
        try:
            with urlopen(base+'/elb',timeout=5) as f: assert b'id="diagram"' in f.read()
            assert b'href="/elb"' in a.html
            for token,origin in [('bad',base),(a.token,'http://example.org')]:
                with pytest.raises(HTTPError) as exc:post(token,origin)
                assert exc.value.code==403
            with post(a.token) as f:assert json.load(f)['result']['status']=='ELB_PATH_CONSTRAINTS_CANDIDATE'
            with urlopen(base+'/api/context',timeout=5) as f:assert json.load(f)==before
        finally:server.shutdown();t.join(timeout=3)
