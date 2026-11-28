import base64,json,re,threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request,urlopen
import pytest
from backend.aws.vpc_endpoint_web import MODES,analyze_endpoint_upload
from backend.aws.vpc_endpoint_evidence import inspect_vpc_endpoint
from backend.aws.interface_endpoint_session_evidence import analyze_interface_endpoint_session
from backend.aws.gateway_endpoint_session_evidence import analyze_gateway_endpoint_session
from scripts.serve_cloudpath import load_web_app,create_server
P=Path('samples/aws/phase7_demo'); HTML=Path('frontend/static/endpoint_viewer.html').read_text()
CONFIG=json.loads(re.search(r'configs=(\{.*?\}),ports=new Set',HTML).group(1))
def raw(n):return (P/n).read_bytes()
def entry(n):return dict(name=n,content_base64=base64.b64encode(raw(n)).decode())
def body(mode='interface_ec2'):
    c=CONFIG[mode];return dict(mode=mode,input_identity='current',files={k:entry(v) for k,v in c['samples'].items()},params=c['params'].copy())
def run(b):return analyze_endpoint_upload(b,'current')['result']
@pytest.mark.parametrize('mode',sorted(MODES))
def test_matches_engine(mode):
    b=body(mode); f={k:raw(v) for k,v in CONFIG[mode]['samples'].items()};p=b['params'];i=p['endpoint_id']
    if '_' not in mode: expected=inspect_vpc_endpoint(f['inventory'],f['endpoints'],i)
    else:
        kind,source=mode.split('_');engine=analyze_interface_endpoint_session if kind=='interface' else analyze_gateway_endpoint_session
        expected=engine(f['inventory'],f['endpoints'],f['observation'],i,source,p['source_port'],**{k:p[k] for k in ('client_ip','task_id','namespace','pod_name') if k in p},**{k+'_raw':f[k] for k in ('ecs','eks','policy','prefix_list') if k in f})
    assert run(b)==expected and expected['live_observation'] is False
@pytest.mark.parametrize('kind',['interface','gateway'])
def test_missing_observation(kind):
    b=body(kind+'_ec2');del b['files']['observation'];r=run(b);assert r['request_status']==r['session_status']=='UNKNOWN' and r['first_request_stop']=='ENDPOINT_SCOPE'
@pytest.mark.parametrize('kind',['interface','gateway'])
def test_blocked(kind):
    b=body(kind+'_eks');b['files']['policy']=entry(kind+'_path_eks_policy_blocked.json');r=run(b);assert r['first_request_stop']=='SOURCE_NETWORK_POLICY_EGRESS' and r['response_status']=='NOT_EVALUATED'
def test_missing_prefix():
    b=body('gateway_ec2');del b['files']['prefix_list'];r=run(b);assert r['reason']=='GATEWAY_SERVICE_PREFIX_LIST_UNCONFIRMED' and r['session_status']=='UNKNOWN'
def test_alternate():
    b=body('gateway_ec2');b['files']={k:entry('gateway_alternate_'+v+'.json') for k,v in [('inventory','inventory'),('endpoints','configuration'),('observation','observation'),('prefix_list','prefix_lists')]};r=run(b);assert r['route_selection']['selected_route']['NatGatewayId']=='nat-12345678' and r['route_selection']['matched_cidr']=='198.51.100.80/32' and r['request_status']=='UNKNOWN' and r['response_status']=='NOT_EVALUATED' and r['first_request_stop']=='GATEWAY_ROUTE'
def test_wrong_config_type():
    b=body('interface');b['params']['endpoint_id']='vpce-22222222'
    with pytest.raises(ValueError):run(b)
@pytest.mark.parametrize('key,value',[('mode',[]),('mode','wrong'),('input_identity','stale'),('files',[]),('params',None),('extra',True)])
def test_outer(key,value):
    with pytest.raises(ValueError):run(body()|{key:value})
@pytest.mark.parametrize('key,value',[('source_port',True),('source_port',0),('source_port',65536),('source_port','50000'),('client_ip','::1'),('client_ip','10.0.1.01'),('endpoint_id',''),('endpoint_id','a'*513),('endpoint_id','x\n'),('extra',True)])
def test_params(key,value):
    b=body();b['params'][key]=value
    with pytest.raises(ValueError):run(b)
@pytest.mark.parametrize('case',['missing','extra','base64','traversal','nonjson','wrongrole'])
def test_files(case):
    b=body()
    if case=='missing':del b['files']['endpoints']
    elif case=='extra':b['files']['ecs']=entry('ecs_task_evidence.json')
    elif case=='base64':b['files']['endpoints']['content_base64']='!'
    elif case=='traversal':b['files']['endpoints']['name']='../endpoints.json'
    elif case=='nonjson':b['files']['endpoints']['name']='endpoints.tf'
    else:b['files']['endpoints']=b['files']['inventory']
    with pytest.raises(ValueError):run(b)
def test_size(monkeypatch):
    monkeypatch.setattr('backend.aws.vpc_endpoint_web.MAX_BYTES',1)
    with pytest.raises(ValueError,match='Total'):run(body())
def test_schema():
    assert set(CONFIG)==set(MODES)
    for mode,(f,o,p) in MODES.items():
        c=CONFIG[mode];assert set(c['files'])==set(f) and set(c['optional'])==set(o) and set(c['params'])==set(p)
    assert 'innerHTML' not in HTML and 'eval(' not in HTML

def test_http():
    a=load_web_app([entry('eks_pod_inventory.json')]);before=a.context();b=body('gateway_ec2')|{'input_identity':a.identity}
    with create_server(a,0) as server:
        t=threading.Thread(target=server.serve_forever,daemon=True);t.start();base=f'http://127.0.0.1:{server.server_port}'
        def post(token,origin=base,data=b):return urlopen(Request(base+'/api/aws-endpoint',data=json.dumps(data).encode(),headers={'Content-Type':'application/json','Origin':origin,'X-CloudPath-Token':token}),timeout=5)
        try:
            with urlopen(base+'/endpoints',timeout=5) as f:assert b'id="diagram"' in f.read()
            assert b'href="/endpoints"' in a.html
            for token,origin in [('bad',base),(a.token,'http://example.org')]:
                with pytest.raises(HTTPError) as e:post(token,origin)
                assert e.value.code==403
            with pytest.raises(HTTPError) as e:post(a.token,data=b|{'input_identity':'stale'})
            assert e.value.code==400
            with post(a.token) as f:assert json.load(f)['result']['path_kind']=='GATEWAY_ENDPOINT'
            with urlopen(base+'/api/context',timeout=5) as f:assert json.load(f)==before
        finally:server.shutdown();t.join(timeout=3)
