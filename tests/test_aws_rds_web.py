import base64,json,re,threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request,urlopen
import pytest
from backend.aws.rds_web import MODES,analyze_rds_upload
from backend.aws.rds_evidence import inspect_rds_configuration
from backend.aws.rds_session_evidence import analyze_rds_session
from backend.aws.rds_failover_evidence import compare_rds_snapshots
from scripts.serve_cloudpath import load_web_app,create_server
P=Path('samples/aws/phase7_demo'); HTML=Path('frontend/static/rds_viewer.html').read_text()
CONFIG=json.loads(re.search(r'configs=(\{.*?\}),ports=new Set',HTML).group(1))
def raw(n):return (P/n).read_bytes()
def entry(n):return dict(name=n,content_base64=base64.b64encode(raw(n)).decode())
def body(mode='session_ec2'):
    c=CONFIG[mode];return dict(mode=mode,input_identity='current',files={k:entry(v) for k,v in c['samples'].items()},params=c['params'].copy())
def run(b):return analyze_rds_upload(b,'current')['result']
@pytest.mark.parametrize('mode',sorted(MODES))
def test_matches_engine(mode):
    b=body(mode); f={k:raw(v) for k,v in CONFIG[mode]['samples'].items()};p=b['params'];i=p['identifier']
    if mode in ('instance','cluster'): expected=inspect_rds_configuration(f['inventory'],f['rds'],mode,i)
    elif mode.startswith('compare_'):expected=compare_rds_snapshots(*(tuple(f[w+'_'+k] for k in ('inventory','rds','observation')) for w in ('before','after')),i,p['client_ip'],p['source_port'],cluster=mode=='compare_cluster')
    else: expected=analyze_rds_session(f['inventory'],f['rds'],f['observation'],i,mode[8:],p['source_port'],**{k:p[k] for k in ('client_ip','task_id','namespace','pod_name') if k in p},**{k+'_raw':f[k] for k in ('ecs','eks','policy') if k in f})
    assert run(b)==expected and expected['live_observation'] is False
@pytest.mark.parametrize('role',['WRITER','READER'])
def test_cluster_endpoint(role):
    b=body();b['params'].update(identifier='demo-aurora',endpoint_kind=role);b['files'].update(inventory=entry('rds_transition_before_inventory.json'),rds=entry('rds_transition_before_configuration.json'),observation=entry('rds_transition_before_'+role.lower()+'.json'))
    r=run(b);assert r['member_selection']['role']==role and r['request_status']=='CONDITIONAL_CANDIDATE'
def test_missing_observation():
    b=body();del b['files']['observation'];r=run(b);assert r['reason']=='RDS_DNS_ENI_EVIDENCE_MISSING' and r['session_status']=='UNKNOWN'
def test_blocked():
    b=body('session_eks');b['files']['policy']=entry('rds_path_eks_policy_blocked.json');r=run(b);assert r['first_request_stop']=='SOURCE_NETWORK_POLICY_EGRESS' and r['response_status']=='NOT_EVALUATED'
@pytest.mark.parametrize('key,value',[('mode',[]),('mode','wrong'),('input_identity','stale'),('files',[]),('params',None),('extra',True)])
def test_outer(key,value):
    with pytest.raises(ValueError):run(body()|{key:value})
@pytest.mark.parametrize('key,value',[('source_port',True),('source_port',0),('source_port',65536),('source_port','50000'),('client_ip','::1'),('client_ip','10.0.1.01'),('identifier',''),('identifier','a'*513),('identifier','x\n'),('endpoint_kind','CUSTOM'),('extra',True)])
def test_params(key,value):
    b=body();b['params'][key]=value
    with pytest.raises(ValueError):run(b)
@pytest.mark.parametrize('case',['missing','extra','base64','traversal','nonjson','wrongrole'])
def test_files(case):
    b=body()
    if case=='missing':del b['files']['rds']
    elif case=='extra':b['files']['ecs']=entry('ecs_task_evidence.json')
    elif case=='base64':b['files']['rds']['content_base64']='!'
    elif case=='traversal':b['files']['rds']['name']='../rds.json'
    elif case=='nonjson':b['files']['rds']['name']='rds.tf'
    else:b['files']['rds']=b['files']['inventory']
    with pytest.raises(ValueError):run(b)
def test_size(monkeypatch):
    monkeypatch.setattr('backend.aws.rds_web.MAX_BYTES',1)
    with pytest.raises(ValueError,match='Total'):run(body())
def test_schema():
    assert set(CONFIG)==set(MODES)
    for mode,(f,o,p) in MODES.items():
        c=CONFIG[mode];assert set(c['files'])==set(f) and set(c['optional'])==set(o) and set(c['params'])==set(p)
    assert 'innerHTML' not in HTML and 'eval(' not in HTML

def test_http():
    a=load_web_app([entry('eks_pod_inventory.json')]);before=a.context();b=body('compare_cluster')|{'input_identity':a.identity}
    with create_server(a,0) as server:
        t=threading.Thread(target=server.serve_forever,daemon=True);t.start();base=f'http://127.0.0.1:{server.server_port}'
        def post(token,origin=base,data=b):return urlopen(Request(base+'/api/aws-rds',data=json.dumps(data).encode(),headers={'Content-Type':'application/json','Origin':origin,'X-CloudPath-Token':token}),timeout=5)
        try:
            with urlopen(base+'/rds',timeout=5) as f:assert b'id="diagram"' in f.read()
            assert b'href="/rds"' in a.html
            for token,origin in [('bad',base),(a.token,'http://example.org')]:
                with pytest.raises(HTTPError) as e:post(token,origin)
                assert e.value.code==403
            with pytest.raises(HTTPError) as e:post(a.token,data=b|{'input_identity':'stale'})
            assert e.value.code==400
            with post(a.token) as f:assert json.load(f)['result']['after']['request_status']=='BLOCKED'
            with urlopen(base+'/api/context',timeout=5) as f:assert json.load(f)==before
        finally:server.shutdown();t.join(timeout=3)
