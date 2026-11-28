import base64
import json
import re
import threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
from backend.aws.workload_web import MODES, analyze_workload_upload
from scripts.serve_cloudpath import load_web_app, create_server

P = Path('samples/aws/phase7_demo')
HTML = Path('frontend/static/workload_viewer.html').read_text()
CONFIG = json.loads(re.search(r'configs=(\{.*?\}),ports=new Set', HTML).group(1))


def entry(name):
    return {'name':name,'content_base64':base64.b64encode((P/name).read_bytes()).decode()}


def body(mode='eks_session'):
    c=CONFIG[mode]
    return dict(mode=mode, input_identity='current', files={k:entry(v) for k,v in c['samples'].items()}, params=c['params'].copy())


@pytest.mark.parametrize('mode', sorted(MODES))
def test_matches_engine(mode):
    b=body(mode)
    engine, files, params, kwfiles, kwparams, optional=MODES[mode]
    raw=lambda k:base64.b64decode(b['files'][k]['content_base64'])
    expected=engine(*(raw(k) for k in files),*(b['params'][k] for k in params),**{k+'_raw':raw(k) for k in kwfiles},**{k:b['params'][k] for k in kwparams})
    p=analyze_workload_upload(b,'current')
    assert p==dict(mode=mode,result=expected)
    assert expected['status']!='UNKNOWN' and expected['live_observation'] is False


@pytest.mark.parametrize('port,status,stop',[(443,'CONDITIONAL_CANDIDATE',None),(8080,'BLOCKED','SOURCE_NETWORK_POLICY_EGRESS'),(8443,'BLOCKED','DESTINATION_SG_INGRESS')])
def test_pod_path(port,status,stop):
    b=body();b['params']['destination_port']=port
    r=analyze_workload_upload(b,'current')['result']
    assert (r['request_status'],r['first_request_stop'])==(status,stop)


@pytest.mark.parametrize('port,status',[(443,'CNI_EVIDENCE_CONSISTENT_CANDIDATE'),(8080,'UNKNOWN'),(8443,'CNI_EVIDENCE_DISCREPANCY_CANDIDATE')])
def test_cni(port,status):
    b=body('eks_cni');b['params']['destination_port']=port
    r=analyze_workload_upload(b,'current')['result']
    assert r['status']==status and r['enforcement_status']==r['session_status']=='UNKNOWN'


@pytest.mark.parametrize('kind,backend,health',[('alb','CONDITIONAL_CANDIDATE','BLOCKED'),('nlb','BLOCKED','CONDITIONAL_CANDIDATE')])
def test_elb_legs(kind,backend,health):
    r=analyze_workload_upload(body('ecs_path_'+kind),'current')['result']
    assert r['targets'][0]['backend_status']==backend and r['targets'][0]['health_check_status']==health


def test_preserve():
    b=body('ecs_path_nlb');b['files']['attributes']=entry('ecs_elb_path_nlb_preserve.json')
    t=analyze_workload_upload(b,'current')['result']['targets'][0]
    assert t['backend'] is None and t['backend_status']=='UNKNOWN'


def test_mixed_service():
    b=body('eks_service_session');b['files'].update(service=entry('eks_service_session_mixed_services.json'),translation=entry('eks_service_session_mixed_translation.json'));b['params'].update(service_name='demo-web',service_port=80)
    r=analyze_workload_upload(b,'current')['result']
    assert len(r['branches'])==2 and r['backend_summary']=='UNRESOLVED_BACKEND_PRESENT'


@pytest.mark.parametrize('mode,expected',[('ecs_prefix_list_evidence','CONDITIONAL_CANDIDATE'),('ecs_prefix_list_miss_evidence','BLOCKED'),(None,'UNKNOWN')])
def test_prefix(mode,expected):
    b=body('ecs_session');b['files']['inventory']=entry('ecs_prefix_list_inventory.json')
    if mode:b['files']['prefix_list']=entry(mode+'.json')
    assert analyze_workload_upload(b,'current')['result']['request_status']==expected


@pytest.mark.parametrize('field,value',[('mode','bad'),('mode',[]),('input_identity','stale'),('files',[]),('params',None),('extra',True)])
def test_invalid_outer(field,value):
    with pytest.raises(ValueError):analyze_workload_upload(body()|{field:value},'current')


@pytest.mark.parametrize('key,value',[('source_port',True),('destination_port',0),('destination_port',65536),('source_port','50000'),('source_namespace',''),('source_pod','x\n'),('source_pod','a'*513),('unknown',True)])
def test_invalid_parameter(key,value):
    b=body();b['params'][key]=value
    with pytest.raises(ValueError):analyze_workload_upload(b,'current')


@pytest.mark.parametrize('case',['missing','extra','bad64','badname','wrongrole','nonjson'])
def test_invalid_files(case):
    b=body()
    if case=='missing':del b['files']['policy']
    elif case=='extra':b['files']['observation']=entry('eks_cni_observation.json')
    elif case=='bad64':b['files']['policy']['content_base64']='!'
    elif case=='badname':b['files']['policy']['name']='../policy.json'
    elif case=='wrongrole':b['files']['policy']=b['files']['eks']
    else:b['files']['policy']['name']='policy.tf'
    with pytest.raises(ValueError):analyze_workload_upload(b,'current')


def test_total(monkeypatch):
    monkeypatch.setattr('backend.aws.workload_web.MAX_BYTES',1)
    with pytest.raises(ValueError,match='Total'):analyze_workload_upload(body(),'current')


def test_schema_contract():
    assert set(CONFIG)==set(MODES)
    for mode,(_,f,p,kf,kp,o) in MODES.items():
        c=CONFIG[mode]
        assert set(c['files'])==set(f+kf) and set(c['optional'])==set(o) and set(c['params'])==set(p+kp)
    assert 'innerHTML' not in HTML and 'eval(' not in HTML


def test_http():
    a=load_web_app([entry('eks_pod_inventory.json')]); before=a.context(); b=body()|{'input_identity':a.identity}
    with create_server(a,0) as server:
        t=threading.Thread(target=server.serve_forever,daemon=True);t.start();base=f'http://127.0.0.1:{server.server_port}'
        def post(token,origin=base, data=b):return urlopen(Request(base+'/api/aws-workload',data=json.dumps(data).encode(),headers={'Content-Type':'application/json','Origin':origin,'X-CloudPath-Token':token}),timeout=5)
        try:
            with urlopen(base+'/workloads',timeout=5) as f:assert b'id="diagram"' in f.read()
            assert b'href="/workloads"' in a.html
            for token,origin in [('bad',base),(a.token,'http://example.org')]:
                with pytest.raises(HTTPError) as e:post(token,origin)
                assert e.value.code==403
            with pytest.raises(HTTPError) as e:post(a.token,data=b|{'input_identity':'stale'})
            assert e.value.code==400
            with post(a.token) as f:assert json.load(f)['result']['request_status']=='CONDITIONAL_CANDIDATE'
            with urlopen(base+'/api/context',timeout=5) as f:assert json.load(f)==before
        finally:server.shutdown();t.join(timeout=3)
