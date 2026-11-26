"""Configuration/result boundaries and repeated HTTP replacement (no browser)."""
import json
import threading
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import pytest
from backend.iac.upload_snapshot import load_snapshot
from scripts.serve_cloudpath import create_server
from test_plan_adapter import entry, fixture
from test_aws_web_review import run_js
from test_aws_web_session import app, body


def legacy(session=False):
    d={'analysis_type':'STATIC_IAC_PREDICTION','scenario':{},'findings':[], 'predicted_connectivity':'UNKNOWN'}
    if session:d['session_trace']={'schema_version':'1.0'}
    return d

@pytest.mark.parametrize('d,kind', [(legacy(), 'LEGACY_RESULT'),(legacy(True),'IAC_SESSION_RESULT'),({'analysis_type':'STATIC_AWS_INVENTORY_PREDICTION'},'AWS_RESULT')])
def test_result_cannot_replace_config(d,kind):
    with pytest.raises(ValueError,match='Saved analysis result JSON'):
        load_snapshot([entry('misleading-plan.json',d)])
    r=run_js(d,'console.log(JSON.stringify([classifyInputJson(d),configJsonError(d),traceJsonError(d)]));')
    assert r[0]==kind and '구조도는 교체되지 않습니다' in r[1]
    assert ('session_trace' in r[2]) == (kind=='LEGACY_RESULT')

@pytest.mark.parametrize('d,kind',[(fixture(),'PLAN_CONFIG'),({'format':'cloudpath-aws-inventory-v1'},'AWS_CONFIG')])
def test_config_cannot_import_as_trace(d,kind):
    r=run_js(d,'console.log(JSON.stringify([classifyInputJson(d),configJsonError(d),traceJsonError(d)]));')
    assert r[0]==kind and not r[1] and '구성 분석 및 교체' in r[2]


def test_aws_plan_rejected_results_aws_sequence():
    demo=json.loads(Path('samples/aws/phase62_demo/aws_static_tcp_example.json').read_text())
    a=app(demo)
    with create_server(a,0) as server:
        t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
        try:
            base=f'http://127.0.0.1:{server.server_port}'
            def get(path):
                with urlopen(base+path,timeout=5) as r:return r.read()
            def context():return json.loads(get('/api/context'))
            def graph():return json.loads(get('/').decode().split('id="graph-data">',1)[1].split('</script>',1)[0])
            def upload(c,name,d):
                req=Request(base+'/api/upload',json.dumps({'input_identity':c['input_identity'],'files':[entry(name,d)]}).encode(),{'Content-Type':'application/json','Origin':base,'X-CloudPath-Token':c['token']})
                with urlopen(req,timeout=5) as r:return json.load(r)
            original=context(); oldgraph=graph()
            p=upload(original,'plan_example.json',fixture()); pg=graph()
            assert p['snapshot']['resource_count']==4 and len(p['endpoints'])==1 and pg['input_identity']==p['input_identity']!=original['input_identity']
            for i,d in enumerate([legacy(),legacy(True),a.analyze_aws(body(a))]):
                with pytest.raises(HTTPError) as e:upload(p,f'result{i}.json',d)
                assert e.value.code==400 and 'Saved analysis result JSON' in json.load(e.value)['error']
                assert context()==p and graph()==pg
            new=upload(p,'aws_again.json',demo); ng=graph()
            assert new['snapshot']['input_type']=='AWS_INVENTORY_JSON' and new['token']!=p['token']
            assert ng['input_identity']==new['input_identity'] and ng['network_graph']==oldgraph['network_graph']
        finally:server.shutdown();t.join(timeout=3)


def test_preflight_and_recovery_wired():
    h=Path('frontend/static/topology_viewer.html').read_text()
    assert h.index('const why=configJsonError(doc)') < h.index("fetch('/api/upload'")
    assert 'const why=traceJsonError(d)' in h and "$('upload-reload').addEventListener('click',()=>{if(confirm(" in h
    assert "finally{$('upload-run').disabled=false;}" in h
