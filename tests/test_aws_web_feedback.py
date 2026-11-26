"""Regression for input provenance and user-facing AWS evidence (no browser)."""
import json
from pathlib import Path
import pytest
from test_aws_web_session import app, body
from test_aws_web_review import run_js

DEMO = Path('samples/aws/phase62_demo/aws_static_tcp_example.json')

def demo():
    return app(json.loads(DEMO.read_text()))

@pytest.mark.parametrize('port,status,verdict', [(443,'PASS','UNKNOWN'),(80,'BLOCKED','BLOCKED'),(8443,'BLOCKED','BLOCKED')])
def test_destination_port_recalculation(port,status,verdict):
    a=demo(); r=a.analyze_aws(body(a,destination_port=port))
    f=next(f for f in r['findings'] if f['id']=='request:DESTINATION_SG_INGRESS')
    assert (r['scenario']['destination_port'],f['status'],r['predicted_connectivity'])==(port,status,verdict)
    msg=run_js(r,"console.log(JSON.stringify(explainAwsFinding(d,d.findings.find(f=>f.id==='request:DESTINATION_SG_INGRESS'))));")
    assert str(port) in msg['message'] and ('허용 후보' if status=='PASS' else '차단') in msg['message']

@pytest.mark.parametrize('source_port',[49152,50000])
def test_reply_port_explanation(source_port):
    a=demo(); r=a.analyze_aws(body(a,source_port=source_port))
    msg=run_js(r,"console.log(JSON.stringify(explainAwsFinding(d,d.findings.find(f=>f.id==='response:DESTINATION_NACL_INGRESS'))));")
    assert str(source_port) in msg['message'] and '규칙 번호 100' in msg['message']
    assert '조건부 검사' in ' '.join(msg['facts'])


def test_scenario_mismatch_detection():
    a=demo(); b=body(a); r=a.analyze_aws(b)
    assert run_js({'r':r,'b':b,'c':a.context()},'''console.log(JSON.stringify([sameLiveScenario(d.r,d.b,d.c),sameLiveScenario(d.r,{...d.b,destination_port:80},d.c),sameLiveScenario(d.r,{...d.b,source:999},d.c)]));''')==[True,False,False]


def test_unknown_is_not_allow():
    d=json.loads(DEMO.read_text());d['inventory']['NetworkAcls'][0]['Associations']=[]
    a=app(d);r=a.analyze_aws(body(a))
    msg=run_js(r,"console.log(JSON.stringify(explainAwsFinding(d,d.findings.find(f=>f.id==='request:SOURCE_NACL_EGRESS'))));")
    assert '미확정' in msg['message'] and '허용 후보' not in msg['message']


def test_single_graph_button_and_input_labels():
    html=Path('frontend/static/topology_viewer.html').read_text()
    card=html.split('const findingCard=f=>{',1)[1].split('return card;',1)[0]
    assert card.count("el('button'")==1 and "el('button','구조도에서 보기')" in card
    assert card.index('card.append(natural)') < card.index('원본 JSON')
    assert '저장된 분석 결과 JSON 추가 (재분석 없음)' in html
    assert '입력값 변경됨' in html


def test_http_replacement_changes_graph_and_type():
    import threading
    from urllib.request import Request, urlopen
    from scripts.serve_cloudpath import create_server
    from test_plan_adapter import entry, fixture
    a=demo()
    with create_server(a,0) as server:
        t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
        try:
            base=f'http://127.0.0.1:{server.server_port}'
            def graph():
                with urlopen(base+'/',timeout=5) as r:
                    return json.loads(r.read().decode().split('id="graph-data">',1)[1].split('</script>',1)[0])
            old=graph()
            req=Request(base+'/api/upload',json.dumps({'input_identity':a.identity,'files':[entry('different-plan.json',fixture())]}).encode(),{'Content-Type':'application/json','Origin':base,'X-CloudPath-Token':a.token})
            with urlopen(req,timeout=5) as r: c=json.load(r)
            new=graph()
            assert c['snapshot']['input_type']=='TERRAFORM_PLAN_JSON'
            assert new['input_identity']==c['input_identity']!=old['input_identity']
            assert {n['id'] for n in new['network_graph']['nodes']}!={n['id'] for n in old['network_graph']['nodes']}
        finally:server.shutdown();t.join(timeout=3)
