"""AWS local session display follows only the active static check trace."""
import copy
import json
from test_aws_egress_web import app as nat_app, DEMO
from test_aws_web_session import app, body
from test_attachment_topology import payload, E, F, N
from test_aws_web_review import run_js
from backend.output.topology_html import TEMPLATE


def result(data=None):
    a=nat_app() if data is None else app(data)
    return a.analyze_aws(body(a)),payload(a)['network_graph']


def plan(d,g,key='request',identity=None):
    return run_js(dict(r=d,g=g,key=key,identity=identity or d['input_identity']), 'console.log(JSON.stringify(planAwsLocalPath(d.r,d.g,d.identity,d.key)));')


def test_local_request_selects_source_route_and_destination():
    d,g=result();p=plan(d,g);assert p['complete'] and len(p['anchors'])==7
    assert p['anchors'][0]['id']==E and p['anchors'][-1]['id']==F
    assert p['anchors'][3]['id']=='aws_route_table.rtb-87654321'
    assert all('nat_gateway' not in a['id'] and 'internet_gateway' not in a['id'] for a in p['anchors'])


def test_response_uses_its_own_route_and_policy_attachment():
    d,g=result();p=plan(d,g,'response');assert p['complete'] and p['anchors'][0]['id']==F and p['anchors'][-1]['id']==E
    assert p['anchors'][3]['id']=='aws_route_table.rtb-12345678'
    assert p['anchors'][1]['target']==F and p['anchors'][-2]['target']==E


def test_source_sg_block_stops_and_disables_response():
    raw=json.loads((DEMO/'public_nat_egress_policy_candidate.json').read_text());raw['inventory']['SecurityGroups'][0]['IpPermissionsEgress']=[]
    d,g=result(raw);p=plan(d,g);assert not p['complete'] and p['stop']=='SOURCE_SG_EGRESS' and len(p['anchors'])==2
    assert not plan(d,g,'response')['anchors']


def test_destination_sg_block_does_not_reach_ec2():
    raw=json.loads((DEMO/'public_nat_egress_policy_candidate.json').read_text());raw['inventory']['SecurityGroups'][0]['IpPermissions']=[]
    d,g=result(raw);p=plan(d,g);assert p['stop']=='DESTINATION_SG_INGRESS' and not p['complete']
    assert p['anchors'][-1]['target']==F and p['anchors'][-1]['status']=='BLOCKED' and not any(a['id']==F for a in p['anchors'])


def test_missing_local_route_evidence_fails_closed():
    d,g=result();g['route_rules']=[r for r in g['route_rules'] if r['target']!='local'];p=plan(d,g);assert not p['complete'] and p['stop']=='ROUTE_LOOKUP'


def test_missing_attachment_fails_closed():
    d,g=result();g['edges']=[e for e in g['edges'] if not(e['relation']=='attached_to' and e['source']==E)];assert not plan(d,g)['anchors']


def test_identity_and_independent_checks_never_create_paths():
    d,g=result();assert not plan(d,g,identity='stale')['anchors'];d['request']['trace'].pop();assert not plan(d,g)['anchors']


def test_scope_ui_separates_default_refs_and_selects_current_result():
    s=TEMPLATE.read_text();assert 'internalActive&&e.layer' in s and '!internalActive&&document.getElementById' in s
    assert '전체 내부 요청 경로 보기' in s and '전체 조건부 응답 경로 보기' in s and 'if(!liveResult)clearOverlay()' in s
