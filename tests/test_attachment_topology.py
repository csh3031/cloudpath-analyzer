"""Presentation-only attachment projection; no AWS API or packet transmission."""
import json
import re
from pathlib import Path
import pytest
from backend.aws.snapshot import load_aws_snapshot, sanitize_inventory, FORMAT_V2
from backend.output.topology_html import build_resource_display, TEMPLATE
from test_adaptive_policy_layout import run_js, box_inside
from test_aws_egress_web import app, body

SAMPLE=Path('samples/aws/phase7_demo/public_nat_egress_policy_candidate.json')
A='aws_instance.i-12345678'; B='aws_instance.i-87654321'
E='aws_network_interface.eni-12345678'; F='aws_network_interface.eni-87654321'
N='aws_nat_gateway.nat-12345678'; M='aws_network_interface.eni-aaaaaaaa'

def payload(a=None):
    a=a or app()
    return json.loads(re.search(rb'<script type="application/json" id="graph-data">(.*?)</script>',a.html,re.S)[1])

def layout(g,d,fold=()):
    html=TEMPLATE.read_text();js=html[html.index('function routeEvidenceForSubnet('):html.index('function positionReference(')]
    return run_js('const POS_W=218,POS_H=112;\n'+js+'\nconst l=positionNetwork('+json.dumps(g)+',new Set('+json.dumps(fold)+'),'+json.dumps(d)+');console.log(JSON.stringify({...l,positions:Object.fromEntries(l.positions),aliases:Object.fromEntries(l.aliases),hiddenBy:Object.fromEntries(l.hiddenBy),labels:Object.fromEntries(l.labels)}));')

def test_sample_primary_and_managed_projection():
    p=payload();g=p['network_graph'];d=layout(g,p['resource_display']);assert d['aliases']=={E:A,F:B,M:N}
    assert set(d['positions'])=={n['id'] for n in g['nodes']}-{E,F,M}
    assert {n['id'] for n in p['reference_graph']['nodes']}>={E,F,M}
    assert 'NAT 경유' in d['labels'][A] and 'IGW' in d['labels'][B]

@pytest.mark.parametrize('change',[{'device_index':1},{'device_index':None},{'requester_managed':True},{'observed_interface_type':'efa'}])
def test_extra_or_uncertain_eni_stays_separate(change):
    p=payload();p['resource_display'][E].update(change);d=layout(p['network_graph'],p['resource_display']);assert E in d['positions'] and E not in d['aliases']

@pytest.mark.parametrize('change',[{'associated':False},{'private_ip':'10.0.2.99'}])
def test_unconfirmed_nat_eni_stays_separate(change):
    p=payload();p['resource_display'][N]['nat_addresses'][0].update(change);d=layout(p['network_graph'],p['resource_display']);assert M in d['positions'] and M not in d['aliases']

def test_eip_reference_and_no_sg_duplicate():
    p=payload();d=layout(p['network_graph'],p['resource_display']);refs=d['addressRefs'];assert len(refs)==1 and refs[0]['owner']==N and refs[0]['allocation_id']=='eipalloc-aaaaaaaa'
    assert not any(ref['allocation_id'] in x for x in d['positions'] for ref in refs)
    assert {g['target'] for g in d['gates'] if g['kind']=='sg'}=={E,F}
    boxes=[*d['positions'].values(),*[g for g in d['gates'] if not g['primary']],*refs]
    assert all(not(a['x']<b['x']+b['w'] and a['x']+a['w']>b['x'] and a['y']<b['y']+b['h'] and a['y']+a['h']>b['y']) for i,a in enumerate(boxes) for b in boxes[i+1:])

def test_public_ip_type_unknown_without_allocation_id():
    d=json.loads(SAMPLE.read_text());eni=d['inventory']['NetworkInterfaces'][0];eni['Association']={'PublicIp':'11.0.0.12'}
    resources,*_=load_aws_snapshot(json.dumps(d).encode());display=build_resource_display(resources)
    assert display[E]['public_addresses']==[{'private_ip':'10.0.1.10','public_ip':'11.0.0.12','kind':'PUBLIC_IP_TYPE_UNKNOWN'}]
    eni['Association']['AllocationId']='eipalloc-bbbbbbbb';resources,*_=load_aws_snapshot(json.dumps(d).encode());display=build_resource_display(resources)
    assert display[E]['public_addresses'][0]['kind']=='EIP_ASSOCIATION' and display[E]['public_addresses'][0]['allocation_id']=='eipalloc-bbbbbbbb'

def test_fold_preserves_hidden_eni_and_no_eip_ref():
    p=payload();d=layout(p['network_graph'],p['resource_display'],['aws_subnet.subnet-87654321']);assert d['hiddenBy'][M]=='aws_subnet.subnet-87654321' and not d['addressRefs']

def test_egress_verdict_preserved_and_explicit_route_overlay():
    a=app();d=a.analyze_aws_egress(body(a));assert d['session_status']=='UNKNOWN' and d['route']['translation']['kind']=='PUBLIC_NAT_THEN_IGW'
    html=TEMPLATE.read_text();assert 'renderEgressConfigPath(awsFocus.data)' in html and '현재 구성과 경로 근거 불일치' in html and '외부 신규 연결 경로 아님' in html
