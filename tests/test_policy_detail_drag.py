import base64,json,re,subprocess
from pathlib import Path
from backend.models.infrastructure import InfrastructureResource
from backend.output.policy_display import build_policy_display, UNKNOWN
from scripts.serve_cloudpath import load_web_app

HTML=Path('frontend/static/topology_viewer.html').read_text()

def resource(t,n,attrs):
    return InfrastructureResource('aws_'+t+'.'+n,'aws','security',t,n,attrs)

def test_inline_sg_allowlist_and_unresolved():
    r=resource('security_group','a',{'ingress':[{'protocol':'tcp','from_port':443,'to_port':443,'cidr_blocks':['10.0.0.0/16','${var.secret}'],'description':'SECRET','user_data':'SECRET'}], 'egress':[]})
    p=build_policy_display([r])[r.id]
    f=p['sections']['ingress']['rows'][0]['fields']
    assert f['cidr_blocks']==['10.0.0.0/16',UNKNOWN] and f['from_port']==443
    assert 'SECRET' not in json.dumps(p) and 'var.secret' not in json.dumps(p)
    assert p['sections']['egress']['presence']=='defined'

def test_standalone_sg_rule_and_unresolved_owner():
    r=resource('security_group','a',{})
    q=InfrastructureResource('aws_vpc_security_group_ingress_rule.a','aws','security','aws_vpc_security_group_ingress_rule','a',{'security_group_id':'${aws_security_group.a.id}','ip_protocol':'tcp','cidr_ipv4':'10.0.0.0/24','from_port':443,'to_port':443})
    q2=InfrastructureResource('aws_security_group_rule.b','aws','security','aws_security_group_rule','b',{'security_group_id':'${var.unknown}','type':'ingress'})
    p=build_policy_display([r,q,q2])[r.id]
    assert p['sections']['ingress']['rows'][0]['source']==q.id and p['sections']['egress']['presence']=='unconfirmed'
    assert p['warnings']

def test_acl_order_and_explicit_deny():
    a=resource('network_acl','a',{'ingress':[{'rule_no':32767,'action':'deny'},{'rule_no':100,'action':'allow'}]})
    p=build_policy_display([a])[a.id]['sections']['ingress']['rows']
    assert [x['fields']['rule_no'] for x in p]==[100,32767]
    assert p[1]['fields']['action']=='deny'

def test_route_local_blackhole_and_standalone():
    a=resource('route_table','a',{'route':[{'cidr_block':'10.0.0.0/16','gateway_id':'local','observed_state':'active'},{'cidr_block':'0.0.0.0/0','observed_state':'blackhole','observed_target_ids':['nat-1234abcd']}]})
    r=resource('route','b',{'route_table_id':'${aws_route_table.a.id}','destination_cidr_block':'192.168.1.0/24','gateway_id':'igw-1234abcd'})
    p=build_policy_display([a,r])[a.id]
    assert p['sections']['route']['rows'][1]['fields']['observed_state']=='blackhole'
    assert p['sections']['route']['rows'][2]['fields']['destination_cidr_block']=='192.168.1.0/24' and p['warnings']

def test_aws_sample_policy_details_payload():
    p=Path('samples/aws/phase62_demo/aws_static_tcp_example.json'); a=load_web_app([{'name':p.name,'content_base64':base64.b64encode(p.read_bytes()).decode()}])
    d=json.loads(re.search(rb'<script type="application/json" id="graph-data">(.*?)</script>',a.html,re.S)[1])['resource_display']
    assert d['aws_security_group.sg-12345678']['policy_details']['sections']['ingress']['rows'][0]['fields']['from_port']==443
    assert d['aws_network_acl.acl-12345678']['policy_details']['sections']['ingress']['rows'][1]['fields']['action']=='deny'
    assert d['aws_route_table.rtb-12345678']['policy_details']['sections']['route']['rows'][0]['fields']['gateway_id']=='local'

def test_drag_geometry_stays_inside_same_regions_and_avoids_overlap():
    js=HTML[HTML.index('function boxInside('):HTML.index('function manualGeometry(')];
    code='function overlaps(a,b){return a.x<b.x+b.w&&a.x+a.w>b.x&&a.y<b.y+b.h&&a.y+a.h>b.y;}\n'+js+'''\nconst bounds={x:0,y:0,w:500,h:500}, regions=[{x:0,y:0,w:250,h:250},{x:260,y:0,w:230,h:250}],base={x:20,y:20,w:60,h:60}, obs=[{x:120,y:120,w:60,h:60}];
console.log(JSON.stringify([[40,40],[220,30],[300,30],[125,125],[-5,20]].map(([x,y])=>validManualPlacement(base,{...base,x,y},regions,obs,bounds))));'''
    assert json.loads(subprocess.check_output(['node','-e',code],text=True))==[True,False,False,False,False]

def test_drag_reroutes_without_mutating_graph_and_policy_details_are_text():
    assert 'renderLinks(GRAPHS[mode],currentLayout);updateFocus();renderOverlay();' in HTML
    assert 'manualOffsets[mode].set(element.dataset.id' in HTML
    assert 'applyManualOffsets();\n  renderLinks(graph,layout);' in HTML
    assert 'appendPolicyDetails(details,display.policy_details)' in HTML
    assert 'innerHTML' not in HTML[HTML.index('function appendPolicyDetails'):HTML.index('function selectNode')]
