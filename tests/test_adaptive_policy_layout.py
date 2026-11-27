"""Visual layout semantics and lane separation; optional Node.js for JS execution."""
import json
import re
import shutil
import subprocess
import pytest
from backend.output.topology_html import TEMPLATE


def run_js(src):
    node=shutil.which('node')
    if not node: pytest.skip('Optional geometry test requires Node.js')
    return json.loads(subprocess.run([node,'-e',src],check=True,capture_output=True,text=True,timeout=15).stdout)


def layout(graph):
    html=TEMPLATE.read_text()
    js=html[html.index('function routeEvidenceForSubnet('):html.index('function positionReference(')]
    return run_js('const POS_W=218,POS_H=112;\n'+js+'\nconst l=positionNetwork('+json.dumps(graph)+');console.log(JSON.stringify({...l,positions:Object.fromEntries(l.positions),labels:Object.fromEntries(l.labels)}));')


def box_inside(a,b):
    return a['x']>=b['x'] and a['y']>=b['y'] and a['x']+a['w']<=b['x']+b['w'] and a['y']+a['h']<=b['y']+b['h']


def fixture():
    types={'v':'vpc','a':'subnet','b':'subnet','i':'instance','j':'instance','sga':'security_group','sgb':'security_group','acl':'network_acl','rt':'route_table','unbound':'security_group'}
    edges=[]
    def e(a,b,r='contains'): edges.append(dict(source=a,target=b,relation=r))
    for n in ('a','b','sga','sgb','acl','rt','unbound'): e('v',n)
    e('a','i');e('b','j');e('sga','i','applies_to');e('sgb','j','applies_to');e('acl','a','applies_to');e('a','rt','uses_route_table');e('b','rt','uses_route_table')
    return {'nodes':[dict(id=k,resource_type=v,name=k) for k,v in types.items()],'edges':edges,'route_rules':[]}


def test_empty_category_not_rendered_and_actual_subnets_share_row():
    d=layout(fixture());p=d['positions'];kinds=[r['kind'] for r in d['regions']]
    assert 'egress-region' not in kinds and kinds.count('internal-region')==1
    assert p['a']['y']==p['b']['y'] and p['a']['x']!=p['b']['x']
    assert set(p)=={n['id'] for n in fixture()['nodes']}


def test_local_and_shared_policy_boundary_slots_and_unique():
    d=layout(fixture());p=d['positions'];regions=d['regions'];a=next(r for r in regions if r.get('subnetId')=='a');b=next(r for r in regions if r.get('subnetId')=='b')
    panel=next(r for r in regions if r['kind']=='other-region')
    assert box_inside(p['unbound'],panel)
    assert p['acl']['y']<p['a']['y'] and p['rt']['y']<p['a']['y']
    assert p['sga']['y']==p['i']['y'] and p['sgb']['y']==p['j']['y']
    for k in ('sga','sgb','acl','rt','unbound'):
        assert not box_inside(p[k],a) and not box_inside(p[k],b)
    assert '확인된 적용: a'==d['labels']['acl']
    assert '확인된 공유 적용: Subnet 2개'==d['labels']['rt']
    assert '적용 리소스 소재 Subnet 미확인'==d['labels']['unbound']


def test_shared_policy_has_one_primary_and_explicit_alias():
    g=fixture();g['edges'].append(dict(source='sga',target='j',relation='applies_to'));d=layout(g)
    slots=[x for x in d['gates'] if x['id']=='sga'];assert {x['target'] for x in slots}=={'i','j'} and sum(x['primary'] for x in slots)==1
    assert d['labels']['sga']=='적용 리소스 소재: Subnet 2개'


def test_route_lane_preference_preserves_valid_route():
    html=TEMPLATE.read_text();router=re.findall(r'<script>(.*?)</script>',html,re.S)[0];helpers=html[html.index('function pathSegments('):html.index('function lineBetween(')]
    js=router+'\nconst CloudPathOrthogonalRouter=module.exports;\n'+helpers+'''\nconst a={x:20,y:30,w:100,h:100},b={x:300,y:30,w:100,h:100},bounds={x:0,y:0,w:500,h:200};const first=routeWithLanes(a,b,[],bounds,[]),reserved=pathSegments(first.points),second=routeWithLanes(a,b,[],bounds,reserved);console.log(JSON.stringify({first,second,old:parallelOverlap(first.points,reserved),new:parallelOverlap(second.points,reserved)}));'''
    d=run_js(js);assert d['first']['status']==d['second']['status']=='routed';assert d['new']<d['old']
