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
    return run_js('const POS_W=218,POS_H=112;\n'+js+'\nconst l=positionNetwork('+json.dumps(graph)+');console.log(JSON.stringify({...l,positions:Object.fromEntries(l.positions)}));')


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


def test_local_policy_nearby_not_contained_shared_and_unknown_unique():
    d=layout(fixture());p=d['positions'];regions=d['regions'];a=next(r for r in regions if r.get('subnetId')=='a');b=next(r for r in regions if r.get('subnetId')=='b')
    local=[r for r in regions if r['kind']=='local-policy-region'];shared=next(r for r in regions if r['kind']=='other-region')
    assert len(local)==2 and box_inside(p['sga'],local[0]) and box_inside(p['acl'],local[0]) and box_inside(p['sgb'],local[1])
    assert all(not box_inside(p[k],a) and not box_inside(p[k],b) for k in ('sga','sgb','acl','rt','unbound'))
    assert box_inside(p['rt'],shared) and box_inside(p['unbound'],shared)


def test_shared_policy_never_local_when_targets_span_subnets():
    g=fixture();g['edges'].append(dict(source='sga',target='j',relation='applies_to'));d=layout(g)
    assert box_inside(d['positions']['sga'],next(r for r in d['regions'] if r['kind']=='other-region'))


def test_route_lane_preference_preserves_valid_route():
    html=TEMPLATE.read_text();router=re.findall(r'<script>(.*?)</script>',html,re.S)[0];helpers=html[html.index('function pathSegments('):html.index('function lineBetween(')]
    js=router+'\nconst CloudPathOrthogonalRouter=module.exports;\n'+helpers+'''\nconst a={x:20,y:30,w:100,h:100},b={x:300,y:30,w:100,h:100},bounds={x:0,y:0,w:500,h:200};const first=routeWithLanes(a,b,[],bounds,[]),reserved=pathSegments(first.points),second=routeWithLanes(a,b,[],bounds,reserved);console.log(JSON.stringify({first,second,old:parallelOverlap(first.points,reserved),new:parallelOverlap(second.points,reserved)}));'''
    d=run_js(js);assert d['first']['status']==d['second']['status']=='routed';assert d['new']<d['old']
