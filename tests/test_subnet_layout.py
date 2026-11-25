"""Subnet layout regression. JS geometry checks run when Node.js is present."""
import json
import shutil
import subprocess

import pytest
from backend.output.topology_html import TEMPLATE


def test_subnet_layout_has_container_and_existing_tabs():
    html = TEMPLATE.read_text()
    assert '.subnet-region {' in html
    assert "kind:'subnet-region',subnetId:subnet.id" in html
    assert 'element.dataset.subnetId=region.subnetId' in html
    assert 'function positionReference(graph)' in html
    assert '소속 Subnet' in html


def graph():
    types = {'v':'vpc','a':'subnet','b':'subnet','empty':'subnet','orphan':'subnet',
             'i':'instance','i2':'instance','i3':'instance','eni':'network_interface','nat':'nat_gateway',
             'j':'instance','oi':'instance','missing':'instance','conflict':'instance','sg':'security_group',
             'acl':'network_acl','rt':'route_table'}
    edges = []
    def e(s,t,r='contains'): edges.append(dict(source=s,target=t,relation=r))
    for t in ('a','b','empty','sg','acl','rt'): e('v',t)
    for t in ('i','i2','i3','eni','nat'): e('a',t)
    e('b','j'); e('orphan','oi');e('a','conflict');e('b','conflict')
    e('eni','i','attached_to');e('sg','i','applies_to');e('acl','a','applies_to')
    e('a','rt','uses_route_table');e('b','rt','uses_route_table')
    return {'nodes':[dict(id=k,resource_type=v,name=k) for k,v in types.items()], 'edges':edges,'route_rules':[]}


@pytest.fixture(scope='module')
def layout():
    node = shutil.which('node')
    if not node: pytest.skip('Optional JS geometry test requires Node.js; no runtime dependency')
    html = TEMPLATE.read_text()
    script = html[html.index('function routeEvidenceForSubnet('):html.index('function positionReference(')]
    src = 'const POS_W=218,POS_H=112;\n'+script+'\nconst l=positionNetwork('+json.dumps(graph())+');console.log(JSON.stringify({...l,positions:Object.fromEntries(l.positions)}));'
    return json.loads(subprocess.run([node,'-e',src],check=True,capture_output=True,text=True,timeout=10).stdout)


def inside(box, area):
    return (box['x']>=area['x'] and box['y']>=area['y'] and box['x']+box['w']<=area['x']+area['w'] and box['y']+box['h']<=area['y']+area['h'])


def overlap(a,b):
    return a['x']<b['x']+b['w'] and a['x']+a['w']>b['x'] and a['y']<b['y']+b['h'] and a['y']+a['h']>b['y']


def test_confirmed_children_contained_even_with_attachment(layout):
    areas={r['subnetId']:r for r in layout['regions'] if 'subnetId' in r}
    p=layout['positions']
    for subnet,children in {'a':['i','i2','i3','eni','nat'],'b':['j'],'empty':[],'orphan':['oi']}.items():
        assert inside(p[subnet],areas[subnet])
        assert all(inside(p[n],areas[subnet]) for n in children)
    assert areas['a']['h']>areas['b']['h']>areas['empty']['h']


def test_shared_policies_and_unknown_membership_not_nested(layout):
    areas=[r for r in layout['regions'] if 'subnetId' in r]
    p=layout['positions']
    for id in ('rt','sg','acl','missing','conflict'):
        assert not any(overlap(p[id],a) for a in areas)
    assert set(p)=={n['id'] for n in graph()['nodes']}
    assert len([r for r in layout['regions'] if r['kind']=='other-region'])==1


def test_no_overlap_and_parent_boundaries(layout):
    p=list(layout['positions'].values());r=layout['regions'];a=[x for x in r if 'subnetId' in x]
    assert not any(overlap(x,y) for i,x in enumerate(p) for y in p[i+1:])
    assert not any(overlap(x,y) for i,x in enumerate(a) for y in a[i+1:])
    vpc=next(x for x in r if x['kind']=='vpc-region'); unknown=next(x for x in r if x['kind']=='unresolved-region')
    for box in a: assert inside(box,unknown if box['subnetId']=='orphan' else vpc)
    assert not overlap(vpc,unknown)
    assert all(inside(x,dict(x=0,y=0,w=layout['width'],h=layout['height'])) for x in p+r)
