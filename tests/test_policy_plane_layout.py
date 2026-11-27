"""Phase 7-A4 UI correction: scopes remain distinct from visual hierarchy."""
import base64
import json
import re
from pathlib import Path
from test_adaptive_policy_layout import fixture, layout, box_inside
from test_layout_storage import run
from scripts.serve_cloudpath import load_web_app


def test_real_nat_fixture_shared_acl_and_local_routes_near_subnets():
    p=Path('samples/aws/phase7_demo/public_nat_egress_policy_candidate.json')
    app=load_web_app([{'name':p.name,'content_base64':base64.b64encode(p.read_bytes()).decode()}])
    g=json.loads(re.search(rb'<script type="application/json" id="graph-data">(.*?)</script>',app.html,re.S)[1])['network_graph']
    d=layout(g);p=d['positions'];r=d['regions'];gates=d['gates'];subnets=[x for x in r if x['kind']=='subnet-region']
    for slot in gates:
        if slot['kind'] in ('acl','route'):
            area=next(x for x in subnets if x['subnetId']==slot['target']);assert slot['y']+slot['h']<area['y']
        else: assert slot['y']==p[slot['target']]['y'] and slot['x']>p[slot['target']]['x']
    assert len([x for x in gates if x['kind']=='acl'])==2
    assert sum(x['primary'] for x in gates if x['kind']=='acl')==1
    assert d['labels']['aws_network_acl.acl-12345678']=='확인된 공유 적용: Subnet 2개'
    assert set(p)=={n['id'] for n in g['nodes']}


def test_single_and_shared_acl_routes_have_distinct_slots():
    g=fixture();g['nodes'] += [{'id':'acl2','resource_type':'network_acl','name':'acl2'},{'id':'rt2','resource_type':'default_route_table','name':'rt2'}]
    g['edges'] += [dict(source='v',target=k,relation='contains') for k in ('acl2','rt2')]+[dict(source='acl2',target=k,relation='applies_to') for k in ('a','b')]+[dict(source='a',target='rt2',relation='uses_route_table')]
    d=layout(g);slots=d['gates'];assert len([x for x in slots if x['kind']=='acl'])==3
    assert len([x for x in slots if x['kind']=='route'])==3
    assert all(sum(x['primary'] for x in slots if x['id']==k)==1 for k in ('acl','acl2','rt','rt2'))


def test_cross_vpc_and_unknown_scope_not_inferred():
    g=fixture();g['nodes'] += [{'id':k,'resource_type':t,'name':k} for k,t in [('v2','vpc'),('c','subnet'),('acl3','network_acl'),('orphan_policy','route_table')]]
    g['edges'] += [dict(source='v2',target=k,relation='contains') for k in ('c','acl3')]+[dict(source='acl3',target='a',relation='applies_to'),dict(source='sga',target='c',relation='applies_to')]
    d=layout(g);p=d['positions'];panels=[r for r in d['regions'] if r['kind']=='other-region'];assert len(panels)==2
    assert box_inside(p['acl3'],panels[1]) and not box_inside(p['orphan_policy'],panels[1]);assert d['labels']['acl3']=='적용 Subnet 미확인';assert '추가 적용 미확인' in d['labels']['sga']
    assert not any(x['id']=='acl3' or x['target']=='c' for x in d['gates'])


def test_no_empty_policy_plane_and_no_graph_node_loss():
    g=fixture();g['nodes']=[n for n in g['nodes'] if n['resource_type'] in ('vpc','subnet','instance')];ids={n['id'] for n in g['nodes']};g['edges']=[e for e in g['edges'] if e['source'] in ids and e['target'] in ids];d=layout(g)
    assert not any(r['kind'] in ('other-region','boundary-gate-region','sg-gate-region') for r in d['regions']);assert set(d['positions'])==ids


def test_saved_old_network_offsets_migrate_without_losing_reference_or_folds():
    assert run('const old=JSON.parse(raw);delete old.network_revision;const d=decodeSavedLayout(JSON.stringify(old),g);console.log(JSON.stringify([d.networkMigrated,d.offsets.network_graph.size,Object.fromEntries(d.offsets.reference_graph),[...d.collapsed]]));')==[True,0,{'n':{'x':-12,'y':14}},['v','s']]
