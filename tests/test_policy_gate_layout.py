"""Boundary presentation is a projection, never a graph resource or packet order."""
from pathlib import Path
from test_adaptive_policy_layout import fixture, layout, box_inside
from test_layout_storage import run


def test_gate_refs_deduplicated_and_not_sg_on_nat_or_subnet():
    g=fixture();g['nodes'].append(dict(id='nat',resource_type='nat_gateway',name='nat'))
    g['edges'] += [dict(source='a',target='nat',relation='contains'),dict(source='sga',target='nat',relation='applies_to'),dict(source='sga',target='a',relation='applies_to'),dict(source='sga',target='i',relation='applies_to')]
    d=layout(g);slots=[x for x in d['gates'] if x['id']=='sga'];assert len(slots)==1 and slots[0]['target']=='i'
    assert set(d['positions'])=={n['id'] for n in g['nodes']}


def test_gate_slots_nonoverlapping_inside_vpc_not_workload():
    g=fixture();d=layout(g);v=next(r for r in d['regions'] if r['kind']=='vpc-region');subs=[r for r in d['regions'] if r['kind']=='subnet-region'];slots=d['gates'];boxes=[*d['positions'].values(),*[x for x in slots if not x['primary']]]
    assert all(box_inside(x,v) and not any(box_inside(x,r) for r in subs) for x in slots)
    assert all(not(a['x']<b['x']+b['w'] and a['x']+a['w']>b['x'] and a['y']<b['y']+b['h'] and a['y']+a['h']>b['y']) for i,a in enumerate(boxes) for b in boxes[i+1:])


def test_previous_policy_plane_offsets_migrate():
    assert run('const old=JSON.parse(raw);old.network_revision=2;const d=decodeSavedLayout(JSON.stringify(old),g);console.log(JSON.stringify([d.networkMigrated,d.offsets.network_graph.size,Object.fromEntries(d.offsets.reference_graph),[...d.collapsed]]));')==[True,0,{'n':{'x':-12,'y':14}},['v','s']]


def test_gate_references_share_details_and_scope_trace_highlight():
    html=Path('frontend/static/topology_viewer.html').read_text()
    assert '동일 VPC 정책 · 별도 리소스 아님' in html
    assert "e.addEventListener('click',()=>selectNode(g.id,true))" in html
    assert 'here=ids.has(id)&&ids.has(target)' in html
    assert 'return ids.has(id)&&ids.has(target)' in html
    assert 'layout.gateKeys?.has(gateKey)' in html
