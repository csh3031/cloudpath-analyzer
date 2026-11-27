"""Presentation-only service slot and default egress references."""
import copy
from test_attachment_topology import payload, layout, A, B, N, M
from test_adaptive_policy_layout import box_inside
from test_layout_storage import run
from backend.output.topology_html import TEMPLATE

SUB='aws_subnet.subnet-87654321'
IGW='aws_internet_gateway.igw-12345678'

def test_nat_small_slot_inside_actual_subnet_above_workloads():
    p=payload();d=layout(p['network_graph'],p['resource_display']);pos=d['positions'];slot=next(r for r in d['regions'] if r['kind']=='edge-service-slot');sub=next(r for r in d['regions'] if r.get('subnetId')==SUB)
    assert box_inside(pos[N],slot) and box_inside(slot,sub) and pos[N]['y']<pos[B]['y']
    assert pos[N]['w']<pos[B]['w'] and pos[N]['h']<pos[B]['h']
    assert d['edgeServices']==[{'id':N,'subnetId':SUB,'kind':'nat_gateway'}] and d['aliases'][M]==N

def test_default_refs_are_same_vpc_config_not_graph_edges():
    p=payload();g=p['network_graph'];before=copy.deepcopy(g);d=layout(g,p['resource_display']);assert {(r['source'],r['target']) for r in d['defaultEgressRefs']}=={(A,N),(N,IGW)};assert g==before

def test_missing_blackhole_or_ambiguous_default_not_projected():
    p=payload();g=p['network_graph'];r=next(r for r in g['route_rules'] if r['target']==N);r['observed_state']='blackhole';assert not any(x['source']==A for x in layout(g,p['resource_display'])['defaultEgressRefs']);r['observed_state']='active';g['route_rules'].append(copy.deepcopy(r));assert not any(x['source']==A for x in layout(g,p['resource_display'])['defaultEgressRefs'])

def test_fold_hides_service_and_reference():
    p=payload();d=layout(p['network_graph'],p['resource_display'],[SUB]);assert not d['edgeServices'] and not d['defaultEgressRefs'] and N in d['hiddenBy'] and M in d['hiddenBy']

def test_prior_layout_migration_preserves_reference_and_folds():
    assert run('const old=JSON.parse(raw);old.network_revision=4;const d=decodeSavedLayout(JSON.stringify(old),g);console.log(JSON.stringify([d.networkMigrated,d.offsets.network_graph.size,d.offsets.reference_graph.size,[...d.collapsed]]));')==[True,0,1,['v','s']]

def test_direction_and_labels_wired_without_reverse_route_assumption():
    html=TEMPLATE.read_text();assert 'hops.filter((_,i)=>d.route.hops[i].stage!==\'ROUTE_LOOKUP\').reverse()' in html and "response&&d.request_status==='BLOCKED'" in html
    assert 'egress-path-summary' in html and "response?'8 5':'none'" in html and "t.kind==='PUBLIC_NAT_THEN_IGW'?'→ NAT 사설 '" in html
    assert 'default-egress-toggle' in html and '외부 신규 연결 경로 아님' in html


def test_default_egress_reference_is_opt_in():
    from html.parser import HTMLParser
    class ToggleParser(HTMLParser):
        def handle_starttag(self, tag, attrs):
            if tag == 'input' and dict(attrs).get('id') == 'default-egress-toggle':
                self.toggles.append(dict(attrs))
    parser=ToggleParser();parser.toggles=[];parser.feed(TEMPLATE.read_text())
    assert len(parser.toggles)==1 and 'checked' not in parser.toggles[0]
    assert parser.toggles[0]['type']=='checkbox'
