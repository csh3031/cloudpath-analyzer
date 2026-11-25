"""Policy application and route declaration are not packet hops."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from backend.analyzer.network_graph_analyzer import analyze_network_graph
from backend.aws.snapshot import load_aws_snapshot
from backend.models.infrastructure import InfrastructureResource
from backend.output.topology_html import TEMPLATE
from scripts.serve_cloudpath import AnalysisApp


def r(id, **attrs):
    return InfrastructureResource(id,'aws','network',id.split('.')[0][4:],id.split('.')[1],attrs)


def ref(id): return '${'+id+'.id}'


def resources():
    v=ref('aws_vpc.v');s=ref('aws_subnet.a');t=ref('aws_route_table.r');g=ref('aws_security_group.g')
    return [r('aws_vpc.v',cidr_block='10.0.0.0/16'),r('aws_subnet.a',vpc_id=v,cidr_block='10.0.1.0/24'),
        r('aws_subnet.b',vpc_id=v,cidr_block='10.0.2.0/24'),r('aws_instance.a',subnet_id=s,vpc_security_group_ids=[g]),
        r('aws_network_interface.a',subnet_id=s,security_groups=[g],instance_id=ref('aws_instance.a')),
        r('aws_security_group.g',vpc_id=v),r('aws_network_acl.a',vpc_id=v,subnet_ids=[s]),
        r('aws_internet_gateway.i',vpc_id=v),r('aws_route_table.r',vpc_id=v,route=[{'cidr_block':'10.0.0.0/16','gateway_id':'local'},{'cidr_block':'0.0.0.0/0','gateway_id':ref('aws_internet_gateway.i')}]),
        r('aws_main_route_table_association.m',vpc_id=v,route_table_id=t)]


def edges(g,kind): return [e for e in g['edges'] if e['relation']==kind]


def test_acl_inline_and_no_guessed_default():
    g=analyze_network_graph(resources());a=[e for e in edges(g,'applies_to') if e['source']=='aws_network_acl.a']
    assert [(e['target'],e['policy_scope']) for e in a]==[('aws_subnet.a','subnet_boundary')]
    assert all(not e['packet_traversable'] for e in g['edges'])


def test_acl_standalone_and_managed_default():
    rs=resources();del rs[6].attributes['subnet_ids'];rs += [r('aws_network_acl_association.a',subnet_id=ref('aws_subnet.a'),network_acl_id=ref('aws_network_acl.a')),r('aws_default_network_acl.d',default_network_acl_id='${aws_vpc.v.default_network_acl_id}')]
    g=analyze_network_graph(rs);a=[(e['source'],e['target']) for e in edges(g,'applies_to') if e.get('policy_scope')=='subnet_boundary']
    assert set(a)=={('aws_network_acl.a','aws_subnet.a'),('aws_default_network_acl.d','aws_subnet.b')}
    assert any(n['id']=='aws_default_network_acl.d' and n['resource_type']=='network_acl' for n in g['nodes'])


def test_conflicting_acl_not_asserted():
    rs=resources();rs.append(r('aws_network_acl.b',vpc_id=ref('aws_vpc.v'),subnet_ids=[ref('aws_subnet.a')]))
    g=analyze_network_graph(rs);assert not any(e.get('policy_scope')=='subnet_boundary' for e in g['edges']);assert any(i['code']=='UNRESOLVED_NACL_ASSOCIATION' for i in g['issues'])


def test_aws_association_not_duplicated_and_conflict_not_reinserted():
    raw=Path('samples/aws/phase61_demo/aws_inventory_example.json').read_bytes();rs,ident,snapshot=load_aws_snapshot(raw)
    def graph(rs):
        html=AnalysisApp(rs,ident,snapshot).html
        return json.loads(re.search(rb'<script type="application/json" id="graph-data">(.*?)</script>',html,re.S)[1])['network_graph']
    g=graph(rs);assert sum(e.get('policy_scope')=='subnet_boundary' for e in g['edges'])==1
    acl=next(x for x in rs if x.resource_type=='network_acl');rs.append(r('aws_network_acl.acl-87654321',**acl.attributes));assert not any(e['relation']=='applies_to' and e['source'].startswith('aws_network_acl.') for e in graph(rs)['edges'])


def test_toggles_default_off_and_trace_independent():
    html=TEMPLATE.read_text();assert re.findall(r'data-policy-layer="([a-z]+)"',html)==['sg','acl','association','next','other']
    assert not re.search(r'<input[^>]+data-policy-layer[^>]+checked',html)
    assert 'boundary||nodes.get(e.target)' in html
    assert "querySelectorAll('.trace-candidate')" in html
    assert 'policy-next-arrow' in html


def test_policy_line_selection_and_target_grouping():
    node=shutil.which('node')
    if not node:pytest.skip('Optional JS test requires Node.js')
    g=analyze_network_graph(resources());g['route_rules'] += [dict(g['route_rules'][0],destination='192.0.2.0/24',target='aws_internet_gateway.i',status='RESOLVED'),dict(g['route_rules'][0],target='aws_internet_gateway.i',status='RESOLVED',observed_state='blackhole'),dict(g['route_rules'][0],target='missing',status='UNKNOWN')]
    html=TEMPLATE.read_text();src='const GRAPHS={network_graph:'+json.dumps(g)+'};\n'+html[html.index('function relationshipLayer('):html.index('function renderLinks(')]+'\nconsole.log(JSON.stringify(policyLines(GRAPHS.network_graph)));'
    lines=json.loads(subprocess.run([node,'-e',src],check=True,capture_output=True,text=True,timeout=10).stdout)
    assert len([x for x in lines if x['layer']=='sg'])==1 and next(x for x in lines if x['layer']=='sg')['target']=='aws_network_interface.a'
    assert len([x for x in lines if x['layer']=='association'])==2
    assert len([x for x in lines if x['layer']=='acl'])==1
    nexts=[x for x in lines if x['layer']=='next'];assert len(nexts)==1 and nexts[0]['directed'] and '192.0.2.0/24' in nexts[0]['label'] and 'blackhole' not in nexts[0]['label']
    assert all(x['target'] not in ('local','missing') for x in lines)
    assert not any(x.get('relation') == 'contains' for x in lines)
    assert any(x.get('relation') == 'contains' for x in g['edges'])


def test_hcl_policy_resource_types(tmp_path):
    from backend.iac.terraform_parser import parse_terraform
    p=tmp_path/'main.tf';p.write_text('resource "aws_network_interface" "a" { subnet_id = aws_subnet.a.id }\nresource "aws_default_network_acl" "a" { default_network_acl_id = aws_vpc.a.default_network_acl_id }\n')
    assert [r.resource_type for r in parse_terraform(p)]==['network_interface','default_network_acl']
