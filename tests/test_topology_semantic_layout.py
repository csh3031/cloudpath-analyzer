"""Phase 3-3: semantic UI regression tests with no browser dependency.

These tests exercise the exported HTML contract, not packet reachability.
"""

import json
import re
from pathlib import Path

from backend.iac.terraform_parser import parse_terraform
from backend.analyzer.graph_analyzer import analyze_graphs
from backend.output.topology_html import build_resource_display, render_topology_html


def html_for_sample(tmp_path):
    resources = parse_terraform("samples/terraform/main.tf")
    graphs = analyze_graphs(resources)
    exported = render_topology_html(
        graphs,
        tmp_path / "topology.html",
        resource_display=build_resource_display(resources),
    )
    return exported.read_text(encoding="utf-8")


def payload_of(html):
    match = re.search(r'<script type="application/json" id="graph-data">(.*?)</script>', html, re.S)
    assert match
    return json.loads(match.group(1))


def test_semantic_network_and_iac_views_remain_separate(tmp_path):
    html = html_for_sample(tmp_path)
    assert 'data-mode="network_graph"' in html
    assert 'data-mode="reference_graph"' in html
    assert 'IaC 참조 관계' in html
    assert '가상 네트워크 구성도' in html


def test_subnet_role_comes_from_route_rules_not_resource_names(tmp_path):
    html = html_for_sample(tmp_path)
    assert 'function routeEvidenceForSubnet(graph, subnetId, tableId, vpcId, index)' in html
    assert "rule.destination === '0.0.0.0/0'" in html
    assert "rule.target_kind !== 'gateway_id'" in html
    assert "edge.relation === 'attached_to'" in html
    assert "subnet.name === 'public'" not in html
    assert "subnet.name === 'private'" not in html


def test_vpc_and_subnet_policy_layout_are_not_packet_hops(tmp_path):
    html = html_for_sample(tmp_path)
    for segment in (
        'function positionNetwork(graph, collapsed = new Set(), display={})',
        'positionNetwork(graph,collapsedRegions,GRAPHS.resource_display||{})',
        'subnetTable = new Map()',
        "edge.relation === 'uses_route_table'",
        "kind:'egress-region'",
        "kind:'internal-region'",
        "kind:'external-region'",
        'Subnet 경계 참조 · ',
    ):
        assert segment in html
    data = payload_of(html)
    assert all(e['packet_traversable'] is False for e in data['network_graph']['edges'])
    assert all(r['packet_traversable'] is False for r in data['network_graph']['route_rules'])


def test_no_fake_external_internet_resource_in_graph(tmp_path):
    html = html_for_sample(tmp_path)
    data = payload_of(html)
    ids = {node['id'] for node in data['network_graph']['nodes']}
    assert 'internet' not in ids
    assert not any(node['resource_type'] == 'internet' for node in data['network_graph']['nodes'])
    assert '외부 인터넷 (설명용 영역 · 실제 AWS 리소스 아님)' in html


def test_reference_view_shows_dependency_direction_without_packet_claim(tmp_path):
    html = html_for_sample(tmp_path)
    assert 'function positionReference(graph)' in html
    assert "name:'기반 리소스 (VPC)'" in html
    assert "name:'관계 정의 (Association / Route)'" in html
    assert "id:'reference-arrow'" in html
    assert 'Terraform에서 A가 B를 참조하는 A → B 방향' in html


def test_preexisting_zoom_and_selection_behaviors_preserved(tmp_path):
    html = html_for_sample(tmp_path)
    assert 'function fitView()' in html
    assert 'function updateFocus()' in html
    assert 'function setZoom(' in html
    for button in ('zoom-in', 'zoom-out', 'zoom-fit', 'zoom-reset'):
        assert f'id="{button}"' in html


def test_rendered_graph_counts_and_route_policy_are_unchanged(tmp_path):
    html = html_for_sample(tmp_path)
    payload = payload_of(html)
    assert len(payload['network_graph']['nodes']) == 6
    assert len(payload['network_graph']['edges']) == 7
    assert len(payload['reference_graph']['nodes']) == 8
    assert len(payload['reference_graph']['edges']) == 10
    assert payload['network_graph']['route_rules'][0]['target'] == 'aws_internet_gateway.main'


def test_html_script_escaping_preserved(tmp_path):
    resources = parse_terraform("samples/terraform/main.tf")
    graphs = analyze_graphs(resources)
    hostile = '</script><script>alert("bad")</script>'
    result = render_topology_html(graphs, tmp_path / 'safe.html', resource_display={'aws_vpc.main': {'cidr_block': hostile}})
    html = result.read_text(encoding='utf-8')
    assert hostile not in html
    assert payload_of(html)['resource_display']['aws_vpc.main']['cidr_block'] == hostile
