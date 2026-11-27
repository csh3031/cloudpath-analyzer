"""Phase 3-2 regression checks for view navigation and safe CIDR labels."""

import json
import re
from pathlib import Path

from backend.iac.terraform_parser import parse_terraform
from backend.analyzer.graph_analyzer import analyze_graphs
from backend.output.topology_html import build_resource_display, render_topology_html


def _graphs_and_resources():
    resources = parse_terraform("samples/terraform/main.tf")
    return analyze_graphs(resources), resources


def _payload(html):
    match = re.search(r'<script type="application/json" id="graph-data">(.*?)</script>', html, re.S)
    assert match, "graph-data JSON script missing"
    return json.loads(match.group(1))


def test_display_metadata_includes_defined_cidr():
    _, resources = _graphs_and_resources()
    display = build_resource_display(resources)
    assert display["aws_vpc.main"]["cidr_block"] == "10.0.0.0/16"
    assert display["aws_subnet.public"]["cidr_block"] == "10.0.1.0/24"


def test_display_metadata_allowlist_does_not_publish_secrets():
    _, resources = _graphs_and_resources()
    resources[0].attributes["secret_token"] = "DO_NOT_EXPORT"
    resources[0].attributes["password"] = "DO_NOT_EXPORT"
    display = build_resource_display(resources)
    assert "DO_NOT_EXPORT" not in json.dumps(display)
    assert set(display[resources[0].id]) <= {"cidr_block", "availability_zone"}


def test_exporter_includes_optional_metadata_and_both_graphs(tmp_path):
    graphs, resources = _graphs_and_resources()
    output = render_topology_html(graphs, tmp_path / "viewer.html",resource_display=build_resource_display(resources))
    payload = _payload(output.read_text(encoding="utf-8"))
    assert payload["resource_display"]["aws_vpc.main"]["cidr_block"] == "10.0.0.0/16"
    assert payload["network_graph"]["metadata"]["packet_path_available"] is False
    assert payload["reference_graph"]["nodes"]


def test_phase31_exporter_signature_unchanged(tmp_path):
    graphs, _ = _graphs_and_resources()
    output = render_topology_html(graphs, tmp_path / "viewer.html")
    assert _payload(output.read_text(encoding="utf-8"))["resource_display"] == {}


def test_user_controlled_metadata_script_escape(tmp_path):
    graphs, _ = _graphs_and_resources()
    attack = '</script><script>alert("injection")</script>'
    output = render_topology_html(graphs,tmp_path / "viewer.html", resource_display={"aws_vpc.main":{"cidr_block":attack}})
    html = output.read_text(encoding="utf-8")
    assert attack not in html
    assert _payload(html)["resource_display"]["aws_vpc.main"]["cidr_block"] == attack


def test_html_has_zoom_pan_fit_and_accessible_labels(tmp_path):
    graphs, _ = _graphs_and_resources()
    html = render_topology_html(graphs,tmp_path / "viewer.html").read_text(encoding="utf-8")
    for part in ('id="canvas-viewport"','id="canvas-stage"','id="zoom-in"',
                 'id="zoom-out"','id="zoom-fit"','id="zoom-reset"',
                 'id="zoom-label"','aria-label="확대"','aria-label="축소"'):
        assert part in html
    assert 'function fitView()' in html
    assert 'function setZoom(' in html


def test_node_highlighting_and_reference_mode_stay_separate(tmp_path):
    graphs,_ = _graphs_and_resources()
    html = render_topology_html(graphs,tmp_path / "viewer.html").read_text(encoding="utf-8")
    assert "function updateFocus()" in html
    assert "function positionReference(graph)" in html
    assert "function positionNetwork(graph, collapsed = new Set(), display={})" in html
    assert "positionNetwork(graph,collapsedRegions,GRAPHS.resource_display||{})" in html
    assert "packet_traversable" in html
    assert "실제 패킷 이동 경로가 아닙니다" in html


def test_unresolved_cidr_is_not_mislabeled_resolved(tmp_path):
    graphs,_ = _graphs_and_resources()
    html = render_topology_html(
        graphs,tmp_path / "viewer.html",resource_display={"aws_vpc.main":{"cidr_block":"${var.vpc_cidr}"}}
    ).read_text(encoding="utf-8")
    assert '${var.vpc_cidr}' in _payload(html)["resource_display"]["aws_vpc.main"]["cidr_block"]
    assert "CIDR: 미해결" in html

