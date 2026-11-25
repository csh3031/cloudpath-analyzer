"""Phase 3-1: offline graph visualization export tests."""
import json
from pathlib import Path

import pytest

from backend.analyzer.graph_analyzer import analyze_graphs
from backend.iac.terraform_parser import parse_terraform
from backend.output.topology_html import render_topology_html


def sample_graphs():
    resources = parse_terraform("samples/terraform/main.tf")
    return analyze_graphs(resources)


def test_html_generated_with_both_graphs(tmp_path):
    target = render_topology_html(sample_graphs(), tmp_path / "out" / "topology.html")
    html = target.read_text(encoding="utf-8")
    assert target.is_file()
    assert 'id="graph-data"' in html
    assert '"network_graph"' in html
    assert '"reference_graph"' in html
    assert "aws_vpc.main" in html
    assert "aws_subnet.public" in html


def test_html_does_not_claim_forwarding(tmp_path):
    html = render_topology_html(sample_graphs(), tmp_path / "topology.html").read_text(encoding="utf-8")
    assert "패킷 이동 경로가 아닙니다" in html
    assert "packet_traversable" in html
    assert '"packet_path_available":false' in html


def test_html_contains_interactive_controls(tmp_path):
    html = render_topology_html(sample_graphs(), tmp_path / "topology.html").read_text(encoding="utf-8")
    assert 'id="graph-mode"' in html
    assert 'id="details"' in html
    assert 'id="topology"' in html
    assert 'id="graph-data"' in html


def test_untrusted_labels_cannot_break_json_script(tmp_path):
    graph = sample_graphs()
    graph["network_graph"]["nodes"][0]["name"] = '</script><script>alert("x")</script>'
    html = render_topology_html(graph, tmp_path / "topology.html").read_text(encoding="utf-8")
    assert "</script><script>alert" not in html
    assert "\\u003c/script\\u003e" in html


def test_reject_missing_graphs(tmp_path):
    with pytest.raises(ValueError, match="Missing graph"):
        render_topology_html({"network_graph": {"nodes": [], "edges": []}}, tmp_path / "broken.html")


def test_reject_invalid_graph_shapes(tmp_path):
    with pytest.raises(ValueError, match="Invalid nodes/edges"):
        render_topology_html({"network_graph": {"nodes": {}}, "reference_graph": {"nodes": [], "edges": []}}, tmp_path / "broken.html")
