"""Phase 3-4: offline viewer integration contract; geometry is tested separately in JS."""
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from backend.output.topology_html import TEMPLATE, render_topology_html


def test_router_embedded_in_self_contained_viewer(tmp_path):
    empty = {"nodes": [], "edges": []}
    result = render_topology_html({"network_graph": empty, "reference_graph": empty}, tmp_path / "view.html")
    html = result.read_text(encoding="utf-8")
    assert "root.CloudPathOrthogonalRouter = api" in html
    assert "CloudPathOrthogonalRouter.routeOrthogonal" in html
    assert not re.search(r'<script\b[^>]*\bsrc\s*=', html, re.I)
    assert 'id="routing-status"' in html


def test_edges_render_after_actual_node_geometry():
    html = TEMPLATE.read_text(encoding="utf-8")
    assert html.index("nodeLayer.append(element);") < html.index("renderLinks(graph,layout);", html.index("function render()"))
    assert "el.offsetHeight" in html
    assert "el.offsetWidth" in html
    assert "geometry.labels" in html
    assert "clearance:12" in html


def test_group_obstacles_are_distinct_from_endpoint_groups():
    html = TEMPLATE.read_text(encoding="utf-8")
    assert "geometry.regions.filter(box=>!overlaps(from,box)&&!overlaps(to,box))" in html
    assert "edge.relation==='contains'" in html
    assert "marker-end':'url(#reference-arrow)" in html


def test_unrouted_edges_do_not_fall_back_to_curves():
    html = TEMPLATE.read_text(encoding="utf-8")
    assert "if (result.status!=='routed') return fail(result.reason);" in html
    assert "미표시 연결 및 사유" in html
    assert "표시 실패는 통신 차단 판정이 아닙니다." in html
    assert "const pathDef =" not in html


def test_embedded_router_geometry_with_node_if_available(tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js optional; browser runs embedded JavaScript without Node.js")
    html = TEMPLATE.read_text(encoding="utf-8")
    scripts = re.findall(r'<script>(.*?)</script>', html, re.S)
    router = tmp_path / "orthogonal_router.js"
    router.write_text(scripts[0], encoding="utf-8")
    tests = Path(__file__).with_name("topology_router_cases.cjs")
    case_file = tmp_path / tests.name
    case_file.write_text(tests.read_text(encoding="utf-8"), encoding="utf-8")
    completed = subprocess.run([node, "--test", str(case_file)], capture_output=True, text=True, timeout=60)
    assert completed.returncode == 0, completed.stdout + completed.stderr
