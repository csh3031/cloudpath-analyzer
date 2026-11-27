import json
import re
from pathlib import Path

from backend.models.infrastructure import InfrastructureResource
from backend.output.topology_html import build_resource_display, render_topology_html, TEMPLATE
from backend.aws.snapshot import load_aws_snapshot
from scripts.serve_cloudpath import AnalysisApp


def test_hover_display_ip_and_sensitive_fields():
    r = InfrastructureResource('aws_instance.a', 'aws', 'compute', 'instance', 'a', {
        'private_ip': '10.0.1.10', 'private_ips': ['10.0.1.10', '10.0.1.11', '10.0.1.11', '${var.secret}'],
        'observed_state': 'running', 'user_data': 'DO_NOT_EXPORT', 'password': 'DO_NOT_EXPORT',
    })
    assert build_resource_display([r])[r.id] == {'private_ip': '10.0.1.10', 'private_ips': ['10.0.1.10', '10.0.1.11'], 'observed_state': 'running'}


def test_hover_policy_counts_only():
    r = InfrastructureResource('aws_security_group.a', 'aws', 'security', 'security_group', 'a', {
        'ingress': [{'description': 'DO_NOT_EXPORT', 'from_port': 443}], 'egress': [], 'observed_state': 'DO_NOT_EXPORT',
    })
    d=build_resource_display([r])[r.id]
    assert d['ingress_inline_count']==1 and d['egress_inline_count']==0
    assert 'DO_NOT_EXPORT' not in json.dumps(d)
    assert d['policy_details']['sections']['ingress']['rows'][0]['fields']=={'from_port':443}


def test_aws_hover_metadata_in_rendered_page():
    raw = Path('samples/aws/phase61_demo/aws_inventory_example.json').read_bytes()
    app = AnalysisApp(*load_aws_snapshot(raw))
    payload = json.loads(re.search(rb'<script type="application/json" id="graph-data">(.*?)</script>', app.html, re.S)[1])
    d = payload['resource_display']['aws_instance.i-12345678']
    assert d['private_ip'] == '10.0.1.10' and d['observed_state'] == 'running'
    assert b'id="resource-hover-toggle" checked' in app.html


def test_hover_toggle_preserves_diagnostics_and_safe_dom():
    html = TEMPLATE.read_text()
    assert 'if(!steps.length&&!resourceHoverToggle.checked)return;' in html
    assert 'if(resourceHoverToggle.checked)' in html
    assert "resourceHoverToggle.addEventListener('change',hideTraceTooltip)" in html
    assert 'position:fixed' in html and "element.addEventListener('pointerenter',()=>showTraceTooltip(element,node.id))" in html
    assert 'innerHTML' not in html[html.index('function appendResourceTooltip'):html.index('function overlayCompatibility')]
