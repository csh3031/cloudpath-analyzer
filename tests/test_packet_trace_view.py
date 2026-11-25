"""Phase 5-1: offline viewer contract (no AWS calls)."""
import json
import re
from backend.output.topology_html import render_topology_html, TEMPLATE


def graphs():
    return {k:{'nodes':[], 'edges':[]} for k in ('network_graph','reference_graph')}


def payload(html):
    return json.loads(re.search(r'<script type="application/json" id="graph-data">(.*?)</script>',html,re.S)[1])


def test_no_trace_backward_compatible(tmp_path):
    html=render_topology_html(graphs(),tmp_path/'a.html').read_text()
    assert payload(html)['packet_traces']==[]
    assert 'id="packet-trace-tab"' in html


def test_trace_payload_preserved(tmp_path):
    entries=[{'name':'a.json','result':{'predicted_connectivity':'BLOCKED','first_blocker_step':'RET02'}}]
    html=render_topology_html(graphs(),tmp_path/'a.html',packet_traces=entries).read_text()
    assert payload(html)['packet_traces']==entries


def test_trace_escape(tmp_path):
    raw='</script><script>alert(1)</script>'
    entries=[{'name':raw,'result':{'reason':raw}}]
    html=render_topology_html(graphs(),tmp_path/'a.html',packet_traces=entries).read_text()
    assert raw not in html and payload(html)['packet_traces']==entries


def test_three_tabs_and_existing_graphs():
    html=TEMPLATE.read_text()
    assert 'data-mode="network_graph"' in html and 'data-mode="reference_graph"' in html
    assert 'id="packet-trace-view" hidden' in html and 'id="graph-view"' in html
    assert "querySelectorAll('.tab[data-mode]')" in html


def test_trace_controls_and_no_remote_dependencies():
    html=TEMPLATE.read_text()
    for id_ in ['trace-file','trace-select','trace-play','trace-next','trace-reset','trace-detail','trace-coverage']:
        assert f'id="{id_}"' in html
    assert not re.search(r'<script\b[^>]*\bsrc\s*=',html,re.I)


def test_trace_preserves_conditionals_and_uses_text():
    html=TEMPLATE.read_text(); js=html.split("/* Phase 5-1:")[1].split("(() =>")[-1]
    assert "next.step.evaluation_mode!=='PREDICTED_PATH'" in js
    assert "next.step.status!=='PASS'" in js
    assert '후속 조건부 차단' in js and '실제 패킷 캡처가 아닙니다' in js
    script=html[html.rfind('<script>'):]
    assert 'innerHTML' not in script and 'textContent' in script
