"""Phase 5-2 input identity and standalone viewer contract."""
import json
import re
from backend.iac.input_identity import input_identity
from backend.output.topology_html import render_topology_html, TEMPLATE


def test_identity_same_content_different_name(tmp_path):
    a=tmp_path/'a.tf';b=tmp_path/'b.tf';a.write_text('a');b.write_text('a')
    assert input_identity([a])==input_identity([b])


def test_identity_changes_with_policy(tmp_path):
    a=tmp_path/'a.tf';a.write_text('allow');before=input_identity([a]);a.write_text('deny')
    assert input_identity([a])!=before


def test_identity_multifile_order_and_membership(tmp_path):
    a=tmp_path/'a.tf';b=tmp_path/'b.tf';a.write_text('a');b.write_text('b')
    assert input_identity([a,b])==input_identity([b,a])
    assert input_identity([a,b])!=input_identity([a])
    assert input_identity([a,a])!=input_identity([a])


def test_identity_embedded(tmp_path):
    a=tmp_path/'a.tf';a.write_text('a');identity=input_identity([a]);g={k:{'nodes':[],'edges':[]} for k in ('network_graph','reference_graph')}
    html=render_topology_html(g,tmp_path/'a.html',input_identity=identity).read_text()
    payload=json.loads(re.search(r'id="graph-data">(.*?)</script>',html,re.S)[1])
    assert payload['input_identity']==identity
    assert json.loads(re.search(r'id="graph-data">(.*?)</script>',render_topology_html(g,tmp_path/'b.html').read_text(),re.S)[1])['input_identity'] is None


def test_overlay_contract():
    h=TEMPLATE.read_text()
    assert 'id="overlay-direction"' in h and 'id="overlay-clear"' in h
    assert 'd.input_identity!==GRAPHS.input_identity' in h
    assert "class:'trace-candidate'" in h and 'trace-first' in h and 'trace-conditional' in h
    assert 'CloudPathOrthogonalRouter.routeOrthogonal' in h
