"""Presentation-only fold behavior, exercised against actual JS geometry."""
import json
import subprocess
from pathlib import Path
import pytest
from test_subnet_layout import graph

HTML=Path('frontend/static/topology_viewer.html').read_text()
JS=HTML[HTML.index('function routeEvidenceForSubnet('):HTML.index('function positionReference(')]

def run(code, folded=()):
    src='const POS_W=218,POS_H=112;\n'+JS+'\nconst g='+json.dumps(graph())+';const saved=JSON.stringify(g);const l=positionNetwork(g,new Set('+json.dumps(list(folded))+'));\n'+code
    return json.loads(subprocess.run(['node','-e',src],check=True,capture_output=True,text=True,timeout=10).stdout)

def layout(folded=()):
    return run('console.log(JSON.stringify({p:Object.fromEntries(l.positions),hidden:Object.fromEntries(l.hiddenBy),regions:l.regions,unchanged:saved===JSON.stringify(g),height:l.height}));',folded)

def test_subnet_fold_preserves_policy_and_ambiguous_nodes():
    x=layout(['a']);assert x['hidden']=={k:'a' for k in ('i','i2','i3','eni','nat')}
    assert all(k in x['p'] for k in ('a','sg','acl','rt','conflict','missing','b','j'))
    assert not any(k in x['p'] for k in x['hidden']);assert x['unchanged']

def test_vpc_fold_preserves_external_and_orphan():
    x=layout(['v','a']);assert set(x['hidden'])=={'a','b','empty','i','i2','i3','eni','nat','j','sg','acl','rt'}
    assert set(x['hidden'].values())=={'v'};assert set(x['p'])=={'v','orphan','oi','conflict','missing'}
    assert x['height']<layout()['height'] and x['unchanged']

def test_orphan_subnet_and_restore():
    x=layout(['orphan']);assert x['hidden']=={'oi':'orphan'}
    y=layout();assert not y['hidden'];assert len(y['p'])==len(graph()['nodes'])

def test_nested_fold_restores_prior_subnet_selection():
    x=run('const set=new Set(["v","a"]);const a=positionNetwork(g,set);set.delete("v");const b=positionNetwork(g,set);set.delete("a");const c=positionNetwork(g,set);console.log(JSON.stringify([a.hiddenBy.get("i"),b.hiddenBy.get("i"),c.positions.has("i"),saved===JSON.stringify(g)]));')
    assert x==['v','a',True,True]

def test_hidden_check_summary_does_not_promote_conditional():
    x=run('console.log(JSON.stringify(collapsedEvidenceSummary(l.hiddenBy,"a",[{ids:["i","eni"],status:"BLOCKED",mode:"PREDICTED_PATH"},{ids:["i2"],status:"BLOCKED",mode:"INDEPENDENT_CHECK"},{ids:["nat"],status:"UNKNOWN",mode:"PREDICTED_PATH"},{ids:["j"],status:"BLOCKED",mode:"PREDICTED_PATH"}])));',['a'])
    assert x==dict(hidden=5,blocked=1,conditional=1,unknown=1)

def test_fold_wiring_and_hidden_links():
    assert 'positionNetwork(graph,collapsedRegions,GRAPHS.resource_display||{})' in HTML
    assert 'toggled.filter(e=>!hiddenBy.has(e.source)&&!hiddenBy.has(e.target))' in HTML
    assert '접기로 숨김' in HTML and '분석 결과 미선택' in HTML
    assert 'collapsedRegions.clear();render();' in HTML and 'aria-expanded' in HTML
    assert "layout.hiddenBy?.has(selectedId)" in HTML
