"""Layout persistence: identity-scoped and presentation-only."""
import json
import subprocess
from pathlib import Path

HTML=Path('frontend/static/topology_viewer.html').read_text()
JS=HTML[HTML.index('const LAYOUT_VERSION='):HTML.index('const layoutKey=')]
PRE='''const identity='sha256-aws-v1:'+ 'a'.repeat(64);
const g={input_identity:identity,network_graph:{nodes:[{id:'v',resource_type:'vpc'},{id:'s',resource_type:'subnet'},{id:'n',resource_type:'instance'}]},reference_graph:{nodes:[{id:'n',resource_type:'instance'}]}};
const offsets={network_graph:new Map([['n',{x:20,y:-15}]]),reference_graph:new Map([['n',{x:-12,y:14}]])};
const raw=encodeSavedLayout(g,offsets,new Set(['v','s']));
function rejects(fn){try{fn();return false;}catch(e){return true;}}
'''

def run(code):
    return json.loads(subprocess.check_output(['node','-e',JS+'\n'+PRE+'\n'+code],text=True,timeout=10))

def test_layout_roundtrip_both_views_and_nested_folds():
    assert run('const d=decodeSavedLayout(raw,g);console.log(JSON.stringify([Object.fromEntries(d.offsets.network_graph),Object.fromEntries(d.offsets.reference_graph),[...d.collapsed]]));')==[{'n':{'x':20,'y':-15}},{'n':{'x':-12,'y':14}},['v','s']]

def test_input_keys_and_missing_identity():
    assert run("console.log(JSON.stringify([layoutStorageKey(identity)!==layoutStorageKey('sha256-plan-v1:'+ 'a'.repeat(64)),layoutStorageKey(null),layoutStorageKey('bad'),rejects(()=>decodeSavedLayout(raw,{...g,input_identity:'sha256-aws-v1:'+'b'.repeat(64)}))]));")==[True,None,None,True]

def test_layout_schema_and_unknown_ids_rejected():
    assert run("console.log(JSON.stringify([d=>d.version=2,d=>d.collapsed.push('n'),d=>d.collapsed.push('v'),d=>d.offsets.network_graph.push(['bad',0,0]),d=>d.offsets.network_graph.push(['n',0,0])].map(change=>{const d=JSON.parse(raw);change(d);return rejects(()=>decodeSavedLayout(JSON.stringify(d),g));})));" )==[True]*5

def test_layout_nonfinite_fractional_and_excessive_coordinates_rejected():
    assert run("console.log(JSON.stringify([null,1.5,1000001,'2'].map(v=>{const d=JSON.parse(raw);d.offsets.network_graph[0][1]=v;return rejects(()=>decodeSavedLayout(JSON.stringify(d),g));})));" )==[True]*4

def test_layout_size_and_bad_json_rejected():
    assert run("console.log(JSON.stringify([rejects(()=>decodeSavedLayout('x'.repeat(LAYOUT_LIMIT+1),g)),rejects(()=>decodeSavedLayout('{bad',g))]));")==[True,True]

def test_storage_wiring_scoped_clear_and_revalidation():
    assert 'localStorage.setItem(layoutKey,encodeSavedLayout' in HTML
    assert 'localStorage.removeItem(layoutKey)' in HTML and 'localStorage.clear()' not in HTML
    assert 'const saved=decodeSavedLayout(raw,GRAPHS)' in HTML
    assert 'if(validManualPlacement(base,next,g.regions,g.obstacles,g.bounds))placeNode(element,next);else layoutRejected++;' in HTML
    assert 'restoreLayout(true);render()' in HTML
