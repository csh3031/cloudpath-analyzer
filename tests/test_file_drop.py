"""Common drop adapter: native FileList/change contracts (Node, not browser E2E)."""
import json
from pathlib import Path
import subprocess

import pytest

HTML = Path('frontend/static/topology_viewer.html').read_text()
HELPER = HTML.split('// FILE_DROP_BEGIN', 1)[1].split('// FILE_DROP_END', 1)[0]
STUB = r'''
class Node {
  constructor(){this.dataset={};this.events={};this.children=[];this.attributes={};this.textContent='';this.files=[];this.value='old';}
  append(...children){this.children.push(...children);for(const child of children)child.parentNode=this;}
  insertBefore(node,ref){this.children.splice(this.children.indexOf(ref),0,node);node.parentNode=this;}
  setAttribute(k,v){this.attributes[k]=v;}
  getAttribute(k){return this.attributes[k]||null;}
  addEventListener(k,fn){(this.events[k]??=[]).push(fn);}
  dispatchEvent(e){for(const fn of this.events[e.type]||[])fn(e);}
  contains(n){return this.children.includes(n);}
  set value(v){this._value=v;if(v==='')this.files=[];}
  get value(){return this._value;}
}
const el=(tag,text,cls)=>{const e=new Node();e.textContent=text||'';e.className=cls;return e;};
class DataTransfer {
  constructor(){this.files=[];this.items={add:f=>this.files.push(f)};}
}
class Event {constructor(type,opts){this.type=type;this.bubbles=opts?.bubbles;}}
const input=new Node();input.id='test-input';input.files=[{name:'old.json'}];
const parent=new Node();parent.append(input);let blocked=false,changes=0,bubbles=false;
input.addEventListener('change',e=>{changes++;bubbles=e.bubbles;});
function drag(type,files,fileKind=true){const e={type,dataTransfer:{types:[fileKind?'Files':'text/plain'],files:files.map(name=>({name})),items:[]},preventDefault(){this.prevented=true},stopPropagation(){this.stopped=true}};return e;}
'''


def run_case(code):
    completed = subprocess.run(['node', '-e', STUB + HELPER + code], text=True, capture_output=True, check=True)
    return json.loads(completed.stdout)


@pytest.mark.parametrize('multiple,names', [(False,['one.json']), (True,['one.tf','two.tf'])])
def test_drop_replaces_native_selection_and_dispatches_change(multiple,names):
    r=run_case(f'''
input.multiple={json.dumps(multiple)};installFileDrop(input,'hint',()=>blocked);
const zone=parent.children[0];const e=drag('drop',{json.dumps(names)});zone.dispatchEvent(e);
console.log(JSON.stringify({{files:input.files.map(f=>f.name),changes,bubbles,prevented:e.prevented,stopped:e.stopped,hint:input.getAttribute('aria-describedby')}}));
''')
    assert r==dict(files=names,changes=1,bubbles=True,prevented=True,stopped=True,hint='test-input-drop-hint')


def test_single_role_rejects_multiple_clears_and_invalidates():
    r=run_case('''
input.multiple=false;installFileDrop(input,'hint');const zone=parent.children[0];
zone.dispatchEvent(drag('drop',['one.json','two.json']));
console.log(JSON.stringify({files:input.files,changes,error:zone.children[2].textContent}));
''')
    assert r['files']==[] and r['changes']==1 and '한 개' in r['error']


def test_busy_upload_does_not_replace_selection():
    r=run_case('''
input.multiple=true;installFileDrop(input,'hint',()=>blocked);blocked=true;
const zone=parent.children[0],over=drag('dragover',[]);zone.dispatchEvent(over);zone.dispatchEvent(drag('drop',['new.json']));
console.log(JSON.stringify({files:input.files,changes,effect:over.dataTransfer.dropEffect,error:zone.children[2].textContent}));
''')
    assert r['files']==[{'name':'old.json'}] and r['changes']==0 and r['effect']=='none' and '유지' in r['error']


def test_outside_file_drop_blocked_but_text_drag_unaffected():
    r=run_case('''
const file=drag('drop',['file.json']),text=drag('drop',[],false);preventUnassignedFileDrop(file);preventUnassignedFileDrop(text);
console.log(JSON.stringify({file:!!file.prevented,text:!!text.prevented,effect:file.dataTransfer.dropEffect}));
''')
    assert r==dict(file=True,text=False,effect='none')


def test_reset_and_file_chooser_clear_inline_warning():
    r=run_case('''
input.multiple=false;const reset=installFileDrop(input,'hint');const zone=parent.children[0];
zone.dispatchEvent(drag('drop',['one.json','two.json']));const before=zone.children[2].textContent;
reset();const after=zone.children[2].textContent;
zone.dispatchEvent(drag('drop',['one.json','two.json']));input.dispatchEvent(new Event('change',{bubbles:true}));
console.log(JSON.stringify({before,after,chooser:zone.children[2].textContent}));
''')
    assert r['before'] and r['after']==r['chooser']==''


def test_all_five_file_inputs_keep_existing_consumers():
    assert "installFileDrop($('upload-files')" in HTML and "installFileDrop($('trace-file')" in HTML
    assert "resetDropHints.push(installFileDrop(file" in HTML
    assert "['paths','Reachability Path JSON'" in HTML and "['analyses','Reachability Analysis JSON'" in HTML and "['logs','Flow Logs v2 텍스트'" in HTML
    assert "Array.from($('upload-files').files)" in HTML and "for(const f of e.target.files)" in HTML
    assert "Object.entries(inputs).filter(([,f])=>f.files.length)" in HTML
    assert "document.addEventListener('drop',preventUnassignedFileDrop)" in HTML
    assert 'showUploadFailure(files,' in HTML
