"""Configuration failure UI state; Node stub tests (not browser E2E)."""
import json
from pathlib import Path
import subprocess
import pytest

HTML = Path('frontend/static/topology_viewer.html').read_text()
HANDLER = HTML.split('// UPLOAD_ERROR_STATE_BEGIN',1)[1].split('// UPLOAD_ERROR_STATE_END',1)[0]

@pytest.mark.parametrize('modal_mode',['supported','unsupported','throws'])
def test_failure_screen(modal_mode):
    stub = '''
const nodes=new Map(), tabs=[{}, {}, {}];
const $=id=>{if(!nodes.has(id))nodes.set(id,{dataset:{},hidden:false,value:'old',setAttribute(k,v){this[k]=v},focus(){this.focused=true}});return nodes.get(id)};
const document={body:{dataset:{}},querySelectorAll:()=>tabs};
let stopped=0,cleared=0;
function stop(){stopped++} function clearOverlay(){cleared++}
const dialog=$('upload-error-dialog');dialog.open=false;
'''
    if modal_mode=='supported': stub+='dialog.showModal=function(){this.open=true};\n'
    if modal_mode=='throws': stub+='dialog.showModal=function(){throw Error("not available")};\n'
    code=stub+HANDLER+'''
showUploadFailure([{name:'<b>bad.json</b>'}],'invalid JSON');
const opened=dialog.open;dialog.open=false;
console.log(JSON.stringify({error:document.body.dataset.configError,hidden:[$('graph-view').hidden,$('packet-trace-view').hidden],nav:$('graph-mode').inert,tabs:tabs.every(t=>t.disabled),file:$('upload-files').value,view:$('upload-error-view').hidden,reload:$('upload-reload').hidden,role:$('upload-status').role,state:$('upload-status').dataset.state,text:$('upload-status').textContent,opened,focused:!!$('upload-error-title').focused,stopped,cleared}));
'''
    result=subprocess.run(['node','-e',code],capture_output=True,text=True,check=True)
    r=json.loads(result.stdout)
    assert r==dict(error='true',hidden=[True,True],nav=True,tabs=True,file='',view=False,reload=False,role='alert',state='error',text='교체 실패: <b>bad.json</b> · invalid JSON',opened=modal_mode=='supported',focused=modal_mode!='supported',stopped=1,cleared=1)

def test_failure_and_retry_wiring():
    upload=HTML.split("$('upload-form').addEventListener('submit'",1)[1].split('let inputRevision',1)[0]
    assert upload.count('showUploadFailure(files,')==2
    assert 'location.replace(\'/\')' in upload and 'finally{$(\'upload-run\').disabled=false;}' in upload
    assert '이전 실패 상태 유지' in upload
    assert 'body[data-config-error="true"] #graph-view' in HTML and '#packet-trace-view { display:none !important; }' in HTML
    assert '<dialog id="upload-error-dialog"' in HTML and '<form method="dialog">' in HTML
    assert '저장하지 않은 화면 분석 결과는 사라질 수 있습니다' in HTML
