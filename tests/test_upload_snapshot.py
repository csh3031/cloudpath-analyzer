import base64
import json
import threading
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import pytest
from backend.iac.upload_snapshot import validate_files, inspect_document, load_snapshot, MAX_BYTES
from scripts import serve_cloudpath as web
from test_web_analysis import payload
from test_session_analyzer import fixture


def entry(name='main.tf', raw=b'example'):
    return {'name':name,'content_base64':base64.b64encode(raw).decode('ascii')}


def test_file_bytes_unchanged():
    raw='resource {}\r\n# 한글\n'.encode()
    assert validate_files([entry(raw=raw)]) == [('main.tf',raw)]

@pytest.mark.parametrize('files', [[],[entry('../x.tf')],[entry('x.tfvars')], [entry('x.tf'),entry('X.tf')], [entry('override.tf')], [entry('x_override.tf')], [entry('x.tf',b'\xff')], [{'name':'x.tf','content_base64':'!'}], [entry(str(i)+'.tf') for i in range(51)], [entry(raw=b'x'*(MAX_BYTES+1))]])
def test_invalid_files(files):
    with pytest.raises(ValueError):validate_files(files)

@pytest.mark.parametrize('doc',[{'module':[{}]}, {'data':[{}]}, {'resource':[{'aws_instance':{'a':{'count':2}}}]}, {'resource':[{'aws_instance':{'a':{'subnet_id':'${var.subnet}'}}}]}, {'resource':[{'aws_instance':{'a':{'subnet_id':'${aws_subnet.a[0].id}'}}}]}])
def test_restricted_constructs(doc):
    assert inspect_document(doc)


def test_plain_reference_not_restricted():
    assert not inspect_document({'variable':[{'unused':{}}], 'resource':[{'aws_instance':{'a':{'subnet_id':'${aws_subnet.a.id}'}}}]})


def test_restricted_analysis_server_side():
    app=web.AnalysisApp(fixture(),'id',{'analysis_restricted':True})
    with pytest.raises(ValueError,match='restricted'):app.analyze(payload(app))


def test_upload_http_transaction_and_queries(monkeypatch):
    app=web.AnalysisApp(fixture(),'initial')
    snap={'files':[{'name':'new.tf','bytes':7}],'resource_count':len(fixture()),'warnings':[],'analysis_restricted':False}
    def fake_loader(files):
        if files!=[entry('new.tf')]:raise ValueError('Invalid upload')
        return fixture(),'new',snap
    monkeypatch.setattr(web,'load_snapshot',fake_loader)
    with web.create_server(app,0) as server:
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            base=f'http://127.0.0.1:{server.server_port}'
            def get(path):
                with urlopen(base+path,timeout=5) as r:return r.read()
            def context():return json.loads(get('/api/context?utm_source=chatgpt.com'))
            def post(path, body, token, origin=base):
                headers={'Content-Type':'application/json','Origin':origin,'X-CloudPath-Token':token}
                with urlopen(Request(base+path,json.dumps(body).encode(),headers),timeout=5) as r:return json.load(r)
            assert b'id="upload-form"' in get('/?utm_source=chatgpt.com')
            old=context();body={'input_identity':'initial','files':[entry('new.tf')]}
            for bad,token,origin,code in [(body,'bad',base,403),(body,old['token'],'http://example.com',403),({**body,'files':[entry('bad.tf')]},old['token'],base,400),({**body,'input_identity':'stale'},old['token'],base,400)]:
                with pytest.raises(HTTPError) as e:post('/api/upload',bad,token,origin)
                assert e.value.code==code and context()['input_identity']=='initial'
            new=post('/api/upload?x=1',body,old['token']);assert new['input_identity']=='new' and new['snapshot']==snap and new['token']!=old['token']
            assert context()==new and b'"input_identity":"new"' in get('/')
            with pytest.raises(HTTPError) as e:post('/api/analyze',payload(app),old['token'])
            assert e.value.code==403
            with pytest.raises(HTTPError) as e:post('/api/analyze',payload(app),new['token'])
            assert e.value.code==400
            assert post('/api/analyze?x=1',payload(app,input_identity='new'),new['token'])['predicted_connectivity']=='REACHABLE'
        finally:server.shutdown();thread.join(timeout=3)


def test_hcl_split_snapshot():
    sample=Path('samples/terraform/session_demo.tf').read_bytes()
    # Split at a top-level resource boundary, preserving the input bytes.
    i=sample.index(b'resource "aws_network_acl" "a"')
    r,identity,snapshot=load_snapshot([entry('network.tf',sample[:i]),entry('security.tf',sample[i:])])
    assert snapshot['resource_count']==15 and not snapshot['analysis_restricted']
    app=web.AnalysisApp(r,identity,snapshot)
    assert app.analyze(payload(app))['predicted_connectivity']=='REACHABLE'
    assert load_snapshot([entry('security.tf',sample[i:]),entry('network.tf',sample[:i])])[1]==identity


def test_hcl_invalid_and_duplicate():
    with pytest.raises(ValueError,match='HCL parsing failed'):load_snapshot([entry(raw=b'resource {')])
    raw=b'resource "aws_vpc" "x" { cidr_block = "10.0.0.0/16" }'
    with pytest.raises(ValueError,match='Duplicate Terraform resource IDs'):load_snapshot([entry('a.tf',raw),entry('b.tf',raw)])


def test_hcl_module_partial_graph():
    raw=b'resource "aws_vpc" "x" { cidr_block = "10.0.0.0/16" }\nmodule "remote" { source = "./not-read" }'
    r,identity,snapshot=load_snapshot([entry(raw=raw)])
    assert len(r)==1 and snapshot['analysis_restricted']
    assert web.AnalysisApp(r,identity,snapshot).context()['snapshot']['warnings']
