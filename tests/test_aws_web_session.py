import base64
import json
import threading
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import pytest
from scripts.serve_cloudpath import load_web_app, AnalysisApp, create_server
from test_aws_policy_evidence import setup
from test_aws_inventory import raw, G
from test_aws_forwarding_evidence import SRC, DST


def files(d):
    return [{'name':'inventory.json','content_base64':base64.b64encode(raw(d)).decode()}]


def app(d=None):
    return load_web_app(files(setup() if d is None else d))


def body(a, **kwargs):
    return dict(source=next(i for i,e in enumerate(a.endpoints) if e['ip']==SRC),
                destination=next(i for i,e in enumerate(a.endpoints) if e['ip']==DST),
                protocol='tcp',source_port=50000,destination_port=443,input_identity=a.identity)|kwargs


def test_aws_web_context():
    a=app(); c=a.context()
    assert c['snapshot']['aws_static_session_available'] is True
    assert c['snapshot']['analysis_restricted'] is True
    assert len(c['endpoints'])==2 and all(e['resource'].startswith('aws_instance.') for e in c['endpoints'])
    assert '_aws_raw' not in c and 'DO_NOT_COPY' not in json.dumps(c)
    assert b'id="aws-static-result"' in a.html
    with pytest.raises(ValueError,match='restricted'):a.analyze(body(a))


def test_aws_static_result():
    a=app();r=a.analyze_aws(body(a))
    assert r['input_identity']==a.identity and r['live_observation'] is False
    assert r['predicted_connectivity']=='UNKNOWN' and r['conditional_connectivity']=='REACHABLE'
    assert all(set(f['web_resource_ids']) <= {x.id for x in a.resources} for f in r['findings'])
    assert 'aws_security_group.'+G in next(f for f in r['findings'] if f['stage']=='SOURCE_SG_EGRESS')['web_resource_ids']
    assert 'DO_NOT_COPY' not in json.dumps(r)


def test_aws_blocked_and_independent():
    d=setup();d['inventory']['SecurityGroups'][0]['IpPermissionsEgress']=[]
    a=app(d);r=a.analyze_aws(body(a))
    assert r['first_blocker']=='request:SOURCE_SG_EGRESS'
    assert r['response']['trace']==[]
    assert all(f['evaluation_mode']=='INDEPENDENT_CHECK' for f in r['findings'][2:])


@pytest.mark.parametrize('kw',[{'source':True},{'destination':-1},{'source_port':0},{'destination_port':True},{'protocol':'udp'},{'input_identity':'stale'},{'assume_tracked_response':True},{'source':999}])
def test_bad_request(kw):
    a=app()
    with pytest.raises(ValueError):a.analyze_aws(body(a,**kw))


def test_missing_or_mismatched_raw():
    a=app()
    with pytest.raises(ValueError):AnalysisApp(a.resources,'wrong',a.snapshot,aws_raw=raw(setup()))
    with pytest.raises(ValueError):AnalysisApp(a.resources,a.identity,a.snapshot).analyze_aws(body(a))


def test_aws_http_and_replacement():
    a=app()
    with create_server(a,0) as server:
        t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
        try:
            base=f'http://127.0.0.1:{server.server_port}'
            def post(path,data,token=a.token,origin=base):
                headers={'Content-Type':'application/json','Origin':origin,'X-CloudPath-Token':token}
                with urlopen(Request(base+path,json.dumps(data).encode(),headers),timeout=5) as r:return json.load(r)
            assert post('/api/aws-analyze',body(a))['conditional_connectivity']=='REACHABLE'
            for path,token,origin,status in [('/api/aws-analyze','bad',base,403),('/api/aws-analyze',a.token,'http://example.org',403),('/api/analyze',a.token,base,400)]:
                with pytest.raises(HTTPError) as e:post(path,body(a),token,origin)
                assert e.value.code==status
            d=setup();d['inventory']['SecurityGroups'][0]['IpPermissionsEgress']=[]
            c=post('/api/upload',{'input_identity':a.identity,'files':files(d)})
            assert c['input_identity']!=a.identity and c['token']!=a.token
            with pytest.raises(HTTPError) as e:post('/api/aws-analyze',body(a))
            assert e.value.code==403
            with pytest.raises(HTTPError) as e:post('/api/aws-analyze',body(a),c['token'])
            assert e.value.code==400
            assert post('/api/aws-analyze',body(a,input_identity=c['input_identity']),c['token'])['predicted_connectivity']=='BLOCKED'
        finally:server.shutdown();t.join(timeout=3)


def test_synthetic_demo():
    from pathlib import Path
    data=Path('samples/aws/phase62_demo/aws_static_tcp_example.json').read_bytes()
    a=load_web_app([{'name':'demo.json','content_base64':base64.b64encode(data).decode()}])
    assert a.analyze_aws(body(a))['conditional_connectivity']=='REACHABLE'
