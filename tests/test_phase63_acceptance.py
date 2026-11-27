"""Phase 6 integration checks over synthetic data; not live AWS or browser E2E."""
import json
import threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import pytest
from scripts.serve_cloudpath import create_server
from test_aws_external_evidence_web import app, body, enc

DEMO = Path('samples/aws/phase62_demo')

@pytest.mark.parametrize('port, verdict, comparison, observation', [
    (443, 'UNKNOWN', 'CONSISTENT_CANDIDATE', 'ACCEPT_RECORDS'),
    (80, 'BLOCKED', 'NOT_COMPARABLE', 'NO_MATCHING_RECORDS'),
])
def test_static_and_external_evidence_remain_separate(port, verdict, comparison, observation):
    a = app(); b = body(a); b['scenario']['destination_port'] = port
    before = a.analyze_aws(b['scenario']); context = a.context()
    result = a.compare_aws_evidence(b)
    assert result['cloudpath_predicted'] == before['predicted_connectivity'] == verdict
    assert result['reachability']['comparison'] == comparison
    assert result['flow_logs']['observation'] == observation
    assert result['live_observation'] is False
    assert a.context() == context and a.analyze_aws(b['scenario']) == before


def test_http_config_revision_invalidates_external_evidence():
    a = app(); original = a.context(); request = body(a)
    with create_server(a, 0) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        base = f'http://127.0.0.1:{server.server_port}'
        def post(path, data, token):
            req = Request(base + path, json.dumps(data).encode(), {'Content-Type':'application/json', 'Origin':base, 'X-CloudPath-Token':token})
            with urlopen(req, timeout=5) as response: return json.load(response)
        try:
            result = post('/api/aws-evidence', request, original['token'])
            assert result['flow_logs']['matched_records'] == 4
            file = DEMO / 'request_blocked.json'
            changed = post('/api/upload', {'input_identity': original['input_identity'], 'files':[{'name':file.name,'content_base64':enc(file.read_bytes())}]}, original['token'])
            assert changed['input_identity'] != original['input_identity'] and changed['token'] != original['token']
            with pytest.raises(HTTPError) as error: post('/api/aws-evidence', request, original['token'])
            assert error.value.code == 403
            with pytest.raises(HTTPError) as error: post('/api/aws-evidence', request, changed['token'])
            assert error.value.code == 400
            with urlopen(base + '/api/context', timeout=5) as response: assert json.load(response) == changed
            file = DEMO / 'aws_static_tcp_example.json'
            restored = post('/api/upload', {'input_identity':changed['input_identity'],'files':[{'name':file.name,'content_base64':enc(file.read_bytes())}]}, changed['token'])
            assert restored['input_identity'] == original['input_identity']
            assert post('/api/aws-evidence', request, restored['token'])['flow_logs']['matched_records'] == 4
        finally:
            server.shutdown(); thread.join(timeout=3)
