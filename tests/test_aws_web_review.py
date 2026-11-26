"""AWS saved result contract and evidence-only graph emphasis (Node, no browser)."""
import copy
import json
from pathlib import Path
import shutil
import subprocess

import pytest
from test_aws_web_session import app, body
from test_aws_policy_evidence import setup


def run_js(data, expression):
    node = shutil.which('node')
    assert node, 'Node.js required for viewer contract regression'
    html = Path('frontend/static/topology_viewer.html').read_text()
    contract = html.split('// AWS_RESULT_CONTRACT_BEGIN',1)[1].split('// AWS_RESULT_CONTRACT_END',1)[0]
    script = contract + '\nconst d=JSON.parse(require("fs").readFileSync(0,"utf8"));\n' + expression
    result = subprocess.run([node,'-e',script], input=json.dumps(data), text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize('blocked',[False,True])
def test_saved_result_replay(blocked):
    d=setup()
    if blocked: d['inventory']['SecurityGroups'][0]['IpPermissionsEgress']=[]
    a=app(d); r=a.analyze_aws(body(a))
    assert run_js(r,'validateAwsResult(d); console.log(JSON.stringify(awsRequestReplay(d).map(f=>f.id)));') == r['request']['trace']


@pytest.mark.parametrize('fault',['live','duplicate','after_stop','verdict','response_mode','port','identity','missing_ids'])
def test_invalid_saved_result(fault):
    d=setup(); d['inventory']['SecurityGroups'][0]['IpPermissionsEgress']=[]
    a=app(d); r=a.analyze_aws(body(a))
    if fault=='live': r['live_observation']=True
    elif fault=='duplicate': r['findings'][1]=r['findings'][0]
    elif fault=='after_stop': r['request']['trace'].append('request:ROUTE_LOOKUP')
    elif fault=='verdict': r['predicted_connectivity']='REACHABLE'
    elif fault=='response_mode': r['findings'][6]['evaluation_mode']='CONDITIONAL_CHECK'
    elif fault=='port': r['scenario']['source_port']=0
    elif fault=='identity': r['input_identity']='fake'
    else: del r['findings'][0]['web_resource_ids']
    assert run_js(r,'try{validateAwsResult(d);console.log(false)}catch(e){console.log(true)}') is True


def test_graph_identity_and_known_ids():
    a=app(); r=a.analyze_aws(body(a)); r['findings'][0]['web_resource_ids'].append('nonexistent')
    assert run_js(r,'''const f=d.findings[0], known=new Set(['nonmatching',f.web_resource_ids[0]]); console.log(JSON.stringify([awsEvidenceIds(d,f,d.input_identity,known),awsEvidenceIds(d,f,'stale',known)]));''') == [[r['findings'][0]['web_resource_ids'][0]],[]]


def test_evidence_ids_include_actual_eni_and_subnet():
    a=app(); r=a.analyze_aws(body(a)); f={f['id']:f for f in r['findings']}
    for key in ('request','response'):
        assert any(x.startswith('aws_network_interface.') for x in f[key+':SOURCE_SG_EGRESS']['web_resource_ids'])
        assert any(x.startswith('aws_subnet.') for x in f[key+':SOURCE_NACL_EGRESS']['web_resource_ids'])
        assert any(x.startswith('aws_subnet.') for x in f[key+':ROUTE_LOOKUP']['web_resource_ids'])
    assert all(set(x['web_resource_ids']) <= {v.id for v in a.resources} for x in r['findings'])
