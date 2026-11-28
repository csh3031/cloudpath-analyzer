import copy
import json
from pathlib import Path
import pytest
from backend.aws.s3_cross_account_evidence import analyze_s3_cross_account
from backend.aws.s3_authorization_evidence import analyze_s3_authorization, MAX_BYTES

D = Path(__file__).resolve().parents[1] / 'samples/aws/phase7_demo'

def sample(mode='allow'):
    return json.loads((D / f's3_cross_account_{mode}.json').read_bytes())

def evaluate(d):
    return analyze_s3_cross_account(json.dumps(d).encode())

@pytest.mark.parametrize('mode,expected', [
    ('allow','POLICY_PATH_ALLOW_CANDIDATE'),
    ('identity_missing_allow','POLICY_PATH_BLOCKED_CANDIDATE'),
    ('bucket_missing_allow','POLICY_PATH_BLOCKED_CANDIDATE'),
    ('endpoint_missing_allow','POLICY_PATH_BLOCKED_CANDIDATE'),
    ('bucket_deny','EXPLICIT_DENY_CANDIDATE'),
    ('incomplete','UNKNOWN'), ('ownership_unknown','UNKNOWN'),
    ('account_delegation','UNKNOWN'), ('same_account','UNKNOWN'), ('endpoint_missing','UNKNOWN')])
def test_fixtures(mode, expected):
    r = evaluate(sample(mode))
    assert r['policy_path_status'] == expected
    assert r['authorization_status'] == r['api_status'] == 'UNKNOWN'
    assert not r['live_observation']

@pytest.mark.parametrize('layer',['identity','bucket','endpoint'])
def test_denial_precedence(layer):
    d=sample(); s=copy.deepcopy(d['policies'][layer][0]['Statement'][0]); s['Effect']='Deny'
    d['policies'][layer][0]['Statement'].append(s); d['complete']['identity']=False
    r=evaluate(d); assert r['policy_path_status']=='EXPLICIT_DENY_CANDIDATE'; assert r['explicit_deny_layers']==[layer]

@pytest.mark.parametrize('layer',['identity','bucket','endpoint'])
def test_completeness(layer):
    d=sample(); d['complete'][layer]=False
    assert evaluate(d)['policy_path_status']=='UNKNOWN'

@pytest.mark.parametrize('flag',['bucket_owner_enforced','no_additional_service_restrictions','object_owned_by_bucket_account'])
def test_scope(flag):
    d=sample(); d['assertions'][flag]=False
    r=evaluate(d); assert r['policy_path_status']=='UNKNOWN'; assert flag in r['unconfirmed_assertions']

@pytest.mark.parametrize('principal',[{'AWS':'arn:aws:iam::123456789012:root'}, {'AWS':'123456789012'}, {'AWS':'arn:aws:sts::123456789012:assumed-role/demo-app/session'}, {'Service':'ecs.amazonaws.com'}])
def test_unsupported_principal(principal):
    d=sample(); d['policies']['bucket'][0]['Statement'][0]['Principal']=principal
    assert evaluate(d)['policy_path_status']=='UNKNOWN'

@pytest.mark.parametrize('layer',['identity','bucket','endpoint'])
def test_unknown_condition(layer):
    d=sample(); d['policies'][layer][0]['Statement'][0]['Condition']={'StringEquals':{'aws:unknown':'x'}}
    assert evaluate(d)['policy_path_status']=='UNKNOWN'

def test_account_context():
    d=sample(); s=d['policies']['bucket'][0]['Statement'][0]; s['Condition']={'StringEquals':{'aws:PrincipalAccount':'222222222222'}}
    assert evaluate(d)['policy_path_status']=='POLICY_PATH_BLOCKED_CANDIDATE'
    s['Condition']['StringEquals']['aws:PrincipalAccount']='123456789012'
    assert evaluate(d)['policy_path_status']=='POLICY_PATH_ALLOW_CANDIDATE'

def test_list_bucket():
    d=sample(); d['request']['action']='s3:ListBucket'; d['request']['resource']='arn:aws:s3:::cloudpath-demo-bucket'; d['assertions']['object_owned_by_bucket_account']=False
    for docs in d['policies'].values():
        for doc in docs:
            for s in doc['Statement']:
                s['Action']=d['request']['action']; s['Resource']=d['request']['resource']
    assert evaluate(d)['policy_path_status']=='POLICY_PATH_ALLOW_CANDIDATE'

def test_interface():
    d=sample(); d['request']['endpoint_type']='Interface'; d['policies']['endpoint'][0]['Statement'][0]['Principal']={'AWS':d['request']['principal_arn']}
    assert evaluate(d)['policy_path_status']=='POLICY_PATH_ALLOW_CANDIDATE'

def test_old_contract_unchanged():
    assert analyze_s3_authorization(json.dumps(sample()).encode())['reason']=='CROSS_ACCOUNT_SCOPE_UNSUPPORTED'

@pytest.mark.parametrize('raw',[b'{}',b'{"schema":1,"schema":2}',b' '* (MAX_BYTES+1),b'not-json'])
def test_bad_input(raw):
    with pytest.raises(ValueError): analyze_s3_cross_account(raw)

@pytest.mark.parametrize('flag',['no_permissions_boundary','no_session_policy','no_scp_rcp','no_kms_requirement'])
def test_never_final_grant(flag):
    d=sample(); d['assertions'][flag]=False
    r=evaluate(d); assert r['policy_path_status']=='POLICY_PATH_ALLOW_CANDIDATE'; assert r['authorization_status']=='UNKNOWN'
