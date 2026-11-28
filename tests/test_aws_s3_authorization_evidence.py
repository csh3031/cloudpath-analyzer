import copy
import json
from pathlib import Path
import pytest
from backend.aws.s3_authorization_evidence import analyze_s3_authorization, _glob

SAMPLES=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
def sample(name='allow'):
    return json.loads((SAMPLES/f's3_authz_{name}.json').read_text())
def run(e): return analyze_s3_authorization(json.dumps(e).encode())
def statement(e,layer='identity'): return e['policies'][layer][0]['Statement'][0]

@pytest.mark.parametrize('name,status,reason',[
 ('allow','ALLOW_CANDIDATE','MATCHING_GRANT_AND_ENDPOINT_ALLOW'),
 ('bucket_deny','EXPLICIT_DENY','MATCHING_EXPLICIT_DENY'),
 ('endpoint_implicit','IMPLICIT_DENY_CANDIDATE','ENDPOINT_NO_MATCHING_ALLOW'),
 ('identity_implicit','IMPLICIT_DENY_CANDIDATE','IDENTITY_AND_BUCKET_NO_MATCHING_ALLOW'),
 ('unknown','UNKNOWN','AUTHORIZATION_EVIDENCE_OR_SCOPE_INCOMPLETE'),
 ('resource_allow','ALLOW_CANDIDATE','MATCHING_GRANT_AND_ENDPOINT_ALLOW'),
 ('missing_context','UNKNOWN','AUTHORIZATION_EVIDENCE_OR_SCOPE_INCOMPLETE'),
])
def test_samples(name,status,reason):
    r=run(sample(name));assert (r['authorization_status'],r['reason'])==(status,reason)
    assert r['network_status']==r['authentication_status']=='NOT_EVALUATED'
    assert r['api_status']=='UNKNOWN' and r['live_observation'] is False

@pytest.mark.parametrize('layer',['identity','bucket','endpoint'])
def test_explicit_deny_overrides(layer):
    e=sample();s=copy.deepcopy(statement(e,layer));s.pop('Condition',None);s['Effect']='Deny';e['policies'][layer][0]['Statement'].append(s)
    r=run(e);assert r['authorization_status']=='EXPLICIT_DENY';assert r['explicit_deny_layers']==[layer]

@pytest.mark.parametrize('layer',['identity','bucket','endpoint'])
def test_incomplete_unknown(layer):
    e=sample();e['complete'][layer]=False;assert run(e)['authorization_status']=='UNKNOWN'

@pytest.mark.parametrize('key',list(sample()['assertions']))
def test_scope_unknown(key):
    e=sample();e['assertions'][key]=False;assert run(e)['authorization_status']=='UNKNOWN'

@pytest.mark.parametrize('key,value',[('NotAction','s3:DeleteObject'),('NotResource','arn:aws:s3:::other/*'),('NotPrincipal','*'),('Condition',{'ForAnyValue:StringEquals':{'aws:SourceVpce':'vpce-22222222'}}),('Condition',{'StringEqualsIfExists':{'aws:SourceVpce':'vpce-22222222'}}),('Condition',{'Null':{'aws:SourceVpce':'false'}}),('Condition',{'StringEquals':{'aws:Unknown':'x'}}),('Resource','arn:aws:s3:::${aws:username}/*'),('Action','${aws:username}')])
def test_unsupported_deny_never_allow(key,value):
    e=sample();s=statement(e,'bucket');s.pop('Condition',None);s[key]=value;assert run(e)['authorization_status']=='UNKNOWN'

@pytest.mark.parametrize('patterns,expected',[(['vpce-22222222','vpce-aaaaaaaa'],'ALLOW_CANDIDATE'),(['vpce-bbbbbbbb','vpce-aaaaaaaa'],'EXPLICIT_DENY')])
def test_negated_condition_nor(patterns,expected):
    e=sample();statement(e,'bucket')['Condition']['StringNotEquals']['aws:SourceVpce']=patterns;assert run(e)['authorization_status']==expected

@pytest.mark.parametrize('pattern,value,expected',[('a?c','abc',True),('a*c','abbbc',True),('a[bc]','ab',False),('a[bc]','a[bc]',True),('a*c','abbd',False),('*','',True),('a**b','axxb',True)])
def test_glob(pattern,value,expected):assert _glob(pattern,value)==expected

def test_case_sensitive_resource_case_insensitive_action():
    e=sample();statement(e)['Action']='S3:GETOBJECT';assert run(e)['authorization_status']=='ALLOW_CANDIDATE'
    statement(e)['Resource']='arn:aws:s3:::cloudpath-demo-bucket/Reports/*';assert run(e)['authorization_status']=='IMPLICIT_DENY_CANDIDATE'

def test_gateway_principal_restriction_unsupported():
    e=sample();statement(e,'endpoint')['Principal']={'AWS':e['request']['principal_arn']};assert run(e)['authorization_status']=='UNKNOWN'
    e['request']['endpoint_type']='Interface';assert run(e)['authorization_status']=='ALLOW_CANDIDATE'

def test_endpoint_missing_not_default():
    e=sample();e['policies']['endpoint']=[];assert run(e)['authorization_status']=='UNKNOWN'

def test_cross_account_unknown():
    e=sample();e['request']['bucket_account']='999999999999';assert run(e)['reason']=='CROSS_ACCOUNT_SCOPE_UNSUPPORTED'

def test_unknown_allow_does_not_override_known_deny():
    e=sample('bucket_deny');e['complete']['identity']=False;assert run(e)['authorization_status']=='EXPLICIT_DENY'

def test_no_raw_policy_export():
    e=sample();statement(e)['Sid']='TEST-SENSITIVE-MARKER';r=run(e);assert 'TEST-SENSITIVE-MARKER' not in json.dumps(r);assert r['layers']['identity']['matching_allows']==[{'document_index':0,'statement_index':0}]

def test_list_bucket():
    e=sample();e['request']['action']='s3:ListBucket';e['request']['resource']='arn:aws:s3:::cloudpath-demo-bucket'
    for k in ('identity','bucket','endpoint'):
        statement(e,k)['Action']='s3:ListBucket';statement(e,k)['Resource']=e['request']['resource']
    assert run(e)['authorization_status']=='ALLOW_CANDIDATE'

@pytest.mark.parametrize('key,val',[('resource','arn:aws:s3:::cloudpath-demo-bucket'),('action','s3:PutObject'),('principal_arn','arn:aws:sts::123456789012:assumed-role/demo/session'),('endpoint_id','invalid'),('secure_transport','true')])
def test_invalid_scope(key,val):
    e=sample();e['request'][key]=val
    with pytest.raises(ValueError):run(e)

def test_duplicate_keys():
    with pytest.raises(ValueError):analyze_s3_authorization(b'{"schema":"a","schema":"b"}')

def test_too_large():
    with pytest.raises(ValueError):analyze_s3_authorization(b' '*1048577)

def test_unknown_document_version():
    e=sample();e['policies']['bucket'][0]['Version']='2008-10-17';assert run(e)['authorization_status']=='UNKNOWN'

def test_account_principal_not_inferred():
    e=sample();statement(e,'bucket')['Principal']={'AWS':'123456789012'};statement(e,'bucket').pop('Condition');assert run(e)['authorization_status']=='UNKNOWN'

def test_arn_condition_components():
    e=sample();statement(e,'endpoint')['Condition']={'ArnLike':{'aws:PrincipalArn':'arn:aws:iam::*:role/demo-*'}};assert run(e)['authorization_status']=='ALLOW_CANDIDATE'
    statement(e,'endpoint')['Condition']={'ArnLike':{'aws:PrincipalArn':'arn:aws:iam:*:role/demo-*'}};assert run(e)['authorization_status']=='UNKNOWN'

def test_bucket_allow_does_not_replace_endpoint_allow():
    e=sample('resource_allow');statement(e,'endpoint')['Action']='s3:ListBucket';assert run(e)['authorization_status']=='IMPLICIT_DENY_CANDIDATE'
