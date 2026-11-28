import copy,json,hashlib
from pathlib import Path
import pytest
from backend.aws.s3_kms_evidence import analyze_s3_kms
D=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
A=(D/'s3_kms_authorization.json').read_bytes()
E=json.loads((D/'s3_kms_allow.json').read_bytes())
def run(a=None,e=None):
    raw=A if a is None else json.dumps(a).encode()
    x=copy.deepcopy(E if e is None else e)
    if a is not None: x['authorization_input_identity']='sha256-s3-authz-v1:'+hashlib.sha256(raw).hexdigest()
    r=analyze_s3_kms(raw,json.dumps(x).encode())
    assert r['api_status']==r['authorization_status']=='UNKNOWN'
    return r

@pytest.mark.parametrize('mode,status', [('allow','POLICY_PATH_ALLOW_CANDIDATE'),('sse_s3','NOT_REQUIRED_CANDIDATE'),('disabled','KEY_UNAVAILABLE_CANDIDATE'),('key_deny','EXPLICIT_DENY_CANDIDATE'),('bucket_key_mismatch','POLICY_PATH_BLOCKED_CANDIDATE'),('bucket_key_allow','POLICY_PATH_ALLOW_CANDIDATE'),('unknown_grants','UNKNOWN'),('incomplete','UNKNOWN'),('aws_managed_cross','POLICY_PATH_BLOCKED_CANDIDATE'),('unknown_encryption','UNKNOWN')])
def test_samples(mode,status):
    r=analyze_s3_kms(A,(D/f's3_kms_{mode}.json').read_bytes()); assert r['kms_status']==status; assert r['api_status']==r['authorization_status']=='UNKNOWN'

@pytest.mark.parametrize('field,value,reason', [('metadata_complete',False,'OBJECT_METADATA_UNCONFIRMED'),('resource','arn:aws:s3:::other/file','OBJECT_METADATA_UNCONFIRMED'),('region','us-east-1','KMS_KEY_OR_CONTEXT_UNCONFIRMED'),('bucket_key_enabled',None,'KMS_KEY_OR_CONTEXT_UNCONFIRMED'),('key_arn','alias/demo','KMS_KEY_OR_CONTEXT_UNCONFIRMED'),('encryption_mode','DSSE_KMS','ENCRYPTION_MODE_UNSUPPORTED_OR_UNKNOWN'),('encryption_mode','SSE_C','ENCRYPTION_MODE_UNSUPPORTED_OR_UNKNOWN')])
def test_object(field,value,reason):
    e=copy.deepcopy(E);e['object'][field]=value; assert run(e=e)['reason']==reason

@pytest.mark.parametrize('field,value,reason', [('state','PendingDeletion','KEY_STATE_NOT_ENABLED'),('state','Unavailable','KEY_STATE_UNCONFIRMED'),('spec','RSA_2048','KEY_TYPE_UNSUPPORTED'),('usage','SIGN_VERIFY','KEY_TYPE_UNSUPPORTED'),('arn','wrong','KMS_KEY_BINDING_MISMATCH'),('policy',[],'POLICY_OR_GRANT_EVIDENCE_INCOMPLETE')])
def test_key(field,value,reason):
    e=copy.deepcopy(E);e['key'][field]=value; assert run(e=e)['reason']==reason

@pytest.mark.parametrize('case,status', [('identity_no_allow','POLICY_PATH_BLOCKED_CANDIDATE'),('identity_deny','EXPLICIT_DENY_CANDIDATE'),('identity_incomplete','UNKNOWN'),('root_delegation','POLICY_PATH_ALLOW_CANDIDATE'),('other_principal','POLICY_PATH_BLOCKED_CANDIDATE'),('unknown_principal','UNKNOWN'),('unsupported_condition','UNKNOWN'),('not_action','UNKNOWN'),('same_account_direct','POLICY_PATH_ALLOW_CANDIDATE'),('same_account_delegation','POLICY_PATH_BLOCKED_CANDIDATE')])
def test_policy(case,status):
    a=json.loads(A);e=copy.deepcopy(E);i=a['policies']['identity'][0]['Statement'];s=e['key']['policy'][0]['Statement'][0]
    if case=='identity_no_allow': i.pop()
    elif case=='identity_deny': i[-1]['Effect']='Deny'
    elif case=='identity_incomplete': a['complete']['identity']=False
    elif case=='root_delegation': s['Principal']={'AWS':'arn:aws:iam::123456789012:root'}
    elif case=='other_principal': s['Principal']={'AWS':'arn:aws:iam::123456789012:role/other'}
    elif case=='unknown_principal': s['Principal']='*'
    elif case=='unsupported_condition': s['Condition']['StringEquals']['kms:EncryptionContext:custom']='value'
    elif case=='not_action': s['NotAction']=s.pop('Action')
    elif case.startswith('same_account'):
        i.pop(); old=e['object']['key_arn']; new=old.replace('222222222222','123456789012');e['object']['key_arn']=e['key']['arn']=new
        if case.endswith('delegation'): s['Principal']={'AWS':'arn:aws:iam::123456789012:root'}
    assert run(a,e)['kms_status']==status

def test_missing(): assert analyze_s3_kms(A)['reason']=='ENCRYPTION_EVIDENCE_MISSING'
def test_binding():
    e=copy.deepcopy(E);e['authorization_input_identity']='wrong';assert run(e=e)['reason']=='AUTHORIZATION_BINDING_MISMATCH'
def test_assertion_conflict():
    a=json.loads(A);a['assertions']['no_kms_requirement']=True;assert run(a)['reason']=='CONTRADICTORY_AUTHORIZATION_ASSERTION'
def test_missing_key():
    e=copy.deepcopy(E);e['key']=None;assert run(e=e)['reason']=='KMS_KEY_EVIDENCE_MISSING'
def test_list_bucket():
    a=json.loads(A);a['request']['action']='s3:ListBucket';a['request']['resource']=a['request']['resource'].split('/')[0];assert run(a)['kms_status']=='NOT_APPLICABLE'
def test_duplicate_json():
    with pytest.raises(ValueError): analyze_s3_kms(A,b'{"schema":1,"schema":2}')
def test_bad_schema():
    with pytest.raises(ValueError): analyze_s3_kms(A,b'{}')
def test_non_bytes():
    with pytest.raises(ValueError): analyze_s3_kms(A,{})
def test_large():
    with pytest.raises(ValueError): analyze_s3_kms(A,b' '*1048577)
