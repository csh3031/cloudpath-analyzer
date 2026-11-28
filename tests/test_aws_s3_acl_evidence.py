import copy,json,hashlib
from pathlib import Path
import pytest
from backend.aws.s3_acl_evidence import analyze_s3_acl,FLAGS
D=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
AUTH=(D/'s3_acl_authorization.json').read_bytes()
BASE=json.loads((D/'s3_acl_account_read.json').read_bytes())
def run(e=BASE,auth=AUTH):
    r=analyze_s3_acl(auth,json.dumps(e).encode() if e is not None else None)
    assert r['authorization_status']==r['api_status']=='UNKNOWN'
    assert r['live_observation'] is False
    return r
@pytest.mark.parametrize('mode,ownership,acl,bpa',[
 ('account_read','BUCKET_ACCOUNT_OWNER_CANDIDATE','ACCOUNT_READ_GRANT_CANDIDATE','NO_RESTRICT_PUBLIC_BUCKETS_BLOCK_CANDIDATE'),
 ('enforced','BUCKET_ACCOUNT_OWNER_CANDIDATE','ACL_DISABLED_CANDIDATE','NO_RESTRICT_PUBLIC_BUCKETS_BLOCK_CANDIDATE'),
 ('other_owner','OTHER_ACCOUNT_OWNER_CANDIDATE','ACCOUNT_READ_GRANT_CANDIDATE','NO_RESTRICT_PUBLIC_BUCKETS_BLOCK_CANDIDATE'),
 ('restrict_public','BUCKET_ACCOUNT_OWNER_CANDIDATE','ACCOUNT_READ_GRANT_CANDIDATE','CROSS_ACCOUNT_BLOCK_CANDIDATE'),
 ('ignore_public','BUCKET_ACCOUNT_OWNER_CANDIDATE','NO_MATCHING_ACCOUNT_READ_GRANT_CANDIDATE','NO_RESTRICT_PUBLIC_BUCKETS_BLOCK_CANDIDATE'),
 ('public_unresolved','BUCKET_ACCOUNT_OWNER_CANDIDATE','UNKNOWN','NO_RESTRICT_PUBLIC_BUCKETS_BLOCK_CANDIDATE'),
 ('block_write_only','BUCKET_ACCOUNT_OWNER_CANDIDATE','ACCOUNT_READ_GRANT_CANDIDATE','NO_RESTRICT_PUBLIC_BUCKETS_BLOCK_CANDIDATE'),
 ('incomplete','BUCKET_ACCOUNT_OWNER_CANDIDATE','UNKNOWN','NO_RESTRICT_PUBLIC_BUCKETS_BLOCK_CANDIDATE'),
 ('unknown_owner','UNKNOWN','UNKNOWN','NO_RESTRICT_PUBLIC_BUCKETS_BLOCK_CANDIDATE'),
 ('unknown_bpa','BUCKET_ACCOUNT_OWNER_CANDIDATE','ACCOUNT_READ_GRANT_CANDIDATE','UNKNOWN'),
 ('no_read','BUCKET_ACCOUNT_OWNER_CANDIDATE','NO_MATCHING_ACCOUNT_READ_GRANT_CANDIDATE','NO_RESTRICT_PUBLIC_BUCKETS_BLOCK_CANDIDATE'),
])
def test_fixtures(mode,ownership,acl,bpa):
    r=run(json.loads((D/f's3_acl_{mode}.json').read_bytes()))
    assert (r['ownership_status'],r['acl_status'],r['public_access_status'])==(ownership,acl,bpa)
@pytest.mark.parametrize('flag',FLAGS)
@pytest.mark.parametrize('bucket,account,org,expected',[(False,False,True,False),(True,None,False,True),(None,True,False,True),(False,False,False,None),(None,False,True,None)])
def test_effective_flags(flag,bucket,account,org,expected):
    e=copy.deepcopy(BASE); p=e['public_access'];p['bucket_flags'][flag]=bucket;p['account_flags'][flag]=account;p['account_includes_org_controls']=org
    assert run(e)['effective_public_access_block'][flag] is expected
@pytest.mark.parametrize('field,value,reason',[
 ('authorization_input_identity','wrong','AUTHORIZATION_BINDING_MISMATCH'),
 ('acl',None,'ACL_METADATA_MISSING'),
])
def test_top(field,value,reason):
    e=copy.deepcopy(BASE);e[field]=value;assert run(e)['reason']==reason
@pytest.mark.parametrize('field,value,reason',[
 ('resource','wrong','RESOURCE_BINDING_MISMATCH'),('bucket_account','999999999999','RESOURCE_BINDING_MISMATCH'),('complete',False,'OWNERSHIP_EVIDENCE_INCOMPLETE'),('mode',None,'OWNERSHIP_EVIDENCE_INCOMPLETE'),('resource_owner_account',None,'OWNERSHIP_EVIDENCE_INCOMPLETE')])
def test_ownership(field,value,reason):
    e=copy.deepcopy(BASE);e['ownership'][field]=value;assert run(e)['reason']==reason
@pytest.mark.parametrize('permission,expected',[('READ',True),('FULL_CONTROL',True),('READ_ACP',False),('WRITE',False),('WRITE_ACP',False)])
def test_permissions(permission,expected):
    e=copy.deepcopy(BASE);e['acl']['grants'][0]['permission']=permission;assert bool(run(e)['acl_read_candidate_refs']) is expected

def test_missing(): assert run(None)['reason']=='ACL_EVIDENCE_MISSING'
def test_owner_mapping():
    e=copy.deepcopy(BASE);e['acl']['canonical_accounts'].pop('b'*64);assert run(e)['reason']=='ACL_OWNER_BINDING_UNCONFIRMED'
def test_conflict():
    e=copy.deepcopy(BASE);e['ownership'].update(mode='BucketOwnerEnforced',resource_owner_account='123456789012');assert run(e)['reason']=='OWNERSHIP_CONFLICT'
def test_unknown_grantee():
    e=copy.deepcopy(BASE);e['acl']['grants'][0]['id']='c'*64;assert run(e)['acl_status']=='UNKNOWN'
def test_duplicate_keys():
    with pytest.raises(ValueError): analyze_s3_acl(AUTH,b'{"schema":1,"schema":2}')
def test_bad_flag():
    e=copy.deepcopy(BASE);e['public_access']['account_flags']['IgnorePublicAcls']=1
    with pytest.raises(ValueError):run(e)
def test_acl_binding():
    e=copy.deepcopy(BASE);e['acl']['resource']='wrong';assert run(e)['reason']=='ACL_RESOURCE_MISMATCH'
def test_public_ignored():
    r=run(json.loads((D/'s3_acl_ignore_public.json').read_bytes()));assert r['ignored_public_refs']==[0] and r['public_read_refs']==[]
def test_same_account_restrict():
    auth=json.loads(AUTH);auth['request']['principal_arn']='arn:aws:iam::222222222222:role/demo-app';auth=json.dumps(auth).encode();e=copy.deepcopy(BASE);e['authorization_input_identity']='sha256-s3-authz-v1:'+hashlib.sha256(auth).hexdigest();e['public_access']['bucket_policy_public']=True;e['public_access']['account_flags']['RestrictPublicBuckets']=True
    assert run(e,auth)['public_access_status']=='NO_RESTRICT_PUBLIC_BUCKETS_BLOCK_CANDIDATE'
def test_incomplete_bucket_policy():
    auth=json.loads(AUTH);auth['complete']['bucket']=False;auth=json.dumps(auth).encode();e=copy.deepcopy(BASE);e['authorization_input_identity']='sha256-s3-authz-v1:'+hashlib.sha256(auth).hexdigest();e['public_access']['bucket_policy_public']=True;e['public_access']['account_flags']['RestrictPublicBuckets']=True
    assert run(e,auth)['public_access_status']=='UNKNOWN'

@pytest.mark.parametrize('owner,expected',[('222222222222','BUCKET_ACCOUNT_OWNER_CANDIDATE'),('123456789012','UNKNOWN')])
def test_list_bucket_scope(owner,expected):
    auth=json.loads(AUTH);auth['request'].update(action='s3:ListBucket',resource='arn:aws:s3:::cloudpath-demo-bucket');auth=json.dumps(auth).encode();e=copy.deepcopy(BASE);e['authorization_input_identity']='sha256-s3-authz-v1:'+hashlib.sha256(auth).hexdigest();e['ownership'].update(resource='arn:aws:s3:::cloudpath-demo-bucket',resource_owner_account=owner);e['acl']['resource']=e['ownership']['resource'];assert run(e,auth)['ownership_status']==expected

def test_public_policy_conflict():
    auth=json.loads(AUTH);auth['policies']['bucket']=[];auth=json.dumps(auth).encode();e=copy.deepcopy(BASE);e['authorization_input_identity']='sha256-s3-authz-v1:'+hashlib.sha256(auth).hexdigest();e['public_access']['bucket_policy_public']=True;e['public_access']['account_flags']['RestrictPublicBuckets']=True;assert run(e,auth)['public_access_status']=='UNKNOWN'
