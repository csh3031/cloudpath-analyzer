import copy
import hashlib
import json
from pathlib import Path
import pytest
from backend.aws.s3_identity_evidence import analyze_s3_identity, MAX_IDENTITY_BYTES

D=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
AUTH=(D/'s3_authz_allow.json').read_bytes()
IDENT=json.loads((D/'s3_identity_allow.json').read_bytes())

def raw(e): return json.dumps(e).encode()
def run(e=None,a=AUTH): return analyze_s3_identity(a,None if e is None else raw(e))
def fresh(): return copy.deepcopy(IDENT)
def rebind(e,a):
    a=raw(a); e['authorization_input_identity']='sha256-s3-authz-v1:'+hashlib.sha256(a).hexdigest(); return a

def test_candidate():
    r=run(fresh()); assert r['identity_status']=='CORRELATED_CANDIDATE'
    assert r['correlated_authorization_status']=='ALLOW_CANDIDATE'
    assert r['attachments'][0]['document_index']==0 and r['attachments'][0]['version']=='v2'
    assert r['source_identity_status']==r['api_status']=='UNKNOWN' and r['live_observation'] is False
    assert r['network_status']==r['authentication_status']=='NOT_EVALUATED'

def test_missing():
    r=run(); assert r['reason']=='IAM_IDENTITY_EVIDENCE_MISSING' and r['correlated_authorization_status']=='UNKNOWN'
    assert r['authorization']['authorization_status']=='ALLOW_CANDIDATE'

@pytest.mark.parametrize('field,value,reason',[
    ('authorization_input_identity','wrong','IAM_AUTHORIZATION_IDENTITY_MISMATCH'),
    ('request_at','2026-11-28T05:05:01Z','IAM_EVIDENCE_TIME_SCOPE_UNCONFIRMED'),
    ('request_at','2026-11-28T04:59:59Z','IAM_EVIDENCE_TIME_SCOPE_UNCONFIRMED'),
    ('started_at','2026-11-28T05:00:21Z','IAM_EVIDENCE_TIME_SCOPE_UNCONFIRMED'),
    ('managed_arns_after',[],'IAM_ATTACHMENT_LIST_CHANGED'),
    ('managed_policies',[],'IAM_ATTACHMENT_DOCUMENT_SET_MISMATCH'),
    ('inline_names_after',['extra'],'IAM_ATTACHMENT_LIST_CHANGED'),
])
def test_unconfirmed(field,value,reason):
    e=fresh(); e[field]=value; r=run(e); assert r['reason']==reason and r['correlated_authorization_status']=='UNKNOWN'

@pytest.mark.parametrize('flag',list(IDENT['complete']))
def test_incomplete(flag):
    e=fresh(); e['complete'][flag]=False; assert run(e)['reason']=='IAM_COLLECTION_INCOMPLETE'

@pytest.mark.parametrize('field,value,reason',[
    ('default_version_after','v3','IAM_MANAGED_DEFAULT_VERSION_UNCONFIRMED'),
    ('default_version_before','v1','IAM_MANAGED_DEFAULT_VERSION_UNCONFIRMED'),
    ('document_version','v1','IAM_MANAGED_DEFAULT_VERSION_UNCONFIRMED'),
    ('is_default_version',False,'IAM_MANAGED_DEFAULT_VERSION_UNCONFIRMED'),
    ('policy_id_after','ANPAOTHERSYNTHETIC12345','IAM_MANAGED_POLICY_ID_CHANGED'),
])
def test_managed_changes(field,value,reason):
    e=fresh(); e['managed_policies'][0][field]=value; r=run(e); assert r['reason']==reason and r['correlated_authorization_status']=='UNKNOWN'

def test_principal_recreated():
    e=fresh(); e['principal_after']['unique_id']='AROAOTHERSYNTHETIC12345'; assert run(e)['reason']=='IAM_PRINCIPAL_CHANGED'

def test_principal_mismatch():
    e=fresh(); e['principal_before']['arn']=e['principal_after']['arn']='arn:aws:iam::123456789012:role/other'; assert run(e)['reason']=='IAM_PRINCIPAL_SCOPE_MISMATCH'

def test_managed_other_account():
    e=fresh(); a='arn:aws:iam::999999999999:policy/demo'; e['managed_arns_before']=e['managed_arns_after']=[a]; e['managed_policies'][0]['arn']=a; assert run(e)['reason']=='IAM_MANAGED_POLICY_ACCOUNT_MISMATCH'

def test_aws_managed():
    e=fresh(); a='arn:aws:iam::aws:policy/demo'; e['managed_arns_before']=e['managed_arns_after']=[a]; e['managed_policies'][0]['arn']=a; assert run(e)['identity_status']=='CORRELATED_CANDIDATE'

def test_duplicate_attachment():
    e=fresh(); e['managed_arns_before']*=2; assert run(e)['reason']=='IAM_DUPLICATE_ATTACHMENT'

def test_duplicate_doc_record():
    e=fresh(); e['managed_policies']*=2; assert run(e)['reason']=='IAM_ATTACHMENT_DOCUMENT_SET_MISMATCH'

def test_doc_content_changed():
    e=fresh(); e['managed_policies'][0]['document']['Statement'][0]['Resource']='arn:aws:s3:::other/*'; assert run(e)['reason']=='IAM_IDENTITY_POLICY_CONTENT_MISMATCH'

def test_boundary_not_evaluated():
    e=fresh(); e['principal_before']['permissions_boundary_arn']=e['principal_after']['permissions_boundary_arn']='arn:aws:iam::123456789012:policy/boundary'; r=run(e); assert r['identity_status']=='CORRELATED_CANDIDATE' and r['reason']=='IAM_PERMISSIONS_BOUNDARY_PENDING' and r['correlated_authorization_status']=='UNKNOWN'

def inline_fixture():
    e=fresh(); d=e['managed_policies'][0]['document']; e['managed_policies']=[]; e['managed_arns_before']=e['managed_arns_after']=[]; e['inline_names_before']=e['inline_names_after']=['Demo']; e['inline_policies']=[{'name':'Demo','principal_id':e['principal_before']['unique_id'],'document_before':copy.deepcopy(d),'document_after':copy.deepcopy(d)}]; return e

def test_inline():
    r=run(inline_fixture()); assert r['correlated_authorization_status']=='ALLOW_CANDIDATE' and r['attachments']==[{'kind':'INLINE','name':'Demo','document_index':0}]

def test_inline_owner():
    e=inline_fixture(); e['inline_policies'][0]['principal_id']='other'; assert run(e)['reason']=='IAM_INLINE_PRINCIPAL_MISMATCH'

def test_inline_changed():
    e=inline_fixture(); e['inline_policies'][0]['document_after']['Statement'][0]['Effect']='Deny'; assert run(e)['reason']=='IAM_INLINE_DOCUMENT_CHANGED'

def test_group_role_conflict():
    e=fresh(); e['groups_before']=e['groups_after']=['arn:aws:iam::123456789012:group/demo']; assert run(e)['reason']=='IAM_ROLE_GROUP_CONFLICT'

def user_fixture():
    e=fresh(); a=json.loads(AUTH); arn='arn:aws:iam::123456789012:user/demo'; a['request']['principal_arn']=arn; a['policies']['endpoint'][0]['Statement'][0]['Condition']['ArnEquals']['aws:PrincipalArn']=arn
    for k in ('principal_before','principal_after'): e[k]['arn']=arn; e[k]['unique_id']='AIDASYNTHETICDEMO12345'
    return e,rebind(e,a)

def test_user_no_groups():
    e,a=user_fixture(); assert run(e,a)['correlated_authorization_status']=='ALLOW_CANDIDATE'

def test_user_groups_unknown():
    e,a=user_fixture(); e['groups_before']=e['groups_after']=['arn:aws:iam::123456789012:group/demo']; assert run(e,a)['reason']=='IAM_GROUP_POLICY_SCOPE_UNSUPPORTED'

def test_g1_explicit_deny_preserved_only_when_correlated():
    e=fresh(); a=json.loads(AUTH); a['policies']['identity'][0]['Statement'][0]['Effect']='Deny'; e['managed_policies'][0]['document']=a['policies']['identity'][0]; a=rebind(e,a); assert run(e,a)['correlated_authorization_status']=='EXPLICIT_DENY'; e['complete']['documents']=False; r=run(e,a); assert r['authorization']['authorization_status']=='EXPLICIT_DENY' and r['correlated_authorization_status']=='UNKNOWN'

def test_g1_incomplete():
    e=fresh(); a=json.loads(AUTH); a['complete']['identity']=False; assert run(e,rebind(e,a))['reason']=='IAM_AUTHORIZATION_IDENTITY_INCOMPLETE'

def test_no_policy_does_not_invent_grant():
    e=fresh(); a=json.loads(AUTH); a['policies']['identity']=[]; e['managed_policies']=[]; e['managed_arns_before']=e['managed_arns_after']=[]; r=run(e,rebind(e,a)); assert r['correlated_authorization_status']=='IMPLICIT_DENY_CANDIDATE'

def test_multiple_identical_documents_multiplicity():
    e=inline_fixture(); a=json.loads(AUTH); a['policies']['identity']*=2; e['inline_names_before']=e['inline_names_after']=['Demo','Second']; row=copy.deepcopy(e['inline_policies'][0]); row['name']='Second'; e['inline_policies'].append(row); a=rebind(e,a); assert len(run(e,a)['attachments'])==2; e['inline_policies'][1]['document_before']['Id']='different'; e['inline_policies'][1]['document_after']['Id']='different'; assert run(e,a)['reason']=='IAM_IDENTITY_POLICY_CONTENT_MISMATCH'

@pytest.mark.parametrize('field,value',[('schema','wrong'),('complete',{}),('managed_arns_before',[123]),('principal_before',{}),('started_at','2026-11-28T05:00:00'),('managed_policies',[{}]),('inline_policies',[{}]),('groups_before',None)])
def test_malformed(field,value):
    e=fresh(); e[field]=value
    with pytest.raises(ValueError): run(e)

@pytest.mark.parametrize('bad',[b'{"schema":1,"schema":2}',b' '* (MAX_IDENTITY_BYTES+1),b'{"x":NaN}',b'\xff'])
def test_invalid_raw(bad):
    with pytest.raises(ValueError): analyze_s3_identity(AUTH,bad)

def test_no_raw_document_export():
    e=fresh(); a=json.loads(AUTH); a['policies']['identity'][0]['Statement'][0]['Sid']='SYNTHETIC-MARKER'; e['managed_policies'][0]['document']=a['policies']['identity'][0]; r=run(e,rebind(e,a)); assert 'SYNTHETIC-MARKER' not in json.dumps(r)
