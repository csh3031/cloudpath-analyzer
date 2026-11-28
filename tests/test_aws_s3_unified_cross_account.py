"""Cross-account composition with separately bound subject SCP and resource RCP."""
import json
import copy
import pytest
from backend.aws.s3_unified_evidence import analyze_s3_unified,digest
from backend.aws.iam_cross_account_organization import analyze_cross_account_organization
from backend.aws.s3_identity_evidence import analyze_s3_identity
from test_aws_s3_unified_evidence import args, raw, enc, change, manifest, rebind_auth, drop

A='123456789012'; B='222222222222'
PASS='CONDITIONAL_ACCESS_CANDIDATE'


def cross_args():
    a=args()
    def mutate(x):
        x['request']['bucket_account']=B
        x['assertions']['no_scp_rcp']=False
        x['policies']['bucket']=json.loads(raw('s3_cross_account_allow'))['policies']['bucket']
    rebind_auth(a,mutate)
    change(a,'acl',lambda x:x['ownership'].update(bucket_account=B,resource_owner_account=B))
    aid='sha256-s3-authz-v1:'+digest(a['authorization'])
    p=json.loads(raw('iam_org_allow'));p['authorization_input_identity']=aid
    o=copy.deepcopy(p);o['account_id']=B;o['levels'][-1]['id']=B
    # Different organizations; each has its own management account and hierarchy.
    o['organization_id']='o-bcdefghijk';o['management_account_id']='333333333333'
    a['organization']=enc(p);a['resource_organization']=enc(o)
    def m(x):
        x['schema']='cloudpath-s3-unified-v2';x['digests'].update(organization=digest(a['organization']),resource_organization=digest(a['resource_organization']));x['observed_at']['resource_organization']=x['request_at']
    manifest(a,m)
    return a


def run(a):
    r=analyze_s3_unified(**a)
    assert r['authorization_status']==r['api_status']==r['runtime_identity_status']=='UNKNOWN'
    assert not r['live_observation']
    return r


def deny(x,kind):
    s={'Effect':'Deny','Action':'s3:GetObject','Resource':'*'}
    if kind=='rcp':s['Principal']='*'
    x['levels'][-1][kind+'s'].append({'id':'p-ExampleDeny','name':'ExampleDeny','aws_managed':False,'document':{'Version':'2012-10-17','Statement':[s]}})


def standalone(x):
    x.update(organization_id=None,management_account_id=None,membership='STANDALONE',scp_state='DISABLED',rcp_state='DISABLED',path_complete=False,levels=[])


def test_cross_allow():
    r=run(cross_args());assert r['integrated_status']==PASS and r['grant_path']=='CROSS_ACCOUNT_IDENTITY_AND_RESOURCE' and r['unresolved']==[]
    assert r['components']['organization']['scp']['status']==r['components']['organization']['rcp']['status']=='ALLOW_CANDIDATE'

@pytest.mark.parametrize('key,kind,blocked',[('organization','scp',True),('resource_organization','rcp',True),('organization','rcp',False),('resource_organization','scp',False)])
def test_separate_account_controls(key,kind,blocked):
    a=cross_args();change(a,key,lambda x:deny(x,kind));r=run(a)
    assert (r['integrated_status']=='UNKNOWN')==blocked
    assert (r['components']['organization'][kind]['status']=='EXPLICIT_DENY')==blocked
    if blocked: assert any(f['layer']==kind and f['status']=='EXPLICIT_DENY' for f in r['independent_findings'])

@pytest.mark.parametrize('key',['organization','resource_organization'])
@pytest.mark.parametrize('mutation',['missing','wrong_account','wrong_digest','incomplete','wrong_principal','wrong_parent','tamper','stale'])
def test_evidence(key,mutation):
    a=cross_args()
    if mutation=='missing':drop(a,key)
    elif mutation=='wrong_account':change(a,key,lambda x:x.update(account_id=B if key=='organization' else A))
    elif mutation=='wrong_digest':change(a,key,lambda x:x.update(authorization_input_identity='bad'))
    elif mutation=='incomplete':change(a,key,lambda x:x.update(scope_complete=False))
    elif mutation=='wrong_principal':change(a,key,lambda x:x.update(principal_kind='IAM_USER'))
    elif mutation=='wrong_parent':change(a,key,lambda x:x['levels'][-1].update(parent_id='r-wrong'))
    elif mutation=='tamper':a[key]+=b' '
    else:manifest(a,lambda x:x['observed_at'].update({key:'2026-11-25T10:00:00Z'}))
    r=run(a);assert r['integrated_status']=='UNKNOWN'
    if mutation=='tamper':assert r['evidence_reason']=='INPUT_DIGEST_MISMATCH'
    if mutation=='stale':assert r['evidence_reason']=='EVIDENCE_TIME_SCOPE_UNCONFIRMED'

@pytest.mark.parametrize('key',['organization','resource_organization'])
def test_standalone(key):
    a=cross_args();change(a,key,standalone);r=run(a);assert r['integrated_status']==PASS
    assert r['components']['organization']['scp' if key=='organization' else 'rcp']['status']=='NOT_APPLICABLE'


def test_same_organization():
    a=cross_args();p=json.loads(a['organization']);change(a,'resource_organization',lambda x:x.update(organization_id=p['organization_id'],management_account_id=p['management_account_id']));assert run(a)['integrated_status']==PASS
    change(a,'resource_organization',lambda x:x['levels'][0]['rcps'].clear());r=run(a);assert r['integrated_status']=='UNKNOWN' and r['components']['organization']['reason']=='SHARED_ORGANIZATION_CONFLICT'


def test_scp_missing_allow():
    a=cross_args();change(a,'organization',lambda x:x['levels'][-1]['scps'][0].update(document={'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'s3:PutObject','Resource':'*'}]} ,id='p-OtherAllow',name='OtherAllow',aws_managed=False));r=run(a);assert r['integrated_status']=='UNKNOWN' and r['components']['organization']['scp']['status']=='NO_MATCHING_ALLOW'


def test_rcp_default_missing():
    a=cross_args();change(a,'resource_organization',lambda x:x['levels'][-1]['rcps'].clear());r=run(a);assert r['integrated_status']=='UNKNOWN' and r['components']['organization']['rcp']['status']=='UNKNOWN'

@pytest.mark.parametrize('key',['identity','limits','acl','encryption'])
def test_other_missing(key):
    a=cross_args();drop(a,key);assert run(a)['integrated_status']=='UNKNOWN'

@pytest.mark.parametrize('key',['boundary','session'])
def test_unknown_limit(key):
    a=cross_args();change(a,'limits',lambda x:x[key].update(complete=False));assert run(a)['integrated_status']=='UNKNOWN'


def test_v1_reject_extra():
    a=cross_args();manifest(a,lambda x:(x.update(schema='cloudpath-s3-unified-v1'),x['digests'].pop('resource_organization'),x['observed_at'].pop('resource_organization')));assert run(a)['evidence_reason']=='RESOURCE_ORGANIZATION_UNBOUND'
    del a['resource_organization'];assert run(a)['integrated_status']=='UNKNOWN'


def test_v2_same_account_conflict():
    a=args();a['resource_organization']=a['organization'];manifest(a,lambda x:(x.update(schema='cloudpath-s3-unified-v2'),x['digests'].update(resource_organization=digest(a['resource_organization'])),x['observed_at'].update(resource_organization=x['request_at'])));assert run(a)['evidence_reason']=='RESOURCE_ORGANIZATION_SCOPE_CONFLICT'

@pytest.mark.parametrize('principal',['*',{'AWS':'123456789012'},{'AWS':['arn:aws:iam::123456789012:role/demo-app','123456789012']}])
def test_unsupported_grant(principal):
    a=cross_args();change(a,'authorization',lambda x:x['policies']['bucket'][0]['Statement'][0].update(Principal=principal)); sync_auth(a);r=run(a);assert r['integrated_status']=='UNKNOWN' and 'CROSS_ACCOUNT_EXACT_RESOURCE_GRANT' in r['unresolved']


def sync_auth(a):
    rebind_auth(a,lambda x:None)
    change(a,'resource_organization',lambda x:x.update(authorization_input_identity='sha256-s3-authz-v1:'+digest(a['authorization'])))


def test_bucket_deny():
    a=cross_args();change(a,'authorization',lambda x:x['policies']['bucket'][0]['Statement'][0].update(Effect='Deny'));sync_auth(a);r=run(a);assert r['integrated_status']=='UNKNOWN' and any(f['layer']=='bucket' and f['status']=='EXPLICIT_DENY' for f in r['independent_findings'])


def test_no_identity_allow():
    a=cross_args();change(a,'authorization',lambda x:x['policies'].update(identity=[]));sync_auth(a);change(a,'identity',lambda x:x.update(managed_policies=[],managed_arns_before=[],managed_arns_after=[]));change(a,'limits',lambda x:x.update(identity_input_identity='sha256-s3-identity-v1:'+digest(a['identity'])));assert run(a)['integrated_status']=='UNKNOWN'


def test_default_identity_contract():
    a=cross_args();assert analyze_s3_identity(a['authorization'],a['identity'])['identity_status']=='UNKNOWN';assert analyze_s3_identity(a['authorization'],a['identity'],cross_account=True)['identity_status']=='CORRELATED_CANDIDATE'

@pytest.mark.parametrize('kind,effect',[('boundary','Deny'),('boundary','Allow'),('session','Deny'),('session','Allow')])
def test_limit_blocks(kind,effect):
    a=cross_args()
    doc={'Version':'2012-10-17','Statement':[{'Effect':effect,'Action':'s3:GetObject' if effect=='Deny' else 's3:PutObject','Resource':'*'}]}
    change(a,'authorization',lambda x:x['assertions'].update({'no_permissions_boundary' if kind=='boundary' else 'no_session_policy':False}));sync_auth(a)
    if kind=='boundary':
        arn='arn:aws:iam::123456789012:policy/demo-boundary'
        change(a,'identity',lambda x:[x[k].update(permissions_boundary_arn=arn) for k in ('principal_before','principal_after')])
        change(a,'limits',lambda x:(x.update(identity_input_identity='sha256-s3-identity-v1:'+digest(a['identity'])),x['boundary'].update(state='PRESENT',policy=dict(arn=arn,policy_id_before='ANPASYNTHETICDEMO12345',policy_id_after='ANPASYNTHETICDEMO12345',default_version_before='v1',default_version_after='v1',document_version='v1',is_default_version=True,document=doc))))
    else:change(a,'limits',lambda x:x['session'].update(state='PRESENT',inline_document=doc))
    r=run(a);assert r['integrated_status']=='UNKNOWN';assert r['components']['limits'][kind]['status']==('EXPLICIT_DENY' if effect=='Deny' else 'NO_MATCHING_ALLOW')


def test_public_restricted():
    a=cross_args();change(a,'acl',lambda x:(x['public_access']['bucket_flags'].update(RestrictPublicBuckets=True),x['public_access'].update(bucket_policy_public=True)))
    r=run(a);assert r['integrated_status']=='UNKNOWN' and 'PUBLIC_ACCESS_SCOPE' in r['unresolved'];assert r['components']['acl']['public_access_status']=='CROSS_ACCOUNT_BLOCK_CANDIDATE'


def test_endpoint_binding_mismatch():
    a=cross_args();b=json.loads(a['network']['binding_raw']);b['network_result_identity']='bad';a['network']['binding_raw']=enc(b);manifest(a,lambda m:m['digests'].update(network_binding=digest(a['network']['binding_raw'])))
    r=run(a);assert r['integrated_status']=='UNKNOWN' and 'NETWORK_REQUEST_BINDING' in r['unresolved']


def test_no_controls_conflict():
    a=cross_args();change(a,'authorization',lambda x:x['assertions'].update(no_scp_rcp=True));sync_auth(a);assert run(a)['integrated_status']=='UNKNOWN'


def test_resource_management_account():
    a=cross_args();change(a,'resource_organization',lambda x:x.update(membership='MANAGEMENT',management_account_id=B,levels=[],path_complete=False));r=run(a);assert r['integrated_status']==PASS and r['components']['organization']['rcp']['status']=='NOT_APPLICABLE'
