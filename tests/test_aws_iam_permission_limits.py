import copy
import hashlib
import json
from pathlib import Path
import pytest
from backend.aws.iam_permission_limits import analyze_iam_permission_limits, MAX_LIMIT_BYTES

D = Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'

def raw(x): return json.dumps(x).encode()
def digest(prefix,x): return prefix+hashlib.sha256(x).hexdigest()

def policy(effect='Allow', action='s3:GetObject'):
    return {'Version':'2012-10-17','Statement':[{'Effect':effect,'Action':action,'Resource':'*'}]}

@pytest.fixture
def data():
    a=json.loads((D/'s3_authz_allow.json').read_bytes())
    i=json.loads((D/'s3_identity_allow.json').read_bytes())
    b=copy.deepcopy(i['managed_policies'][0]); b['arn']='arn:aws:iam::123456789012:policy/demo-boundary'; b['document']=policy()
    for k in ('principal_before','principal_after'): i[k]['permissions_boundary_arn']=b['arn']
    a['assertions']['no_permissions_boundary']=a['assertions']['no_session_policy']=False
    e={'schema':'cloudpath-iam-permission-limits-v1','authorization_input_identity':'','identity_input_identity':'','boundary':{'state':'PRESENT','complete':True,'policy':b},'session':{'state':'PRESENT','complete':True,'session_kind':'ASSUMED_ROLE','inline_document':policy(),'managed_policies':[]}}
    return a,i,e

def bind(data):
    a,i,e=data; ar=raw(a); i['authorization_input_identity']=digest('sha256-s3-authz-v1:',ar); ir=raw(i); e['authorization_input_identity']=i['authorization_input_identity']; e['identity_input_identity']=digest('sha256-s3-identity-v1:',ir); return ar,ir,raw(e)

def run(data):
    r=analyze_iam_permission_limits(*bind(data)); assert r['authorization_status']==r['api_status']==r['runtime_identity_status']=='UNKNOWN'; assert not r['live_observation']; return r

def test_allow(data):
    r=run(data); assert r['identity_grant_status']=='IDENTITY_GRANT_CANDIDATE'; assert r['boundary']['status']==r['session']['status']=='ALLOW_CANDIDATE'

@pytest.mark.parametrize('layer',['boundary','session'])
@pytest.mark.parametrize('effect,action,expected',[('Deny','s3:GetObject','EXPLICIT_DENY_CANDIDATE'),('Allow','s3:ListBucket','IDENTITY_GRANT_BLOCKED_CANDIDATE'),('Allow','S3:GETOBJECT','IDENTITY_GRANT_CANDIDATE')])
def test_policy(data,layer,effect,action,expected):
    e=data[2]; doc=policy(effect,action)
    if layer=='boundary': e[layer]['policy']['document']=doc
    else: e[layer]['inline_document']=doc
    assert run(data)['identity_grant_status']==expected

@pytest.mark.parametrize('layer',['boundary','session'])
@pytest.mark.parametrize('mode',['unknown','incomplete'])
def test_incomplete(data,layer,mode):
    e=data[2][layer]
    if mode=='incomplete': e['complete']=False
    else:
        e['state']='UNKNOWN'
        e['policy' if layer=='boundary' else 'inline_document']=None
    r=run(data); assert r[layer]['status']=='UNKNOWN' and r['identity_grant_status']=='UNKNOWN'

@pytest.mark.parametrize('layer',['boundary','session'])
def test_absent(data,layer):
    a,i,e=data; e[layer]['state']='ABSENT'
    if layer=='boundary':
        e[layer]['policy']=None; a['assertions']['no_permissions_boundary']=True
        for k in ('principal_before','principal_after'): i[k]['permissions_boundary_arn']=None
    else: e[layer]['inline_document']=None; a['assertions']['no_session_policy']=True
    r=run(data); assert r[layer]['status']=='NOT_APPLICABLE' and r['identity_grant_status']=='IDENTITY_GRANT_CANDIDATE'

@pytest.mark.parametrize('layer',['boundary','session'])
def test_absence_conflict(data,layer):
    e=data[2][layer]; e['state']='ABSENT'; e['policy' if layer=='boundary' else 'inline_document']=None
    assert run(data)[layer]['status']=='UNKNOWN'

@pytest.mark.parametrize('key,val',[('default_version_after','v3'),('document_version','v1'),('is_default_version',False),('policy_id_after','ANPAOTHERDEMO12345'),('arn','arn:aws:iam::999999999999:policy/demo-boundary'),('arn','arn:aws:iam::123456789012:policy/other')])
def test_boundary_binding(data,key,val):
    data[2]['boundary']['policy'][key]=val
    assert run(data)['boundary']['status']=='UNKNOWN'

@pytest.mark.parametrize('layer',['boundary','session'])
def test_unsupported_condition(data,layer):
    doc=policy(); doc['Statement'][0]['Condition']={'NumericEquals':{'s3:max-keys':'1'}}
    if layer=='boundary': data[2][layer]['policy']['document']=doc
    else: data[2][layer]['inline_document']=doc
    assert run(data)[layer]['status']=='UNKNOWN'

@pytest.mark.parametrize('key',['authorization_input_identity','identity_input_identity'])
def test_digest(data,key):
    ar,ir,er=bind(data); e=json.loads(er); e[key]='wrong'; assert analyze_iam_permission_limits(ar,ir,raw(e))['reason']=='LIMIT_INPUT_IDENTITY_MISMATCH'

def test_missing(data):
    ar,ir,_=bind(data); assert analyze_iam_permission_limits(ar,ir)['identity_grant_status']=='UNKNOWN'

def test_uncorrelated(data):
    data[1]['complete']['principal']=False; assert run(data)['reason']=='IAM_ATTACHMENT_UNCORRELATED'

def test_session_union(data):
    a,i,e=data; row=copy.deepcopy(i['managed_policies'][0]); e['session']['managed_policies']=[row]; e['session']['inline_document']=policy(action='s3:ListBucket'); assert run(data)['session']['status']=='ALLOW_CANDIDATE'

def test_session_explicit_deny(data):
    a,i,e=data; row=copy.deepcopy(i['managed_policies'][0]); row['document']=policy('Deny'); e['session']['managed_policies']=[row]; assert run(data)['session']['status']=='EXPLICIT_DENY'

def test_session_duplicate(data):
    row=copy.deepcopy(data[1]['managed_policies'][0]); data[2]['session']['managed_policies']=[row,row]; assert run(data)['session']['status']=='UNKNOWN'

def test_session_version(data):
    row=copy.deepcopy(data[1]['managed_policies'][0]); row['document_version']='v1'; data[2]['session']['managed_policies']=[row]; assert run(data)['session']['status']=='UNKNOWN'

@pytest.mark.parametrize('kind',['IAM_USER','UNKNOWN'])
def test_session_kind(data,kind):
    data[2]['session']['session_kind']=kind; assert run(data)['session']['status']=='UNKNOWN'

def test_bucket_grant_not_composed(data):
    a,i,e=data; a['policies']['bucket']=[{'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'s3:GetObject','Resource':'*','Principal':'*'}]}]; e['boundary']['policy']['document']=policy(action='s3:ListBucket'); r=run(data); assert r['identity_grant_status']=='IDENTITY_GRANT_BLOCKED_CANDIDATE' and r['authorization_status']=='UNKNOWN'

def test_no_identity_grant(data):
    a,i,e=data; a['policies']['identity']=[policy(action='s3:ListBucket')]; i['managed_policies'][0]['document']=a['policies']['identity'][0]; assert run(data)['identity_grant_status']=='IDENTITY_GRANT_BLOCKED_CANDIDATE'

@pytest.mark.parametrize('bad',[b'{}',b'{"schema":1,"schema":2}',b'x'*(MAX_LIMIT_BYTES+1)])
def test_bad(data,bad):
    ar,ir,_=bind(data)
    with pytest.raises(ValueError): analyze_iam_permission_limits(ar,ir,bad)

def test_state_conflict(data):
    data[2]['session']['state']='ABSENT'
    with pytest.raises(ValueError): run(data)

def test_no_mutation(data):
    args=bind(data); before=copy.deepcopy(args); assert analyze_iam_permission_limits(*args)==analyze_iam_permission_limits(*args); assert args==before
