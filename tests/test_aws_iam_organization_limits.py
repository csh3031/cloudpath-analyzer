import copy
import hashlib
import json
from pathlib import Path
import pytest
from backend.aws.iam_organization_limits import analyze_iam_organization_limits as analyze

D=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
A=(D/'iam_org_authorization.json').read_bytes()

def sample(mode='allow'):
    return json.loads((D/f'iam_org_{mode}.json').read_bytes())

def run(e, a=A):
    r=analyze(a,json.dumps(e).encode())
    assert r['authorization_status']==r['runtime_identity_status']==r['api_status']=='UNKNOWN'
    assert r['live_observation'] is False
    return r

@pytest.mark.parametrize('mode,scp,rcp,overall',[
 ('allow','ALLOW_CANDIDATE','ALLOW_CANDIDATE','ORGANIZATION_PASS_CANDIDATE'),
 ('scp_deny','EXPLICIT_DENY','ALLOW_CANDIDATE','EXPLICIT_DENY_CANDIDATE'),
 ('scp_no_allow','NO_MATCHING_ALLOW','ALLOW_CANDIDATE','ORGANIZATION_BLOCKED_CANDIDATE'),
 ('rcp_deny','ALLOW_CANDIDATE','EXPLICIT_DENY','EXPLICIT_DENY_CANDIDATE'),
 ('incomplete','UNKNOWN','ALLOW_CANDIDATE','UNKNOWN'),
 ('missing_rcp_default','ALLOW_CANDIDATE','UNKNOWN','UNKNOWN'),
 ('standalone','NOT_APPLICABLE','NOT_APPLICABLE','ORGANIZATION_PASS_CANDIDATE'),
])
def test_samples(mode,scp,rcp,overall):
    r=run(sample(mode)); assert (r['scp']['status'],r['rcp']['status'],r['organization_status'])==(scp,rcp,overall)

def test_missing():
    assert analyze(A)['reason']=='ORGANIZATION_EVIDENCE_MISSING'

@pytest.mark.parametrize('key,value,reason',[
 ('authorization_input_identity','bad','ORGANIZATION_INPUT_IDENTITY_MISMATCH'),
 ('account_id','222222222222','ORGANIZATION_ACCOUNT_SCOPE_UNSUPPORTED_OR_MISMATCH'),
 ('scope_complete',False,'ORGANIZATION_SCOPE_INCOMPLETE'),
 ('membership','UNKNOWN','ORGANIZATION_SCOPE_INCOMPLETE'),
 ('principal_kind','UNKNOWN','ORGANIZATION_SCOPE_INCOMPLETE'),
 ('principal_kind','IAM_USER','PRINCIPAL_KIND_CONFLICT'),
 ('principal_kind','SERVICE_LINKED_ROLE','PRINCIPAL_KIND_CONFLICT'),
 ('management_account_id','123456789012','ORGANIZATION_MEMBERSHIP_CONFLICT'),
 ('organization_id',None,'ORGANIZATION_MEMBERSHIP_CONFLICT'),
 ('membership','MANAGEMENT','ORGANIZATION_MEMBERSHIP_CONFLICT'),
 ('membership','STANDALONE','ORGANIZATION_MEMBERSHIP_CONFLICT'),
])
def test_scope(key,value,reason):
    e=sample();e[key]=value;r=run(e);assert r['reason']==reason and r['organization_status']=='UNKNOWN'

@pytest.mark.parametrize('mutation', ['incomplete','no_root','wrong_parent','wrong_account','wrong_ou_root','reordered','duplicate'])
def test_path(mutation):
    e=sample();l=e['levels']
    if mutation=='incomplete':e['path_complete']=False
    elif mutation=='no_root':l.pop(0)
    elif mutation=='wrong_parent':l[1]['parent_id']='r-xxxx'
    elif mutation=='wrong_account':l[-1]['id']='222222222222'
    elif mutation=='wrong_ou_root':l[1]['id']='ou-xxxx-abcdefgh';l[-1]['parent_id']=l[1]['id']
    elif mutation=='reordered':l[1],l[2]=l[2],l[1]
    else:l.insert(1,copy.deepcopy(l[0]))
    r=run(e);assert r['scp']['reason']==r['rcp']['reason']=='HIERARCHY_UNCONFIRMED'

@pytest.mark.parametrize('kind', ['scp','rcp'])
def test_disabled_conflict(kind):
    e=sample();e[kind+'_state']='DISABLED';assert run(e)[kind]['reason']=='DISABLED_WITH_ATTACHMENTS'

@pytest.mark.parametrize('kind', ['scp','rcp'])
def test_disabled(kind):
    e=sample();e[kind+'_state']='DISABLED'
    for l in e['levels']:l[kind+'s']=[]
    assert run(e)[kind]['status']=='NOT_APPLICABLE'

@pytest.mark.parametrize('kind', ['scp','rcp'])
def test_unknown_policy_type(kind):
    e=sample();e[kind+'_state']='UNKNOWN';assert run(e)[kind]['status']=='UNKNOWN'

@pytest.mark.parametrize('mutation',['custom_allow','wrong_principal','fake_default','missing_default','unresolved_condition'])
def test_rcp_invalid(mutation):
    e=sample('rcp_deny');rows=e['levels'][1]['rcps'];s=rows[1]['document']['Statement'][0]
    if mutation=='custom_allow':s['Effect']='Allow'
    elif mutation=='wrong_principal':s['Principal']={'AWS':'*'}
    elif mutation=='fake_default':
        for l in e['levels']:l['rcps'][0]['aws_managed']=False
    elif mutation=='missing_default':rows.pop(0)
    else:s['Condition']={'StringEquals':{'aws:PrincipalOrgID':'o-abcdefghij'}}
    assert run(e)['rcp']['status']=='UNKNOWN'

def test_management():
    e=sample();e.update(membership='MANAGEMENT',management_account_id=e['account_id']);r=run(e);assert r['scp']['status']==r['rcp']['status']=='NOT_APPLICABLE'

def rebind(e, mutate):
    a=json.loads(A);mutate(a);raw=json.dumps(a).encode();e['authorization_input_identity']='sha256-s3-authz-v1:'+hashlib.sha256(raw).hexdigest();return raw

def test_assertion_conflict():
    e=sample();a=rebind(e,lambda a:a['assertions'].update(no_scp_rcp=True));r=run(e,a);assert r['scp']['reason']==r['rcp']['reason']=='G1_NO_CONTROLS_ASSERTION_CONFLICT'

def test_cross_account():
    e=sample();a=rebind(e,lambda a:a['request'].update(bucket_account='222222222222'));assert run(e,a)['reason']=='ORGANIZATION_ACCOUNT_SCOPE_UNSUPPORTED_OR_MISMATCH'

def test_service_linked():
    e=sample();e['principal_kind']='SERVICE_LINKED_ROLE';a=rebind(e,lambda a:a['request'].update(principal_arn='arn:aws:iam::123456789012:role/aws-service-role/demo.amazonaws.com/AWSServiceRoleForDemo'));r=run(e,a);assert r['scp']['status']==r['rcp']['status']=='NOT_APPLICABLE'

def test_same_level_union():
    e=sample('scp_no_allow');e['levels'][1]['scps'].append(copy.deepcopy(e['levels'][0]['scps'][0]));assert run(e)['scp']['status']=='ALLOW_CANDIDATE'

def test_deny_precedence():
    e=sample('scp_deny');e['levels'][1]['scp_complete']=False;assert run(e)['organization_status']=='EXPLICIT_DENY_CANDIDATE'

@pytest.mark.parametrize('raw',[b'{"a":1,"a":2}',b'null',b'{',b'{}',b' '* (2*1024*1024+1)])
def test_malformed(raw):
    with pytest.raises(ValueError):analyze(A,raw)

@pytest.mark.parametrize('mutation',['duplicate_policy','conflicting_policy','bad_flag','bad_schema'])
def test_invalid_evidence(mutation):
    e=sample()
    if mutation=='duplicate_policy':e['levels'][0]['scps'].append(e['levels'][0]['scps'][0])
    elif mutation=='conflicting_policy':e['levels'][1]['scps'][0]['name']='different'
    elif mutation=='bad_flag':e['scope_complete']=1
    else:e['schema']='other'
    with pytest.raises(ValueError):run(e)
