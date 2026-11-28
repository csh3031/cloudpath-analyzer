"""G3e.2 end-to-end exact principal resource-grant composition."""
import json
import copy
import pytest
from backend.aws.s3_unified_evidence import analyze_s3_unified,digest
from backend.aws.s3_access_evidence import analyze_s3_access
from test_aws_s3_unified_evidence import args,change,manifest,rebind_auth,drop,enc,raw

PASS='CONDITIONAL_ACCESS_CANDIDATE'
ALLOW='RESOURCE_GRANT_ALLOW_CANDIDATE'
BLOCK='RESOURCE_GRANT_BLOCKED_CANDIDATE'
DENY='EXPLICIT_DENY_CANDIDATE'


def refresh_limits(a):
    change(a,'limits',lambda x:x.update(identity_input_identity='sha256-s3-identity-v1:'+digest(a['identity'])))


def refresh_network(a):
    net=a['network']; b=json.loads(net['binding_raw'])
    result=analyze_s3_access(authorization_raw=a['authorization'],**net)
    b['network_result_identity']=result['network_result_identity'];net['binding_raw']=enc(b)
    manifest(a,lambda m:(m['digests'].update(network_binding=digest(net['binding_raw'])),m.update(network_result_identity=b['network_result_identity'])))


def case(kind='role',principal_form='exact',identity_effect=None):
    a=args()
    def edit(x):
        req=x['request']; req['principal_arn']=req['principal_arn'].replace(':role/',f':{kind}/')
        p=req['principal_arn']; action=req['action']; resource=req['resource']
        principal={'AWS':p} if principal_form=='exact' else {'AWS':[p,'arn:aws:iam::123456789012:role/other']} if principal_form=='list' else '*' if principal_form=='wildcard' else {'AWS':'123456789012'} if principal_form=='account' else {'AWS':'arn:aws:sts::123456789012:assumed-role/demo-app/session'} if principal_form=='sts' else {'AWS':[p,'123456789012']}
        x['policies']['bucket']=[dict(Version='2012-10-17',Statement=[dict(Effect='Allow',Action=action,Resource=resource,Principal=principal)])]
        x['policies']['identity']=[] if identity_effect is None else [dict(Version='2012-10-17',Statement=[dict(Effect=identity_effect,Action=action,Resource=resource)])]
        if kind=='user': x['policies']['endpoint'][0]['Statement'][0]['Condition']['ArnEquals']['aws:PrincipalArn']=p
    rebind_auth(a,edit)
    auth=json.loads(a['authorization']); principal=auth['request']['principal_arn']
    def ident(x):
        for k in ('principal_before','principal_after'):
            x[k]['arn']=principal
            if kind=='user': x[k]['unique_id']='AIDASYNTHETICDEMO12345'
        if identity_effect is None: x.update(managed_policies=[],managed_arns_before=[],managed_arns_after=[])
        else: x['managed_policies'][0]['document']=auth['policies']['identity'][0]
    change(a,'identity',ident)
    if kind=='user':
        change(a,'limits',lambda x:x['session'].update(session_kind='IAM_USER'))
        change(a,'organization',lambda x:x.update(principal_kind='IAM_USER'))
        net=a['network']; ep=json.loads(net['endpoint_raw']); ep['VpcEndpoints'][0]['PolicyDocument']=json.dumps(auth['policies']['endpoint'][0]); net['endpoint_raw']=enc(ep)
        obs=json.loads(net['observation_raw']);obs['endpoint_input_identity']='sha256-vpc-endpoints-v1:'+digest(net['endpoint_raw']);net['observation_raw']=enc(obs)
        refresh_network(a)
    refresh_limits(a)
    return a


def set_limit(a,which,mode):
    # Present policies are tied to the exact principal attachment, version and request.
    flag='no_permissions_boundary' if which=='boundary' else 'no_session_policy'
    rebind_auth(a,lambda x:x['assertions'].update({flag:False}))
    req=json.loads(a['authorization'])['request']
    effect='Deny' if mode=='deny' else 'Allow'
    doc=dict(Version='2012-10-17',Statement=[dict(Effect=effect,Action='s3:ListBucket' if mode=='miss' else req['action'],Resource='*')])
    if which=='boundary':
        policy=copy.deepcopy(json.loads(raw('s3_unified_identity'))['managed_policies'][0]); policy.update(arn='arn:aws:iam::123456789012:policy/test-boundary',document=doc)
        change(a,'identity',lambda x:[x[k].update(permissions_boundary_arn=policy['arn']) for k in ('principal_before','principal_after')])
        change(a,'limits',lambda x:x['boundary'].update(state='PRESENT',policy=policy))
    else:
        change(a,'limits',lambda x:x['session'].update(state='PRESENT',inline_document=doc))
    if mode=='unknown':change(a,'limits',lambda x:x[which].update(complete=False))
    refresh_limits(a)


def run(a):
    r=analyze_s3_unified(**a)
    assert r['api_status']==r['authorization_status']==r['runtime_identity_status']=='UNKNOWN' and not r['live_observation']
    return r,r['components']['resource_grant']


@pytest.mark.parametrize('kind',['role','user'])
@pytest.mark.parametrize('form',['exact','list'])
def test_exact(kind,form):
    r,g=run(case(kind,form)); assert r['integrated_status']==PASS and r['grant_path']=='RESOURCE_POLICY' and not r['unresolved'];assert g['status']==ALLOW and g['ignored_implicit_limits']==['identity']


@pytest.mark.parametrize('kind',['role','user'])
@pytest.mark.parametrize('form',['wildcard','account','sts','mixed'])
def test_unsupported(kind,form):
    r,g=run(case(kind,form));assert r['integrated_status']=='UNKNOWN' and g['status']=='UNKNOWN'


@pytest.mark.parametrize('kind,mode,expected,integrated',[('role','allow',ALLOW,PASS),('role','miss',BLOCK,'UNKNOWN'),('role','deny',DENY,'UNKNOWN'),('role','unknown','UNKNOWN','UNKNOWN'),('user','allow',ALLOW,PASS),('user','miss',ALLOW,PASS),('user','deny',DENY,'UNKNOWN'),('user','unknown','UNKNOWN','UNKNOWN')])
def test_boundary(kind,mode,expected,integrated):
    a=case(kind);set_limit(a,'boundary',mode);r,g=run(a);assert g['status']==expected and r['integrated_status']==integrated
    assert ('boundary' in g['ignored_implicit_limits'])==(kind=='user' and mode=='miss')


@pytest.mark.parametrize('mode,expected,integrated',[('allow',ALLOW,PASS),('miss',BLOCK,'UNKNOWN'),('deny',DENY,'UNKNOWN'),('unknown','UNKNOWN','UNKNOWN')])
def test_session(mode,expected,integrated):
    a=case();set_limit(a,'session',mode);r,g=run(a);assert g['status']==expected and r['integrated_status']==integrated


@pytest.mark.parametrize('kind',['role','user'])
def test_identity_deny(kind):
    r,g=run(case(kind,identity_effect='Deny'));assert g['status']==DENY and r['integrated_status']=='UNKNOWN'


@pytest.mark.parametrize('kind',['role','user'])
def test_both_grants(kind):
    r,g=run(case(kind,identity_effect='Allow'));assert g['status']==ALLOW and r['integrated_status']==PASS and r['grant_path']=='IDENTITY'


def test_bucket_deny():
    a=case();rebind_auth(a,lambda x:x['policies']['bucket'][0]['Statement'].append(dict(x['policies']['bucket'][0]['Statement'][0],Effect='Deny')));r,g=run(a);assert g['status']==DENY and r['integrated_status']=='UNKNOWN'


@pytest.mark.parametrize('layer',['identity','bucket','endpoint'])
def test_incomplete_policy(layer):
    a=case();rebind_auth(a,lambda x:x['complete'].update({layer:False}));r,g=run(a);assert r['integrated_status']=='UNKNOWN' and g['status']=='UNKNOWN'


@pytest.mark.parametrize('key',['identity','limits','organization','encryption','acl'])
def test_missing_sidecar(key):
    a=case();drop(a,key);r,g=run(a);assert r['integrated_status']=='UNKNOWN'
    if key in ('identity','limits','organization'):assert g['status']=='UNKNOWN'


def test_unresolved_deny():
    a=case();rebind_auth(a,lambda x:x['policies']['bucket'][0]['Statement'].append(dict(x['policies']['bucket'][0]['Statement'][0],Effect='Deny',Condition={'NumericEquals':{'s3:max-keys':'1'}})));r,g=run(a);assert g['status']=='UNKNOWN' and r['integrated_status']=='UNKNOWN'


def test_manifest_tamper():
    a=case();a['authorization']+=b' ';r,g=run(a);assert g is None and r['integrated_status']=='UNKNOWN'


def test_wrong_network_binding():
    a=case();a['network']['binding_raw']=None;manifest(a,lambda m:(m['digests'].update(network_binding=None),m['observed_at'].update(network_binding=None)));r,g=run(a);assert g['status']==ALLOW and r['integrated_status']=='UNKNOWN'


def test_org_deny():
    a=case();rebind_auth(a,lambda x:x['assertions'].update(no_scp_rcp=False));org=json.loads(raw('iam_org_scp_deny'));org['authorization_input_identity']='sha256-s3-authz-v1:'+digest(a['authorization']);a['organization']=enc(org);manifest(a,lambda m:m['digests'].update(organization=digest(a['organization'])));r,g=run(a);assert g['status']==DENY and r['integrated_status']=='UNKNOWN'


def test_additional_service_restrictions():
    a=case();rebind_auth(a,lambda x:x['assertions'].update(no_additional_service_restrictions=False));r,g=run(a);assert g['status']==ALLOW and r['integrated_status']=='UNKNOWN'
