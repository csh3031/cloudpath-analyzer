import json
from pathlib import Path
import pytest
from backend.aws.s3_unified_evidence import analyze_s3_unified,digest
from backend.aws.s3_access_evidence import analyze_s3_access

D=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
def raw(n):return (D/(n+'.json')).read_bytes()
def enc(x):return json.dumps(x).encode()
def args():
    return dict(authorization=raw('s3_authz_allow'), **{k:raw('s3_unified_'+k) for k in ('identity','limits','organization','encryption','acl','manifest')},network=dict(inventory_raw=raw('gateway_path_ecs_inventory'),endpoint_raw=raw('s3_access_gateway_configuration'),observation_raw=raw('s3_access_gateway_observation'),binding_raw=raw('s3_access_allow_binding'),endpoint_id='vpce-22222222',endpoint_type='Gateway',source_kind='ec2',source_port=50000,client_ip='10.0.1.10',prefix_list_raw=raw('gateway_path_ecs_prefix_lists')))
def manifest(a,fn):
    m=json.loads(a['manifest']);fn(m);a['manifest']=enc(m)
def change(a,key,fn,rehash=True):
    x=json.loads(a[key]);fn(x);a[key]=enc(x)
    if rehash:manifest(a,lambda m:m['digests'].update({key:digest(a[key])}))
def drop(a,key):
    a[key]=None;manifest(a,lambda m:(m['digests'].update({key:None}),m['observed_at'].update({key:None})))
def rebind_auth(a,mutate):
    change(a,'authorization',mutate);aid='sha256-s3-authz-v1:'+digest(a['authorization'])
    for k in ('identity','limits','organization','encryption','acl'):
        change(a,k,lambda x:x.update(authorization_input_identity=aid))
    change(a,'limits',lambda x:x.update(identity_input_identity='sha256-s3-identity-v1:'+digest(a['identity'])))
    b=json.loads(a['network']['binding_raw']);b['authorization_input_identity']=aid;a['network']['binding_raw']=enc(b)
    manifest(a,lambda m:m['digests'].update(network_binding=digest(a['network']['binding_raw'])))

def test_allow():
    r=analyze_s3_unified(**args());assert r['integrated_status']=='CONDITIONAL_ACCESS_CANDIDATE' and not r['unresolved'];assert r['authorization_status']==r['api_status']==r['runtime_identity_status']=='UNKNOWN' and r['live_observation'] is False
    assert r['components']['identity']['identity_status']=='CORRELATED_CANDIDATE'

def test_missing_manifest():
    a=args();a['manifest']=None;r=analyze_s3_unified(**a);assert r['integrated_status']=='UNKNOWN' and r['evidence_reason']=='UNIFIED_MANIFEST_MISSING'

@pytest.mark.parametrize('key',['identity','limits','organization','encryption','acl'])
def test_missing_sidecar(key):
    a=args();drop(a,key);r=analyze_s3_unified(**a);assert r['integrated_status']=='UNKNOWN' and r['unresolved']

@pytest.mark.parametrize('key',['authorization','identity','limits','organization','encryption','acl'])
def test_bytes_tampered(key):
    a=args();a[key]+=b' ';r=analyze_s3_unified(**a);assert r['evidence_reason']=='INPUT_DIGEST_MISMATCH' and r['integrated_status']=='UNKNOWN'

@pytest.mark.parametrize('field,value,reason',[('same_hypothetical_request',False,'REQUEST_ASSERTION_MISSING'),('same_hypothetical_request',1,'REQUEST_ASSERTION_MISSING'),('network_result_identity','wrong','NETWORK_RESULT_IDENTITY_MISMATCH')])
def test_manifest(field,value,reason):
    a=args();manifest(a,lambda m:m.update({field:value}));assert analyze_s3_unified(**a)['evidence_reason']==reason

@pytest.mark.parametrize('t,reason',[(None,'EVIDENCE_TIME_MISSING'),('2026-11-25T10:54:59Z','EVIDENCE_TIME_SCOPE_UNCONFIRMED'),('2026-11-25T11:00:01Z','EVIDENCE_TIME_SCOPE_UNCONFIRMED')])
def test_time(t,reason):
    a=args();manifest(a,lambda m:m['observed_at'].update(acl=t));assert analyze_s3_unified(**a)['evidence_reason']==reason

def test_identity_time():
    a=args();manifest(a,lambda m:m['observed_at'].update(identity='2026-11-25T10:59:49Z'));assert analyze_s3_unified(**a)['evidence_reason']=='IAM_TIME_SCOPE_MISMATCH'

def test_network_time():
    a=args();manifest(a,lambda m:m['observed_at'].update(network_binding='2026-11-25T10:59:59Z'));assert analyze_s3_unified(**a)['evidence_reason']=='NETWORK_TIME_SCOPE_MISMATCH'

@pytest.mark.parametrize('key',['identity','limits','organization','encryption','acl'])
def test_mismatched_sidecar_even_with_new_manifest(key):
    a=args();change(a,key,lambda x:x.update(authorization_input_identity='wrong'));r=analyze_s3_unified(**a);assert r['integrated_status']=='UNKNOWN' and r['unresolved']

def test_no_network():
    a=args();a['network']=None;manifest(a,lambda m:(m.update(network_result_identity=None),m['digests'].update(network_binding=None),m['observed_at'].update(network_binding=None)));r=analyze_s3_unified(**a);assert r['integrated_status']=='UNKNOWN' and 'NETWORK_REQUEST_BINDING' in r['unresolved']

def test_network_unbound():
    a=args();a['network']['binding_raw']=None;manifest(a,lambda m:(m['digests'].update(network_binding=None),m['observed_at'].update(network_binding=None)));r=analyze_s3_unified(**a);assert r['integrated_status']=='UNKNOWN' and 'NETWORK_REQUEST_BINDING' in r['unresolved']

def test_boundary_unknown():
    a=args();change(a,'limits',lambda x:x['boundary'].update(complete=False));r=analyze_s3_unified(**a);assert r['integrated_status']=='UNKNOWN' and any(x['layer']=='boundary' and x['status']=='UNKNOWN' for x in r['independent_findings'])

def test_org_unknown():
    a=args();change(a,'organization',lambda x:x.update(scope_complete=False));r=analyze_s3_unified(**a);assert r['integrated_status']=='UNKNOWN' and 'ORGANIZATION_GUARDRAILS' in r['unresolved']

def test_acl_other_mode():
    a=args();change(a,'acl',lambda x:x['ownership'].update(mode='ObjectWriter'));r=analyze_s3_unified(**a);assert r['integrated_status']=='UNKNOWN' and 'OWNERSHIP_OR_ACL_SCOPE' in r['unresolved']

def test_kms_unknown():
    a=args();change(a,'encryption',lambda x:x['object'].update(metadata_complete=False));r=analyze_s3_unified(**a);assert r['integrated_status']=='UNKNOWN' and 'KMS_COMPOSITION_UNSUPPORTED_OR_UNKNOWN' in r['unresolved']

def test_cross_account():
    a=args();rebind_auth(a,lambda x:x['request'].update(bucket_account='222222222222'));r=analyze_s3_unified(**a);assert r['account_scope']=='CROSS_ACCOUNT' and r['integrated_status']=='UNKNOWN' and r['components']['cross_account'] is not None

def test_bucket_explicit_deny():
    a=args();rebind_auth(a,lambda x:x['policies']['bucket'][0]['Statement'][0].pop('Condition'));r=analyze_s3_unified(**a);assert r['integrated_status']=='UNKNOWN' and any(f['layer']=='bucket' and f['status']=='EXPLICIT_DENY' for f in r['independent_findings'])

def test_no_additional_scope():
    a=args();rebind_auth(a,lambda x:x['assertions'].update(no_additional_service_restrictions=False));r=analyze_s3_unified(**a);assert r['integrated_status']=='UNKNOWN' and 'ADDITIONAL_SERVICE_RESTRICTIONS' in r['unresolved']

def test_no_identity_grant_resource_grant():
    a=args()
    def edit(x):
        x['policies']['identity']=[]; x['policies']['bucket']=[{'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'AWS':x['request']['principal_arn']},'Action':'s3:GetObject','Resource':x['request']['resource']}]}]
    rebind_auth(a,edit);change(a,'identity',lambda x:x.update(managed_policies=[],managed_arns_before=[],managed_arns_after=[]));change(a,'limits',lambda x:x.update(identity_input_identity='sha256-s3-identity-v1:'+digest(a['identity'])));r=analyze_s3_unified(**a);assert r['integrated_status']=='CONDITIONAL_ACCESS_CANDIDATE' and r['grant_path']=='RESOURCE_POLICY' and r['components']['authorization']['authorization_status']=='ALLOW_CANDIDATE'

def test_bad_manifest():
    a=args();a['manifest']=b'{}'
    with pytest.raises(ValueError):analyze_s3_unified(**a)

def g2_fixture(a,mode):
    # Reuse the original raw G2 regression fixture and synchronize manifest.
    from test_aws_s3_access_evidence import case
    g=case(mode);auth=json.loads(g.pop('authorization_raw'))
    rebind_auth(a,lambda x:(x.clear(),x.update(auth)))
    # Preserve exact G2 authorization bytes; recompute binding for serialized input.
    a['network']=g
    b=json.loads(g['binding_raw']);b['authorization_input_identity']='sha256-s3-authz-v1:'+digest(a['authorization']);g['binding_raw']=enc(b)
    manifest(a,lambda m:(m['digests'].update(network_binding=digest(g['binding_raw'])),m.update(network_result_identity=b['network_result_identity'])))

@pytest.mark.parametrize('mode',['network_blocked','both_blocked','endpoint_implicit'])
def test_bound_path_block(mode):
    a=args();g2_fixture(a,mode);r=analyze_s3_unified(**a)
    expected='ENDPOINT_POLICY_BLOCK_CANDIDATE' if mode=='endpoint_implicit' else 'NETWORK_PATH_BLOCKED_CANDIDATE'
    assert r['integrated_status']==expected and r['api_status']=='UNKNOWN'
    if mode=='both_blocked':assert any(f['layer']=='bucket' and f['status']=='EXPLICIT_DENY' for f in r['independent_findings'])
