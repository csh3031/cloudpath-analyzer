"""S3 composition retains separate raw outcomes and refuses unrelated evidence."""
import hashlib
import json
from pathlib import Path
import pytest
from backend.aws.s3_access_evidence import analyze_s3_access, network_result_identity
from backend.aws.peering_evidence import _load

D=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
def raw(name): return (D/(name+'.json')).read_bytes()
def enc(doc): return json.dumps(doc).encode()
def case(mode='allow'):
    interface=mode in ('interface_allow','network_blocked','both_blocked')
    alt=mode=='alternate'
    base='interface' if interface else 'alternate' if alt else 'implicit' if mode=='endpoint_implicit' else 'gateway'
    name='s3_access_interface_deny' if mode=='both_blocked' else 's3_access_interface_allow' if interface else 's3_authz_'+('allow' if alt else 'unknown' if mode=='auth_unknown' else mode)
    args=dict(inventory_raw=raw('interface_path_eks_inventory' if interface else 'gateway_alternate_inventory' if alt else 'gateway_path_ecs_inventory'),endpoint_raw=raw('s3_access_'+base+'_configuration'),observation_raw=raw('s3_access_'+base+'_observation'),authorization_raw=raw(name),binding_raw=raw('s3_access_'+mode+'_binding'),endpoint_id='vpce-11111111' if interface else 'vpce-22222222',endpoint_type='Interface' if interface else 'Gateway',source_kind='eks' if interface else 'ec2',source_port=50000)
    if interface: args.update(eks_raw=raw('interface_path_eks_pods'),policy_raw=raw('interface_path_eks_policy'+('_blocked' if mode!='interface_allow' else '')),namespace='demo',pod_name='app-2')
    else: args.update(client_ip='10.0.1.10',prefix_list_raw=raw('gateway_alternate_prefix_lists' if alt else 'gateway_path_ecs_prefix_lists'))
    return args

def rebind(args,**changes):
    r=analyze_s3_access(**dict(args,binding_raw=None))
    b=dict(schema='cloudpath-s3-access-binding-v1',network_result_identity=r['network_result_identity'],authorization_input_identity=r['authorization']['input_identity'],collected_at='2026-11-25T11:00:00+00:00',same_hypothetical_request=True)
    b.update(changes);args['binding_raw']=enc(b)
    return analyze_s3_access(**args)

def cfg_change(args,fn):
    c=json.loads(args['endpoint_raw']);fn(c['VpcEndpoints'][0]);args['endpoint_raw']=enc(c)
    o=json.loads(args['observation_raw']);o['endpoint_input_identity']='sha256-vpc-endpoints-v1:'+hashlib.sha256(args['endpoint_raw']).hexdigest();args['observation_raw']=enc(o)

def inv_change(args,fn):
    i=json.loads(args['inventory_raw']);fn(i['inventory']);args['inventory_raw']=enc(i);identity,_,_=_load(args['inventory_raw'])
    c=json.loads(args['endpoint_raw']);c['inventory_identity']=identity;args['endpoint_raw']=enc(c)
    o=json.loads(args['observation_raw']);o.update(inventory_identity=identity,endpoint_input_identity='sha256-vpc-endpoints-v1:'+hashlib.sha256(args['endpoint_raw']).hexdigest());args['observation_raw']=enc(o)
    p=json.loads(args['prefix_list_raw']);p['inventory_identity']=identity;args['prefix_list_raw']=enc(p)

@pytest.mark.parametrize('mode,net,auth,access,stop',[
 ('allow','CONDITIONAL_CANDIDATE','ALLOW_CANDIDATE','CONDITIONAL_ACCESS_CANDIDATE',None),
 ('bucket_deny','CONDITIONAL_CANDIDATE','EXPLICIT_DENY','AUTHORIZATION_DENY','AUTHORIZATION'),
 ('endpoint_implicit','CONDITIONAL_CANDIDATE','IMPLICIT_DENY_CANDIDATE','AUTHORIZATION_DENY_CANDIDATE','AUTHORIZATION'),
 ('auth_unknown','CONDITIONAL_CANDIDATE','UNKNOWN','UNKNOWN','AUTHORIZATION'),
 ('alternate','UNKNOWN','ALLOW_CANDIDATE','UNKNOWN','GATEWAY_ROUTE'),
 ('network_blocked','BLOCKED','ALLOW_CANDIDATE','NETWORK_BLOCKED','SOURCE_NETWORK_POLICY_EGRESS'),
 ('both_blocked','BLOCKED','EXPLICIT_DENY','NETWORK_BLOCKED','SOURCE_NETWORK_POLICY_EGRESS'),
 ('interface_allow','CONDITIONAL_CANDIDATE','ALLOW_CANDIDATE','CONDITIONAL_ACCESS_CANDIDATE',None)])
def test_samples(mode,net,auth,access,stop):
    r=analyze_s3_access(**case(mode));assert (r['network_status'],r['authorization_status'],r['access_status'],r['first_stop'])==(net,auth,access,stop)
    assert r['api_status']=='UNKNOWN' and r['authentication_status']==r['tls_status']=='NOT_EVALUATED' and r['live_observation'] is False
    assert r['network']['authorization_status']=='NOT_EVALUATED' and r['authorization']['network_status']=='NOT_EVALUATED'
    assert r['independent_denial_layers']==(['bucket'] if mode=='both_blocked' else [])
    assert r['authorization_evaluation_mode']==('CONDITIONAL_CHECK' if net=='CONDITIONAL_CANDIDATE' else 'INDEPENDENT_CHECK')
    assert r['binding_status']==('UNKNOWN' if mode=='alternate' else 'CORRELATED_CANDIDATE')

@pytest.mark.parametrize('field,value,reason',[
 ('network_result_identity','wrong','S3_REQUEST_BINDING_IDENTITY_MISMATCH'),('authorization_input_identity','wrong','S3_REQUEST_BINDING_IDENTITY_MISMATCH'),('same_hypothetical_request',False,'S3_REQUEST_BINDING_UNCONFIRMED'),('same_hypothetical_request',1,'S3_REQUEST_BINDING_UNCONFIRMED'),('collected_at','2026-11-25T11:01:00+00:00','S3_REQUEST_BINDING_TIME_SCOPE_UNCONFIRMED'),('collected_at','2026-11-25T10:59:59+00:00','S3_REQUEST_BINDING_TIME_SCOPE_UNCONFIRMED')])
def test_binding(field,value,reason):
    args=case();b=json.loads(args['binding_raw']);b[field]=value;args['binding_raw']=enc(b);r=analyze_s3_access(**args);assert r['access_status']=='UNKNOWN' and r['binding_reason']==reason and r['correlated_authorization_status']=='UNKNOWN'

@pytest.mark.parametrize('value',[None,False])
def test_https(value):
    args=case();a=json.loads(args['authorization_raw']);a['request']['secure_transport']=value;args['authorization_raw']=enc(a);r=rebind(args);assert r['binding_reason']=='S3_HTTPS_CONTEXT_UNCONFIRMED' and r['access_status']=='UNKNOWN'

@pytest.mark.parametrize('field,value',[('endpoint_id','vpce-11111111'),('endpoint_type','Interface'),('vpc_id','vpc-aaaaaaaa')])
def test_request_scope(field,value):
    args=case();a=json.loads(args['authorization_raw']);a['request'][field]=value;args['authorization_raw']=enc(a);r=rebind(args);assert r['binding_reason']=='S3_REQUEST_ENDPOINT_CONTEXT_MISMATCH' and r['access_status']=='UNKNOWN'

@pytest.mark.parametrize('value,reason',[(None,'S3_ENDPOINT_POLICY_SNAPSHOT_UNCONFIRMED'),('{}','S3_ENDPOINT_POLICY_SNAPSHOT_UNCONFIRMED'),('bad','S3_ENDPOINT_POLICY_SNAPSHOT_UNCONFIRMED'),('{"Version":"2012-10-17","Statement":[]}','S3_ENDPOINT_POLICY_SNAPSHOT_MISMATCH'),('{"Version":"2012-10-17","Version":"2012-10-17"}','S3_ENDPOINT_POLICY_SNAPSHOT_UNCONFIRMED')])
def test_snapshot_policy(value,reason):
    args=case();cfg_change(args,lambda c:c.update(PolicyDocument=value));r=rebind(args);assert r['network_status']=='CONDITIONAL_CANDIDATE' and r['access_status']=='UNKNOWN' and r['binding_reason']==reason

@pytest.mark.parametrize('count',[0,2])
def test_endpoint_document_count(count):
    args=case();a=json.loads(args['authorization_raw']);a['policies']['endpoint']*=count;args['authorization_raw']=enc(a);r=rebind(args);assert r['binding_reason']=='S3_ENDPOINT_POLICY_SNAPSHOT_MISMATCH'

def test_missing_binding():
    r=analyze_s3_access(**dict(case(),binding_raw=None));assert r['access_status']=='UNKNOWN' and r['binding_reason']=='S3_REQUEST_BINDING_MISSING'

def test_policy_object_semantically_equal():
    args=case();cfg_change(args,lambda c:c.update(PolicyDocument=json.loads(c['PolicyDocument'])));assert rebind(args)['access_status']=='CONDITIONAL_ACCESS_CANDIDATE'

def test_replayed_binding_different_authorization():
    r=analyze_s3_access(**dict(case(),authorization_raw=raw('s3_authz_bucket_deny')));assert r['access_status']=='UNKNOWN' and r['authorization_status']=='EXPLICIT_DENY' and r['binding_reason']=='S3_REQUEST_BINDING_IDENTITY_MISMATCH'

def test_replayed_binding_different_source_port():
    r=analyze_s3_access(**dict(case(),source_port=50001));assert r['binding_reason']=='S3_REQUEST_BINDING_IDENTITY_MISMATCH'

def test_missing_observation():
    args=case();args['observation_raw']=None;r=rebind(args);assert r['binding_reason']=='S3_NETWORK_DESTINATION_UNCONFIRMED' and r['access_status']=='UNKNOWN'

def test_missing_prefix():
    args=case();args['prefix_list_raw']=None;r=rebind(args);assert r['binding_reason']=='S3_NETWORK_DESTINATION_UNCONFIRMED' and r['access_status']=='UNKNOWN'

def test_cross_account():
    args=case();a=json.loads(args['authorization_raw']);a['request']['bucket_account']='111111111111';args['authorization_raw']=enc(a);r=rebind(args);assert r['authorization_status']=='UNKNOWN' and r['access_status']=='UNKNOWN'

def test_network_block_without_binding():
    r=analyze_s3_access(**dict(case('both_blocked'),binding_raw=None));assert r['access_status']=='NETWORK_BLOCKED' and r['independent_denial_layers']==[] and r['authorization_status']=='EXPLICIT_DENY'

def test_response_block():
    args=case();inv_change(args,lambda i:i['NetworkAcls'][0]['Entries'].append(dict(RuleNumber=50,Protocol='6',RuleAction='deny',Egress=False,CidrBlock='198.51.100.0/24',PortRange={'From':50000,'To':50000})))
    r=rebind(args);assert r['access_status']=='CONDITIONAL_RESPONSE_BLOCKED' and r['first_stop']=='DESTINATION_NACL_INGRESS' and r['authorization_evaluation_mode']=='INDEPENDENT_CHECK'

def test_ecs():
    args=case();o=json.loads(raw('gateway_path_ecs_observation'));o['endpoint_input_identity']='sha256-vpc-endpoints-v1:'+hashlib.sha256(args['endpoint_raw']).hexdigest();args.update(source_kind='ecs',observation_raw=enc(o),ecs_raw=raw('ecs_task_evidence'),task_id='2'*32);args.pop('client_ip');assert rebind(args)['access_status']=='CONDITIONAL_ACCESS_CANDIDATE'

def test_non_s3():
    args=case();cfg_change(args,lambda c:c.update(ServiceName='com.amazonaws.ap-northeast-2.dynamodb'));o=json.loads(args['observation_raw']);o['hostname']='dynamodb.ap-northeast-2.amazonaws.com';args['observation_raw']=enc(o);p=json.loads(args['prefix_list_raw']);p['prefix_lists'][0]['name']='com.amazonaws.ap-northeast-2.dynamodb';args['prefix_list_raw']=enc(p);r=rebind(args);assert r['network_status']=='CONDITIONAL_CANDIDATE' and r['binding_reason']=='S3_ENDPOINT_SCOPE_UNCONFIRMED'

@pytest.mark.parametrize('bad',[b'{}',b'{"schema":1,"schema":2}',b'x'*16385,b'[]'])
def test_invalid_binding(bad):
    with pytest.raises(ValueError): analyze_s3_access(**dict(case(),binding_raw=bad))

def test_raw_policy_not_exposed():
    r=analyze_s3_access(**case());assert 'PolicyDocument' not in json.dumps(r) and 'Statement' not in json.dumps(r)

def test_result_identity_stable():
    r=analyze_s3_access(**case());assert r['network_result_identity']==network_result_identity(dict(reversed(list(r['network'].items()))))
