"""Offline Gateway TCP constraints and opt-in prefix route priority."""
import hashlib,json
from ipaddress import IPv4Address
from pathlib import Path
import pytest
from backend.aws.gateway_endpoint_session_evidence import analyze_gateway_endpoint_session
from backend.aws.prefix_list_evidence import load_prefix_lists,match_prefix_list
from backend.aws.route_evidence import select_subnet_ipv4_route
from backend.aws.interface_endpoint_session_evidence import analyze_interface_endpoint_session
from backend.aws.peering_evidence import _load
from test_aws_interface_endpoint_session_evidence import data as interface_data

ROOT=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
def read(n):return (ROOT/(n+'.json')).read_bytes()
def enc(v):return json.dumps(v).encode()
def data(mode):
    base='eks' if mode=='eks' else 'ecs'
    inv=read('gateway_path_'+base+'_inventory');cfg=read('gateway_path_'+base+'_configuration');obs=read('gateway_path_'+mode+'_observation');pl=read('gateway_path_'+base+'_prefix_lists')
    kw={'client_ip':'10.0.1.10'} if mode=='ec2' else {'ecs_raw':read('ecs_task_evidence'),'task_id':'2'*32} if mode=='ecs' else {'eks_raw':read('gateway_path_eks_pods'),'policy_raw':read('gateway_path_eks_policy'),'namespace':'demo','pod_name':'app-2'}
    return inv,cfg,obs,pl,kw

def run(mode='ec2',*,obs_change=None,inv_change=None,pl_change=None,cfg_change=None,policy_change=None,missing=False,missing_pl=False):
    inv,cfg,obs,pl,kw=data(mode);o=json.loads(obs);d=json.loads(cfg);p=json.loads(pl)
    if inv_change:
        i=json.loads(inv);inv_change(i['inventory']);inv=enc(i);identity,_,_=_load(inv);d['inventory_identity']=identity;o['inventory_identity']=identity;p['inventory_identity']=identity
        if mode=='eks':
            e=json.loads(kw['eks_raw']);e['inventory_identity']=identity;kw['eks_raw']=enc(e);n=json.loads(kw['policy_raw']);n['eks_input_identity']='sha256-eks-pod-v1:'+hashlib.sha256(kw['eks_raw']).hexdigest();kw['policy_raw']=enc(n)
    if cfg_change:cfg_change(d['VpcEndpoints'][0])
    if cfg_change or inv_change:
        cfg=enc(d);o['endpoint_input_identity']='sha256-vpc-endpoints-v1:'+hashlib.sha256(cfg).hexdigest()
    if obs_change:o.update(obs_change)
    if pl_change:pl_change(p)
    if policy_change:
        n=json.loads(kw['policy_raw']);policy_change(n);kw['policy_raw']=enc(n)
    return analyze_gateway_endpoint_session(inv,cfg,None if missing else enc(o),'vpce-22222222',mode,50000,prefix_list_raw=None if missing_pl else enc(p),**kw)

def stage(r,name,direction='request'):return next(x for x in r[direction] if x['stage']==name)

@pytest.mark.parametrize('mode',['ec2','ecs','eks'])
def test_allowed(mode):
    r=run(mode);assert r['request_status']==r['response_status']=='CONDITIONAL_CANDIDATE';assert r['session_status']=='UNKNOWN' and r['authorization_status']==r['endpoint_policy_status']==r['tls_status']=='NOT_EVALUATED' and r['live_observation'] is False
    assert r['destination_endpoint']['eni_id'] is None and 'security_group_ids' not in r['destination_endpoint']
    assert r['path_kind']=='GATEWAY_ENDPOINT' and r['route_selection']['matched_cidr']=='198.51.100.0/24'
    assert stage(r,'SOURCE_SG_EGRESS')['prefix_list_version'] is None and stage(r,'SOURCE_SG_EGRESS')['prefix_list_kind']=='AWS_MANAGED'
    assert not any(x['stage']=='DESTINATION_SG_INGRESS' for x in r['request'])

@pytest.mark.parametrize('field,value,reason',[
 ('inventory_identity','bad','ENDPOINT_PATH_EVIDENCE_IDENTITY_MISMATCH'),('endpoint_input_identity','bad','ENDPOINT_PATH_EVIDENCE_IDENTITY_MISMATCH'),('endpoint_id','vpce-11111111','ENDPOINT_PATH_EVIDENCE_IDENTITY_MISMATCH'),('source_ip','10.0.2.60','ENDPOINT_PATH_EVIDENCE_IDENTITY_MISMATCH'),('source_eni_id','eni-aaaaaaaa','ENDPOINT_PATH_EVIDENCE_IDENTITY_MISMATCH'),('complete',False,'GATEWAY_PATH_PROFILE_UNCONFIRMED'),('resolver_scope','OTHER','GATEWAY_PATH_PROFILE_UNCONFIRMED'),('direct_ipv4_no_translation',False,'GATEWAY_PATH_PROFILE_UNCONFIRMED'),('hostname','s3.us-east-1.amazonaws.com','GATEWAY_REGIONAL_DNS_NAME_UNCONFIRMED'),('hostname','bucket.s3.ap-northeast-2.amazonaws.com','GATEWAY_REGIONAL_DNS_NAME_UNCONFIRMED'),('answers',[],'ENDPOINT_DNS_SINGLE_IPV4_UNCONFIRMED'),('answers',['198.51.100.80','198.51.100.81'],'ENDPOINT_DNS_SINGLE_IPV4_UNCONFIRMED'),('answers',['::1'],'ENDPOINT_DNS_SINGLE_IPV4_UNCONFIRMED'),('answers',['10.0.1.90'],'GATEWAY_EXTERNAL_SERVICE_ADDRESS_REQUIRED'),('answers',['198.51.101.80'],'GATEWAY_DNS_ADDRESS_NOT_IN_SERVICE_PREFIX_LIST'),('ttl_seconds',0,'ENDPOINT_DNS_TIME_SCOPE_UNCONFIRMED'),('resolved_at','2026-11-25T10:59:00+00:00','ENDPOINT_DNS_TIME_SCOPE_UNCONFIRMED'),('collected_at','2026-11-25T11:06:00+00:00','SNAPSHOT_TIME_GAP')])
def test_dns_uncertainty(field,value,reason):
    r=run(obs_change={field:value});assert r['status']=='UNKNOWN' and r['reason']==reason and r['session_status']=='UNKNOWN' and r['response_status']=='NOT_EVALUATED'

@pytest.mark.parametrize('field,value', [('owner_id','123456789012'),('name','com.amazonaws.ap-northeast-2.dynamodb'),('name','com.amazonaws.us-east-1.s3'),('entries_confirmed',False),('complete',False),('entries',[]),('entries',['198.51.100.1/24']),('state','modify-in-progress'),('address_family','IPv6')])
def test_service_prefix_unconfirmed(field,value):
    r=run(pl_change=lambda p:p['prefix_lists'][0].update({field:value}));assert r['status']=='UNKNOWN' and r['reason']=='GATEWAY_SERVICE_PREFIX_LIST_UNCONFIRMED'

def test_missing_dns():assert run(missing=True)['reason']=='GATEWAY_DNS_EVIDENCE_MISSING'
def test_missing_prefix():assert run(missing_pl=True)['reason']=='GATEWAY_SERVICE_PREFIX_LIST_UNCONFIRMED'
def test_prefix_time():assert run(pl_change=lambda p:p.update(collected_at='2026-11-25T11:01:00+00:00'))['reason']=='ENDPOINT_DNS_TIME_SCOPE_UNCONFIRMED'

@pytest.mark.parametrize('mode',['ec2','ecs','eks'])
def test_sg_block(mode):
    r=run(mode,inv_change=lambda i:i['SecurityGroups'][0].update(IpPermissionsEgress=[]));assert r['first_request_stop']=='SOURCE_SG_EGRESS' and r['session_status']=='BLOCKED';assert stage(r,'GATEWAY_ROUTE')['evaluation_mode']=='INDEPENDENT_CHECK' and r['response_status']=='NOT_EVALUATED'

def test_eks_policy():
    r=run('eks',policy_change=lambda p:p['networkPolicies'][-1]['spec']['egress'][0]['to'][0]['ipBlock'].update(except_=['198.51.100.80/32']))
    assert r['request_status']=='UNKNOWN' # invalid field is not a recognized policy
    r=run('eks',policy_change=lambda p:p['networkPolicies'][-1]['spec']['egress'][0]['to'][0]['ipBlock'].update({'except':['198.51.100.80/32']}))
    assert r['request_status']=='BLOCKED' and r['first_request_stop']=='SOURCE_NETWORK_POLICY_EGRESS'

def test_reverse_block():
    def change(i):i['NetworkAcls'][0]['Entries'].append(dict(RuleNumber=50,Protocol='6',RuleAction='deny',Egress=False,CidrBlock='198.51.100.0/24',PortRange={'From':50000,'To':50000}))
    r=run(inv_change=change);assert r['request_status']=='CONDITIONAL_CANDIDATE' and r['response_status']=='BLOCKED' and r['conditional_first_response_stop']=='DESTINATION_NACL_INGRESS' and r['session_status']=='UNKNOWN'

@pytest.mark.parametrize('cidr,origin,state,target,expected,reason',[
 ('198.51.100.80/32','CreateRoute','active','nat','UNKNOWN','ALTERNATE_ROUTE_NOT_COMPOSED'),('198.51.100.0/24','CreateRoute','active','nat','UNKNOWN','ALTERNATE_ROUTE_NOT_COMPOSED'),('198.51.100.0/24','EnableVgwRoutePropagation','active','vgw','CONDITIONAL_CANDIDATE','MATCHING_GATEWAY_ENDPOINT_ROUTE'),('198.51.100.80/32','CreateRoute','blackhole','nat','BLOCKED','SELECTED_ROUTE_BLACKHOLE'),('198.51.0.0/16','CreateRoute','active','nat','CONDITIONAL_CANDIDATE','MATCHING_GATEWAY_ENDPOINT_ROUTE'),('198.51.100.0/24',None,'active','nat','UNKNOWN','EQUAL_PREFIX_ROUTE_PRIORITY_UNSUPPORTED')])
def test_route_priority(cidr,origin,state,target,expected,reason):
    def change(i):
        r=dict(DestinationCidrBlock=cidr,State=state);r['NatGatewayId' if target=='nat' else 'GatewayId']='nat-12345678' if target=='nat' else 'vgw-12345678'
        if origin:r['Origin']=origin
        i['RouteTables'][1]['Routes'].append(r)
    r=run(inv_change=change);assert r['request_status']==expected and stage(r,'GATEWAY_ROUTE')['reason']==reason
    if expected!='CONDITIONAL_CANDIDATE':assert r['response_status']=='NOT_EVALUATED'

@pytest.mark.parametrize('present,overlap,expected',[(False,False,'PREFIX_LIST_ROUTE_EVIDENCE_UNRESOLVED'),(True,True,'OVERLAPPING_PREFIX_LIST_ROUTE_PRIORITY_UNCONFIRMED'),(True,False,'MATCHING_GATEWAY_ENDPOINT_ROUTE')])
def test_competing_prefix(present,overlap,expected):
    def change(i):i['RouteTables'][1]['Routes'].append(dict(DestinationPrefixListId='pl-22222222',NatGatewayId='nat-12345678',State='active'))
    def pl(p):
        if present:p['prefix_lists'].append(dict(id='pl-22222222',kind='CUSTOMER_MANAGED',address_family='IPv4',state='create-complete',version_before=1,version_after=1,entries_version=1,complete=True,entries=['198.51.100.0/25' if overlap else '192.0.2.0/24']))
    assert stage(run(inv_change=change,pl_change=pl),'GATEWAY_ROUTE')['reason']==expected

def test_interface_coexistence():
    inv,cfg,obs,kw=interface_data('ec2');i=json.loads(inv);c=json.loads(cfg);o=json.loads(obs)
    for t in i['inventory']['RouteTables']:t['Routes'].append(dict(DestinationPrefixListId='pl-11111111',GatewayId='vpce-22222222',State='active'))
    inv=enc(i);identity,meta,_=_load(inv);c['inventory_identity']=identity;cfg=enc(c);o.update(inventory_identity=identity,endpoint_input_identity='sha256-vpc-endpoints-v1:'+hashlib.sha256(cfg).hexdigest())
    p=json.loads(read('gateway_path_ecs_prefix_lists'));p['inventory_identity']=identity
    r=analyze_interface_endpoint_session(inv,cfg,enc(o),'vpce-11111111','ec2',50000,prefix_list_raw=enc(p),**kw);assert r['request_status']=='CONDITIONAL_CANDIDATE' and r['response_status']=='CONDITIONAL_CANDIDATE'

def test_dynamodb_regional():
    def cfg(c):c['ServiceName']='com.amazonaws.ap-northeast-2.dynamodb'
    def pl(p):p['prefix_lists'][0]['name']='com.amazonaws.ap-northeast-2.dynamodb'
    r=run(cfg_change=cfg,pl_change=pl,obs_change={'hostname':'dynamodb.ap-northeast-2.amazonaws.com'})
    assert r['request_status']==r['response_status']=='CONDITIONAL_CANDIDATE'
    assert r['destination_endpoint']['service_name']=='com.amazonaws.ap-northeast-2.dynamodb'

def test_unassociated_gateway():
    def inv(i):i['RouteTables'][1]['Routes']=[r for r in i['RouteTables'][1]['Routes'] if 'DestinationPrefixListId' not in r]
    r=run(inv_change=inv,cfg_change=lambda c:c.update(RouteTableIds=['rtb-12345678']))
    assert r['request_status']=='UNKNOWN' and stage(r,'GATEWAY_ROUTE')['reason']=='ALTERNATE_ROUTE_NOT_COMPOSED'
    assert r['route_selection']['selected_route']['NatGatewayId']=='nat-12345678'

def test_propagation_unconfirmed():
    r=run(inv_change=lambda i:i['RouteTables'][1].update(PropagatingVgws=[{'GatewayId':'vgw-12345678'}]))
    assert r['request_status']=='UNKNOWN' and stage(r,'GATEWAY_ROUTE')['reason']=='GATEWAY_ROUTE_PROPAGATION_UNCONFIRMED'

def test_prefix_scope_mismatch():
    r=run(pl_change=lambda p:p.update(inventory_identity='different'))
    assert r['reason']=='GATEWAY_SERVICE_PREFIX_LIST_UNCONFIRMED' and r['prefix_list_evidence']['status']=='UNRESOLVED'
