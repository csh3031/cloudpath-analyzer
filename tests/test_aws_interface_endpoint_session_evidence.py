import hashlib,json
from pathlib import Path
import pytest
from backend.aws.interface_endpoint_session_evidence import analyze_interface_endpoint_session
from backend.aws.peering_evidence import _load

ROOT=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
def read(name):return (ROOT/(name+'.json')).read_bytes()
def enc(v):return json.dumps(v).encode()
def data(mode):
    base='eks' if mode=='eks' else 'ecs'
    inv=read('interface_path_'+base+'_inventory');cfg=read('interface_path_'+base+'_configuration');obs=read('interface_path_'+mode+'_observation')
    kw={'client_ip':'10.0.1.10'} if mode=='ec2' else {'ecs_raw':read('ecs_task_evidence'),'task_id':'2'*32} if mode=='ecs' else {'eks_raw':read('interface_path_eks_pods'),'policy_raw':read('interface_path_eks_policy'),'namespace':'demo','pod_name':'app-2'}
    return inv,cfg,obs,kw

def run(mode,*,obs_change=None,inv_change=None,policy_change=None,cfg_change=None,missing=False,source_port=50000,endpoint_id='vpce-11111111',prefix=None):
    inv,cfg,obs,kw=data(mode);o=json.loads(obs);d=json.loads(cfg)
    if inv_change:
        i=json.loads(inv);inv_change(i['inventory']);inv=enc(i);identity,_,_=_load(inv);d['inventory_identity']=identity;o['inventory_identity']=identity
        if mode=='eks':
            x=json.loads(kw['eks_raw']);x['inventory_identity']=identity;kw['eks_raw']=enc(x);p=json.loads(kw['policy_raw']);p['eks_input_identity']='sha256-eks-pod-v1:'+hashlib.sha256(kw['eks_raw']).hexdigest();kw['policy_raw']=enc(p)
    if cfg_change: cfg_change(d['VpcEndpoints'][0])
    if cfg_change or inv_change:
        cfg=enc(d);o['endpoint_input_identity']='sha256-vpc-endpoints-v1:'+hashlib.sha256(cfg).hexdigest()
    if obs_change:o.update(obs_change)
    if policy_change:
        p=json.loads(kw['policy_raw']);policy_change(p);kw['policy_raw']=enc(p)
    if prefix is not None:
        identity,meta,_=_load(inv);kw['prefix_list_raw']=enc(dict(format='cloudpath-aws-prefix-lists-v1',inventory_identity=identity,region=meta['region'],collected_at=meta['collected_at'],prefix_lists=[dict(id='pl-11111111',kind='CUSTOMER_MANAGED',address_family='IPv4',state='create-complete',version_before=2,version_after=2,entries_version=2,complete=True,entries=[prefix])]))
    return analyze_interface_endpoint_session(inv,cfg,None if missing else enc(o),endpoint_id,mode,source_port,**kw)

def stage(r,name,direction='request'):return next(x for x in r[direction] if x['stage']==name)

@pytest.mark.parametrize('mode',['ec2','ecs','eks'])
def test_allowed(mode):
    r=run(mode);assert r['request_status']==r['response_status']=='CONDITIONAL_CANDIDATE';assert r['session_status']=='UNKNOWN' and r['authorization_status']==r['endpoint_policy_status']==r['tls_status']=='NOT_EVALUATED' and r['live_observation'] is False
    assert r['destination_endpoint']['private_ip']=='10.0.1.90' and r['destination_endpoint']['port']==443
    assert stage(r,'DESTINATION_SG_INGRESS')['reason']=='MATCHING_DIRECT_PEER_SG_REFERENCE'
    assert stage(r,'SOURCE_NACL_EGRESS')['status']==('NOT_APPLICABLE' if mode=='ec2' else 'ALLOW_CANDIDATE')

@pytest.mark.parametrize('field,value,reason',[
 ('inventory_identity','bad','ENDPOINT_PATH_EVIDENCE_IDENTITY_MISMATCH'),('endpoint_input_identity','bad','ENDPOINT_PATH_EVIDENCE_IDENTITY_MISMATCH'),('endpoint_id','vpce-22222222','ENDPOINT_PATH_EVIDENCE_IDENTITY_MISMATCH'),('source_ip','10.0.2.60','ENDPOINT_PATH_EVIDENCE_IDENTITY_MISMATCH'),('source_eni_id','eni-aaaaaaaa','ENDPOINT_PATH_EVIDENCE_IDENTITY_MISMATCH'),('complete',False,'ENDPOINT_PATH_PROFILE_UNCONFIRMED'),('resolver_scope','OTHER','ENDPOINT_PATH_PROFILE_UNCONFIRMED'),('direct_private_ipv4_no_translation',False,'ENDPOINT_PATH_PROFILE_UNCONFIRMED'),('hostname','s3.ap-northeast-2.amazonaws.com','ENDPOINT_EXPLICIT_DNS_NAME_UNCONFIRMED'),('hostname','a.b.vpce-11111111-example.s3.ap-northeast-2.vpce.amazonaws.com','ENDPOINT_EXPLICIT_DNS_NAME_UNCONFIRMED'),('hostname','*.vpce-11111111-example.s3.ap-northeast-2.vpce.amazonaws.com','ENDPOINT_EXPLICIT_DNS_NAME_UNCONFIRMED'),('answers',[],'ENDPOINT_DNS_SINGLE_IPV4_UNCONFIRMED'),('answers',['10.0.1.90','10.0.2.90'],'ENDPOINT_DNS_SINGLE_IPV4_UNCONFIRMED'),('answers',['::1'],'ENDPOINT_DNS_SINGLE_IPV4_UNCONFIRMED'),('answers',['10.0.2.90'],'ENDPOINT_DNS_ENI_MISMATCH'),('eni_id','eni-aaaaaaaa','ENDPOINT_DNS_ENI_MISMATCH'),('ttl_seconds',0,'ENDPOINT_DNS_TIME_SCOPE_UNCONFIRMED'),('ttl_seconds',True,'ENDPOINT_DNS_TIME_SCOPE_UNCONFIRMED'),('resolved_at','2026-11-25T11:00:01+00:00','ENDPOINT_DNS_TIME_SCOPE_UNCONFIRMED'),('resolved_at','2026-11-25T10:59:00+00:00','ENDPOINT_DNS_TIME_SCOPE_UNCONFIRMED'),('collected_at','2026-11-25T11:06:00+00:00','SNAPSHOT_TIME_GAP')])
def test_observation_unknown(field,value,reason):
    r=run('ec2',obs_change={field:value});assert r['status']=='UNKNOWN' and r['reason']==reason and r['destination_endpoint'] is None and r['session_status']=='UNKNOWN'
    assert r['first_request_stop']=='ENDPOINT_SCOPE' and r['response_status']=='NOT_EVALUATED'

def test_missing():assert run('ec2',missing=True)['reason']=='ENDPOINT_DNS_ENI_EVIDENCE_MISSING'
def test_missing_endpoint():assert run('ec2',endpoint_id='vpce-aaaaaaaa')['reason']=='ENDPOINT_CONFIGURATION_UNCONFIRMED'

def test_gateway():
    r=analyze_interface_endpoint_session(read('vpc_endpoint_inventory'),read('vpc_endpoint_configuration'),None,'vpce-22222222','ec2',50000,client_ip='10.0.1.10');assert r['reason']=='INTERFACE_ENDPOINT_REQUIRED'

@pytest.mark.parametrize('mode',['ec2','ecs','eks'])
def test_sg_block(mode):
    r=run(mode,inv_change=lambda i:i['SecurityGroups'][-1].update(IpPermissions=[]));assert r['first_request_stop']=='DESTINATION_SG_INGRESS' and r['session_status']=='BLOCKED' and r['response_status']=='NOT_EVALUATED';assert all(x['evaluation_mode']=='INDEPENDENT_CHECK' for x in r['response'])

@pytest.mark.parametrize('peer,status',[
 ({'ipBlock':{'cidr':'10.0.1.0/24','except':['10.0.1.90/32']}},'BLOCKED'),({'ipBlock':{'cidr':'10.0.2.0/24'}},'BLOCKED'),({'podSelector':{}},'BLOCKED'),({'ipBlock':{'cidr':'bad'}},'UNKNOWN'),({},'CONDITIONAL_CANDIDATE')])
def test_external_policy(peer,status):
    def change(p):p['networkPolicies'][-1]['spec']['egress'][0]['to']=[peer]
    r=run('eks',policy_change=change);assert r['request_status']==status
    if status!='CONDITIONAL_CANDIDATE':assert r['first_request_stop']=='SOURCE_NETWORK_POLICY_EGRESS' and r['response_status']=='NOT_EVALUATED' and stage(r,'DESTINATION_SG_INGRESS')['evaluation_mode']=='INDEPENDENT_CHECK'

def test_policy_profile():assert run('eks',policy_change=lambda p:p.update(complete=False))['request_status']=='UNKNOWN'

def test_return_nacl_block():
    def change(i):i['NetworkAcls'][0]['Entries'].append(dict(RuleNumber=50,Protocol='6',RuleAction='deny',Egress=True,CidrBlock='10.0.2.0/24',PortRange={'From':50000,'To':50000}))
    r=run('ecs',inv_change=change);assert r['request_status']=='CONDITIONAL_CANDIDATE' and r['response_status']=='BLOCKED' and r['conditional_first_response_stop']=='SOURCE_NACL_EGRESS' and r['session_status']=='UNKNOWN'

@pytest.mark.parametrize('prefix,status',[('10.0.2.0/24','CONDITIONAL_CANDIDATE'),('10.0.3.0/24','BLOCKED'),(None,'UNKNOWN')])
def test_prefix_lists(prefix,status):
    def change(i):i['SecurityGroups'][-1]['IpPermissions']=[{'IpProtocol':'tcp','FromPort':443,'ToPort':443,'PrefixListIds':[{'PrefixListId':'pl-11111111'}]}]
    assert run('ecs',inv_change=change,prefix=prefix)['request_status']==status

def test_route_prefix_unknown():
    def change(i):i['RouteTables'][0]['Routes'].append(dict(DestinationPrefixListId='pl-11111111',GatewayId='vpce-22222222',State='active'))
    r=run('ecs',inv_change=change);assert r['request_status']=='UNKNOWN' and r['session_status']=='UNKNOWN'

def test_alternate_eni():
    r=run('ec2',obs_change={'answers':['10.0.2.90'],'eni_id':'eni-99999992'});assert r['path_kind']=='CROSS_SUBNET_DIRECT' and r['request_status']=='CONDITIONAL_CANDIDATE'

def test_exact_dns():
    host='vpce-11111111-example.s3.ap-northeast-2.vpce.amazonaws.com'
    r=run('ec2',obs_change={'hostname':host},cfg_change=lambda x:x['DnsEntries'][0].update(DnsName=host));assert r['request_status']=='CONDITIONAL_CANDIDATE'

def test_wrong_endpoint_dns_name():
    host='vpce-22222222-example.s3.ap-northeast-2.vpce.amazonaws.com'
    assert run('ec2',obs_change={'hostname':host},cfg_change=lambda x:x['DnsEntries'][0].update(DnsName=host))['reason']=='ENDPOINT_EXPLICIT_DNS_NAME_UNCONFIRMED'

def test_bad_port():
    with pytest.raises(ValueError):run('ecs',source_port=True)
