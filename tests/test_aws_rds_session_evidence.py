import hashlib,json
from pathlib import Path
import pytest
from backend.aws.rds_session_evidence import analyze_rds_session
from backend.aws.peering_evidence import _load
from backend.aws.eks_session_evidence import peer_match

ROOT=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
def read(name):return (ROOT/(name+'.json')).read_bytes()
def enc(v):return json.dumps(v).encode()
def data(mode):
    base='eks' if mode=='eks' else 'ecs'
    inv=read('rds_path_'+base+'_inventory');rds=read('rds_path_'+base+'_configuration');obs=read('rds_path_'+mode+'_observation')
    kw={'client_ip':'10.0.1.10'} if mode=='ec2' else {'ecs_raw':read('ecs_task_evidence'),'task_id':'2'*32} if mode=='ecs' else {'eks_raw':read('rds_path_eks_pods'),'policy_raw':read('rds_path_eks_policy'),'namespace':'demo','pod_name':'app-2'}
    return inv,rds,obs,kw

def run(mode,*,obs_change=None,inv_change=None,policy_change=None,missing=False,source_port=50000):
    inv,rds,obs,kw=data(mode);o=json.loads(obs)
    if inv_change:
        i=json.loads(inv);inv_change(i['inventory']);inv=enc(i);identity,_,_=_load(inv)
        d=json.loads(rds);d['inventory_identity']=identity;rds=enc(d);o['inventory_identity']=identity;o['rds_input_identity']='sha256-rds-config-v1:'+hashlib.sha256(rds).hexdigest()
        if mode=='eks':
            x=json.loads(kw['eks_raw']);x['inventory_identity']=identity;kw['eks_raw']=enc(x);p=json.loads(kw['policy_raw']);p['eks_input_identity']='sha256-eks-pod-v1:'+hashlib.sha256(kw['eks_raw']).hexdigest();kw['policy_raw']=enc(p)
    if obs_change:o.update(obs_change)
    if policy_change:
        p=json.loads(kw['policy_raw']);policy_change(p);kw['policy_raw']=enc(p)
    return analyze_rds_session(inv,rds,None if missing else enc(o),'demo-mysql',mode,source_port,**kw)

def stage(r,name,direction='request'):return next(x for x in r[direction] if x['stage']==name)

@pytest.mark.parametrize('mode',['ec2','ecs','eks'])
def test_allowed(mode):
    r=run(mode);assert r['request_status']==r['response_status']=='CONDITIONAL_CANDIDATE';assert r['session_status']=='UNKNOWN' and r['authentication_status']==r['tls_status']=='NOT_EVALUATED' and r['live_observation'] is False
    assert r['destination_endpoint']['private_ip']=='10.0.1.80' and r['destination_endpoint']['port']==3306
    assert stage(r,'DESTINATION_SG_INGRESS')['reason']=='MATCHING_DIRECT_PEER_SG_REFERENCE'
    assert stage(r,'SOURCE_NACL_EGRESS')['status']==('NOT_APPLICABLE' if mode=='ec2' else 'ALLOW_CANDIDATE')
    assert r['rds_configuration']['endpoints'][0]['ip'] is None

@pytest.mark.parametrize('field,value,reason',[
 ('inventory_identity','bad','RDS_PATH_EVIDENCE_IDENTITY_MISMATCH'),('rds_input_identity','bad','RDS_PATH_EVIDENCE_IDENTITY_MISMATCH'),('identifier','other','RDS_PATH_EVIDENCE_IDENTITY_MISMATCH'),('hostname','wrong.example.rds.amazonaws.com','RDS_PATH_EVIDENCE_IDENTITY_MISMATCH'),('source_ip','10.0.2.60','RDS_PATH_EVIDENCE_IDENTITY_MISMATCH'),('source_eni_id','eni-aaaaaaaa','RDS_PATH_EVIDENCE_IDENTITY_MISMATCH'),('complete',False,'RDS_PATH_PROFILE_UNCONFIRMED'),('resolver_scope','OTHER','RDS_PATH_PROFILE_UNCONFIRMED'),('direct_private_ipv4_no_translation',False,'RDS_PATH_PROFILE_UNCONFIRMED'),('answers',[],'RDS_DNS_SINGLE_IPV4_UNCONFIRMED'),('answers',['10.0.1.80','10.0.1.81'],'RDS_DNS_SINGLE_IPV4_UNCONFIRMED'),('answers',['::1'],'RDS_DNS_SINGLE_IPV4_UNCONFIRMED'),('answers',['10.0.1.81'],'RDS_ENI_IP_OWNER_UNCONFIRMED'),('eni_id','eni-aaaaaaaa','RDS_ENI_IP_OWNER_UNCONFIRMED'),('ttl_seconds',0,'RDS_DNS_TIME_SCOPE_UNCONFIRMED'),('ttl_seconds',True,'RDS_DNS_TIME_SCOPE_UNCONFIRMED'),('resolved_at','2026-11-25T11:00:01+00:00','RDS_DNS_TIME_SCOPE_UNCONFIRMED'),('resolved_at','2026-11-25T10:59:00+00:00','RDS_DNS_TIME_SCOPE_UNCONFIRMED'),('collected_at','2026-11-25T11:06:00+00:00','SNAPSHOT_TIME_GAP')])
def test_observation_unknown(field,value,reason):
    r=run('ec2',obs_change={field:value});assert r['status']=='UNKNOWN' and r['reason']==reason and r['destination_endpoint'] is None and r['session_status']=='UNKNOWN'

def test_missing():assert run('ec2',missing=True)['reason']=='RDS_DNS_ENI_EVIDENCE_MISSING'

@pytest.mark.parametrize('field,value,reason',[
 ('RequesterManaged',False,'RDS_ENI_PROFILE_UNCONFIRMED'),('Status','available','RDS_ENI_PROFILE_UNCONFIRMED'),('InterfaceType','network_load_balancer','RDS_ENI_PROFILE_UNCONFIRMED'),('Groups',[{'GroupId':'sg-12345678'}],'RDS_ENI_CONFIGURATION_CONFLICT'),('Attachment',{'InstanceId':'i-87654321','DeviceIndex':2},'RDS_ENI_PROFILE_UNCONFIRMED')])
def test_eni(field,value,reason):
    r=run('ec2',inv_change=lambda i:i['NetworkInterfaces'][-1].update({field:value}));assert r['reason']==reason

@pytest.mark.parametrize('mode',['ec2','ecs','eks'])
def test_sg_block(mode):
    r=run(mode,inv_change=lambda i:i['SecurityGroups'][-1].update(IpPermissions=[]));assert r['first_request_stop']=='DESTINATION_SG_INGRESS' and r['session_status']=='BLOCKED' and r['response_status']=='NOT_EVALUATED';assert all(x['evaluation_mode']=='INDEPENDENT_CHECK' for x in r['response'])

@pytest.mark.parametrize('peer,status',[
 ({'ipBlock':{'cidr':'10.0.1.0/24','except':['10.0.1.80/32']}},'BLOCKED'),({'ipBlock':{'cidr':'10.0.2.0/24'}},'BLOCKED'),({'podSelector':{}},'BLOCKED'),({'namespaceSelector':{}},'BLOCKED'),({'ipBlock':{'cidr':'bad'}},'UNKNOWN'),({'ipBlock':{'cidr':'10.0.1.0/24','except':['10.0.2.0/24']}},'UNKNOWN'),({},'CONDITIONAL_CANDIDATE')])
def test_external_policy(peer,status):
    def change(p):p['networkPolicies'][-1]['spec']['egress'][0]['to']=[peer]
    r=run('eks',policy_change=change);assert r['request_status']==status
    if status!='CONDITIONAL_CANDIDATE':
        assert r['first_request_stop']=='SOURCE_NETWORK_POLICY_EGRESS' and r['response_status']=='NOT_EVALUATED';assert stage(r,'DESTINATION_SG_INGRESS')['evaluation_mode']=='INDEPENDENT_CHECK'

def test_old_ipblock_still_unknown():assert peer_match({'ipBlock':{'cidr':'10.0.1.0/24'}},None,{},'demo') is None

def test_policy_profile():assert run('eks',policy_change=lambda p:p.update(complete=False))['first_request_stop']=='SOURCE_NETWORK_POLICY_EGRESS'

def test_return_nacl_block():
    def change(i):i['NetworkAcls'][0]['Entries'].append(dict(RuleNumber=50,Protocol='6',RuleAction='deny',Egress=True,CidrBlock='10.0.2.0/24',PortRange={'From':50000,'To':50000}))
    r=run('ecs',inv_change=change);assert r['request_status']=='CONDITIONAL_CANDIDATE' and r['response_status']=='BLOCKED' and r['conditional_first_response_stop']=='SOURCE_NACL_EGRESS' and r['session_status']=='UNKNOWN'

def test_bad_port():
    with pytest.raises(ValueError):run('ecs',source_port=True)

@pytest.mark.parametrize('mode',['ecs','eks'])
def test_competing_workload_claim(mode):
    inv,rds,obs,kw=data(mode)
    if mode=='ecs':
        d=json.loads(kw['ecs_raw']);d['tasks'][0]['attachments'][0]['details'].append({'name':'networkInterfaceId','value':'eni-99999999'});kw['ecs_raw']=enc(d)
    else:
        d=json.loads(kw['eks_raw']);d['pods'][0]['status']['podIP']='10.0.1.80';kw['eks_raw']=enc(d)
    r=analyze_rds_session(inv,rds,obs,'demo-mysql',mode,50000,**kw);assert r['reason']=='RDS_ENI_OWNERSHIP_CONFLICT'

@pytest.mark.parametrize('provided,match,status',[(True,True,'CONDITIONAL_CANDIDATE'),(True,False,'BLOCKED'),(False,False,'UNKNOWN')])
def test_prefix_lists(provided,match,status):
    inv,rds,obs,kw=data('ecs');i=json.loads(inv);i['inventory']['SecurityGroups'][-1]['IpPermissions']=[{'IpProtocol':'tcp','FromPort':3306,'ToPort':3306,'PrefixListIds':[{'PrefixListId':'pl-11111111'}]}];inv=enc(i);identity,_,_=_load(inv)
    d=json.loads(rds);d['inventory_identity']=identity;rds=enc(d);o=json.loads(obs);o.update(inventory_identity=identity,rds_input_identity='sha256-rds-config-v1:'+hashlib.sha256(rds).hexdigest())
    p=dict(format='cloudpath-aws-prefix-lists-v1',inventory_identity=identity,region=i['region'],collected_at=i['collected_at'],prefix_lists=[dict(id='pl-11111111',kind='CUSTOMER_MANAGED',address_family='IPv4',state='create-complete',version_before=2,version_after=2,entries_version=2,complete=True,entries=['10.0.2.0/24' if match else '10.0.3.0/24'])])
    r=analyze_rds_session(inv,rds,enc(o),'demo-mysql','ecs',50000,prefix_list_raw=enc(p) if provided else None,**kw);assert r['request_status']==status


def test_same_subnet_unusual_route():
    def change(i):i['RouteTables'][1]['Routes'].append(dict(DestinationCidrBlock='10.0.1.80/32',NetworkInterfaceId='eni-12345678',State='active'))
    r=run('ec2',inv_change=change);assert r['request_status']=='UNKNOWN' and r['session_status']=='UNKNOWN'
