"""Prefix lists are evidence, not a guarantee of live traffic."""
import hashlib,json
from pathlib import Path
import pytest
from backend.aws.prefix_list_evidence import load_prefix_lists,match_prefix_list,FORMAT
from backend.aws.policy_evidence import _sg,evaluate_observed_policy
from backend.aws.session_evidence import analyze_observed_session
from backend.aws.ecs_session_evidence import analyze_ecs_task_session
from backend.aws.eks_session_evidence import analyze_eks_pod_session
from test_aws_direct_sg_reference import fixtures,A,B,rule
from test_aws_policy_evidence import setup
from test_aws_forwarding_evidence import SRC,DST
from test_aws_inventory import raw

P='pl-11111111'; T='2026-11-25T11:00:00+00:00'; REGION='ap-northeast-2'; ID='test-identity'
ROOT=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'

def wrap(entries=None,**updates):
    row=dict(id=P,kind='CUSTOMER_MANAGED',address_family='IPv4',state='create-complete',version_before=2,version_after=2,entries_version=2,complete=True,entries=['10.0.0.0/16'] if entries is None else entries)
    row.update(updates)
    return dict(format=FORMAT,inventory_identity=ID,region=REGION,collected_at=T,prefix_lists=[row])

def load(d,identity=ID,region=REGION,t=T,**kw):return load_prefix_lists(raw(d),identity,region,t,**kw)
def prefix_rule(**kw):return dict(IpProtocol='tcp',FromPort=443,ToPort=443,PrefixListIds=[{'PrefixListId':P}])|kw

@pytest.mark.parametrize('entries,expected',[(['10.0.2.0/24'],True),(['10.0.1.0/24'],False),([],False),(['0.0.0.0/0'],True),(['10.0.2.10/32'],True)])
def test_membership(entries,expected):
    lists,s=load(wrap(entries)); match,detail=match_prefix_list({'PrefixListId':P},lists,'10.0.2.10');assert match is expected and detail['prefix_list_version']==2 and s['live_observation'] is False

@pytest.mark.parametrize('change,reason',[
    ({'kind':'AWS_MANAGED'},'PREFIX_LIST_PROFILE_UNSUPPORTED'),({'address_family':'IPv6'},'PREFIX_LIST_PROFILE_UNSUPPORTED'),({'state':'modify-in-progress'},'PREFIX_LIST_STATE_UNCONFIRMED'),({'version_after':3},'PREFIX_LIST_VERSION_UNCONFIRMED'),({'entries_version':1},'PREFIX_LIST_VERSION_UNCONFIRMED'),({'version_before':True},'PREFIX_LIST_VERSION_UNCONFIRMED'),({'complete':False},'PREFIX_LIST_ENTRIES_INCOMPLETE'),({'entries':['10.0.0.1/24']},'PREFIX_LIST_CIDRS_INVALID'),({'entries':['::/0']},'PREFIX_LIST_CIDRS_INVALID'),({'entries':['10.0.0.0/16']*2},'PREFIX_LIST_CIDRS_INVALID'),({'entries':[2]},'PREFIX_LIST_CIDRS_INVALID')])
def test_unresolved(change,reason):
    lists,s=load(wrap(**change));match,detail=match_prefix_list({'PrefixListId':P},lists,'10.0.2.10');assert match is None and detail['reason']==reason

@pytest.mark.parametrize('field,value,reason',[('inventory_identity','other','PREFIX_LIST_INVENTORY_IDENTITY_MISMATCH'),('region','us-east-1','PREFIX_LIST_REGION_MISMATCH'),('collected_at','2026-11-25T11:05:01+00:00','PREFIX_LIST_SNAPSHOT_TIME_GAP')])
def test_scope(field,value,reason):
    d=wrap();d[field]=value;lists,s=load(d);assert s['reason']==reason and match_prefix_list({'PrefixListId':P},lists,'10.0.2.10')[0] is None

def test_full_time_window():
    d=wrap();d['collected_at']='2026-11-25T11:04:00+00:00';lists,s=load(d,additional_times=('2026-11-25T10:58:00+00:00',));assert s['time_gap_seconds']==360 and s['status']=='UNRESOLVED'

@pytest.mark.parametrize('case',['duplicate','invalid_id','bad_date','too_many_entries','bad_wrapper','nonlist','unknown_key'])
def test_malformed(case):
    d=wrap()
    if case=='duplicate':d['prefix_lists']*=2
    elif case=='invalid_id':d['prefix_lists'][0]['id']='invalid'
    elif case=='bad_date':d['collected_at']='2026-11-25T11:00:00'
    elif case=='too_many_entries':d['prefix_lists'][0]['entries']=['10.0.0.0/16']*1001
    elif case=='bad_wrapper':d['format']='other'
    elif case=='nonlist':d['prefix_lists']={}
    else:d['prefix_lists'][0]['extra']=1
    with pytest.raises(ValueError):load(d)

@pytest.mark.parametrize('egress',[True,False])
@pytest.mark.parametrize('case,expected',[('match','ALLOW_CANDIDATE'),('miss','BLOCKED'),('missing','UNKNOWN'),('incomplete','UNKNOWN'),('union','ALLOW_CANDIDATE'),('wrong_port','BLOCKED'),('wrong_protocol','BLOCKED'),('unknown_port','UNKNOWN')])
def test_sg(egress,case,expected):
    g,a,b=fixtures();rs=[prefix_rule()];d=wrap()
    if case=='miss':d=wrap(['192.0.2.0/24'])
    elif case=='missing':d['prefix_lists']=[]
    elif case=='incomplete':d=wrap(complete=False)
    elif case=='union':d=wrap(complete=False);rs.append(rule(B))
    elif case=='wrong_port':rs=[prefix_rule(FromPort=80,ToPort=80)]
    elif case=='wrong_protocol':rs=[prefix_rule(IpProtocol='udp')]
    elif case=='unknown_port':rs=[prefix_rule(FromPort=None)]
    g[A]['IpPermissionsEgress' if egress else 'IpPermissions']=rs;lists,_=load(d)
    r=_sg(g,a,b,egress,443,direct_same_vpc=True,prefix_lists=lists);assert r['status']==expected
    if case=='match':assert r['reason']=='MATCHING_IPV4_PREFIX_LIST_RULE' and r['matched_cidr']=='10.0.0.0/16'

def evidence(inv,entries=None,**kw):
    d=wrap(entries,**kw); meta=json.loads(inv);d.update(inventory_identity='sha256-aws-'+('v2' if meta['format'].endswith('v2') else 'v1')+':'+hashlib.sha256(inv).hexdigest(),region=meta['region'],collected_at=meta['collected_at']);return raw(d)

@pytest.mark.parametrize('entries,expected',[(['10.0.0.0/16'],'ALLOW_CANDIDATE'),(['192.0.2.0/24'],'BLOCKED')])
def test_ec2(entries,expected):
    d=setup();d['inventory']['SecurityGroups'][0]['IpPermissions']=[prefix_rule()];inv=raw(d);pl=evidence(inv,entries)
    r=evaluate_observed_policy(inv,SRC,DST,50000,443,prefix_list_raw=pl);assert r['request']['checks'][-1]['status']==expected and r['response']['checks'][0]['status']=='CONDITIONAL'
    s=analyze_observed_session(inv,SRC,DST,50000,443,prefix_list_raw=pl);assert s['predicted_connectivity']==('BLOCKED' if expected=='BLOCKED' else 'UNKNOWN')

def test_ecs():
    d=json.loads((ROOT/'ecs_task_inventory.json').read_bytes());d['inventory']['SecurityGroups'][0]['IpPermissions']=[prefix_rule()];inv=raw(d)
    r=analyze_ecs_task_session(inv,(ROOT/'ecs_task_evidence.json').read_bytes(),'1'*32,'2'*32,50000,443,prefix_list_raw=evidence(inv));assert r['request_status']=='CONDITIONAL_CANDIDATE' and r['request'][-1]['reason']=='MATCHING_IPV4_PREFIX_LIST_RULE' and r['session_status']=='UNKNOWN'

def test_eks():
    d=json.loads((ROOT/'eks_pod_inventory.json').read_bytes());d['inventory']['SecurityGroups'][0]['IpPermissions']=[prefix_rule()];inv=raw(d)
    eks=json.loads((ROOT/'eks_policy_pods.json').read_bytes());eks['inventory_identity']='sha256-aws-v2:'+hashlib.sha256(inv).hexdigest();er=raw(eks)
    policy=json.loads((ROOT/'eks_network_policy_evidence.json').read_bytes());policy['eks_input_identity']='sha256-eks-pod-v1:'+hashlib.sha256(er).hexdigest()
    r=analyze_eks_pod_session(inv,er,raw(policy),'demo','app-1','demo','app-2',50000,443,prefix_list_raw=evidence(inv));assert r['request_status']=='CONDITIONAL_CANDIDATE' and next(x for x in r['request'] if x['stage']=='DESTINATION_SG_INGRESS')['reason']=='MATCHING_IPV4_PREFIX_LIST_RULE' and r['session_status']=='UNKNOWN'
