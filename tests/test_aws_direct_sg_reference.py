"""Static direct peer membership, not a transitive allow or live verdict."""
import hashlib
import json
from pathlib import Path
import pytest
from backend.aws.policy_evidence import _sg
from backend.aws.ecs_session_evidence import analyze_ecs_task_session
from backend.aws.eks_session_evidence import analyze_eks_pod_session
from test_aws_policy_evidence import setup, run
from test_aws_inventory import G, S
from test_aws_forwarding_evidence import explicit

A,B,C='sg-11111111','sg-22222222','sg-33333333'
V='vpc-12345678'

def rule(ref=B, **kwargs):
    return dict(IpProtocol='tcp',FromPort=443,ToPort=443,UserIdGroupPairs=[{'GroupId':ref}]) | kwargs

def fixtures():
    groups={g:dict(GroupId=g,VpcId=V,IpPermissions=[],IpPermissionsEgress=[]) for g in (A,B,C)}
    a=dict(security_group_ids=[A],eni_id='eni-11111111',private_ip='10.0.1.10')
    b=dict(security_group_ids=[B],eni_id='eni-22222222',private_ip='10.0.2.10')
    return groups,a,b

@pytest.mark.parametrize('egress',[True,False])
def test_direct_match(egress):
    g,a,b=fixtures();g[A]['IpPermissionsEgress' if egress else 'IpPermissions']=[rule()]
    r=_sg(g,a,b,egress,443,direct_same_vpc=True)
    assert r['status']=='ALLOW_CANDIDATE' and r['referenced_group_id']==B and r['peer_eni_id']==b['eni_id']

@pytest.mark.parametrize('ref,expected',[(C,'BLOCKED'),('sg-aaaaaaaa','UNKNOWN'),(A,'BLOCKED'),(B,'ALLOW_CANDIDATE')])
def test_reference_membership(ref,expected):
    g,a,b=fixtures();g[A]['IpPermissions']=[rule(ref)]
    assert _sg(g,a,b,False,443,direct_same_vpc=True)['status']==expected

@pytest.mark.parametrize('case',['no_direct','missing_membership','unknown_peer_group','different_vpc','same_eni','duplicate_peer_group','foreign_reference_metadata'])
def test_uncertain(case):
    g,a,b=fixtures();g[A]['IpPermissions']=[rule()];direct=True
    if case=='no_direct':direct=False
    elif case=='missing_membership':b.pop('security_group_ids')
    elif case=='unknown_peer_group':b['security_group_ids'].append('sg-aaaaaaaa')
    elif case=='different_vpc':g[B]['VpcId']='vpc-87654321'
    elif case=='same_eni':b['eni_id']=a['eni_id']
    elif case=='duplicate_peer_group':b['security_group_ids'].append(B)
    else:g[A]['IpPermissions'][0]['UserIdGroupPairs'][0]['VpcPeeringConnectionId']='pcx-12345678'
    assert _sg(g,a,b,False,443,direct_same_vpc=direct)['status']=='UNKNOWN'

@pytest.mark.parametrize('proto,lo,hi,port,expected',[('udp',443,443,443,'BLOCKED'),('tcp',443,443,80,'BLOCKED'),('-1',None,None,80,'ALLOW_CANDIDATE'),('6',440,450,443,'ALLOW_CANDIDATE'),('tcp',None,None,443,'UNKNOWN'),('unknown',443,443,443,'UNKNOWN')])
def test_protocol_ports(proto,lo,hi,port,expected):
    g,a,b=fixtures();g[A]['IpPermissions']=[rule(IpProtocol=proto,FromPort=lo,ToPort=hi)]
    assert _sg(g,a,b,False,port,direct_same_vpc=True)['status']==expected

@pytest.mark.parametrize('explicit_rule,expected',[(True,'ALLOW_CANDIDATE'),(False,'BLOCKED')])
def test_self_reference(explicit_rule,expected):
    g,a,b=fixtures();b['security_group_ids']=[A];g[A]['IpPermissions']=[rule(A)] if explicit_rule else []
    assert _sg(g,a,b,False,443,direct_same_vpc=True)['status']==expected

@pytest.mark.parametrize('kind',['cidr','reference','missing_prefix','transitive'])
def test_union(kind):
    g,a,b=fixtures();g[A]['IpPermissions']=[rule('sg-aaaaaaaa')]
    if kind=='cidr':g[A]['IpPermissions'].append(dict(IpProtocol='-1',IpRanges=[{'CidrIp':'10.0.0.0/16'}]))
    elif kind=='reference':g[A]['IpPermissions'].append(rule(B))
    elif kind=='missing_prefix':g[A]['IpPermissions']=[dict(IpProtocol='-1',PrefixListIds=[{'PrefixListId':'pl-11111111'}])]
    else:g[A]['IpPermissions']=[rule(C)];g[C]['IpPermissions']=[rule(B)]
    assert _sg(g,a,b,False,443,direct_same_vpc=True)['status']=={'cidr':'ALLOW_CANDIDATE','reference':'ALLOW_CANDIDATE','missing_prefix':'UNKNOWN','transitive':'BLOCKED'}[kind]

@pytest.mark.parametrize('blackhole',[False,True])
def test_ec2_integration(blackhole):
    d=setup();sg=d['inventory']['SecurityGroups'][0];sg['IpPermissions']=[rule(G)];sg['IpPermissionsEgress']=[rule(G)]
    if blackhole:explicit(d,S)['Routes'][0]['State']='blackhole'
    r=run(d);expected='UNKNOWN' if blackhole else 'ALLOW_CANDIDATE'
    assert r['request']['checks'][0]['status']==r['request']['checks'][-1]['status']==expected

ROOT=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'

def test_ecs_integration():
    inv=json.loads((ROOT/'ecs_task_inventory.json').read_bytes());sg=inv['inventory']['SecurityGroups'][0];sg['IpPermissions']=[rule(sg['GroupId'])]
    r=analyze_ecs_task_session(json.dumps(inv).encode(),(ROOT/'ecs_task_evidence.json').read_bytes(),'1'*32,'2'*32,50000,443)
    assert r['request_status']=='CONDITIONAL_CANDIDATE' and r['request'][-1]['reason']=='MATCHING_DIRECT_PEER_SG_REFERENCE' and r['session_status']=='UNKNOWN'

def test_eks_integration():
    inv=json.loads((ROOT/'eks_pod_inventory.json').read_bytes());sg=inv['inventory']['SecurityGroups'][0];sg['IpPermissions']=[rule(sg['GroupId'])]
    inv_raw=json.dumps(inv).encode(); eks=json.loads((ROOT/'eks_policy_pods.json').read_bytes()); eks['inventory_identity']='sha256-aws-v2:'+hashlib.sha256(inv_raw).hexdigest()
    eks_raw=json.dumps(eks).encode(); policy=json.loads((ROOT/'eks_network_policy_evidence.json').read_bytes()); policy['eks_input_identity']='sha256-eks-pod-v1:'+hashlib.sha256(eks_raw).hexdigest()
    r=analyze_eks_pod_session(inv_raw,eks_raw,json.dumps(policy).encode(),'demo','app-1','demo','app-2',50000,443)
    assert r['request_status']=='CONDITIONAL_CANDIDATE' and next(x for x in r['request'] if x['stage']=='DESTINATION_SG_INGRESS')['reason']=='MATCHING_DIRECT_PEER_SG_REFERENCE' and r['session_status']=='UNKNOWN'
