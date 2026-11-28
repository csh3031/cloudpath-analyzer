import json
from pathlib import Path
import pytest
from backend.aws.rds_evidence import inspect_rds_configuration

ROOT=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
@pytest.fixture
def data():
    return (ROOT/'ecs_task_inventory.json').read_bytes(),json.loads((ROOT/'rds_configuration.json').read_text())

def run(data,kind='instance',name='demo-mysql'):
    raw,d=data
    return inspect_rds_configuration(raw,json.dumps(d).encode(),kind,name)

@pytest.mark.parametrize('kind,name,ports',[('instance','demo-mysql',[3306]),('instance','demo-writer',[5432]),('instance','demo-reader',[5432]),('cluster','demo-aurora',[5432,5432])])
def test_candidate(data,kind,name,ports):
    r=run(data,kind,name)
    assert r['status']=='RDS_CONFIGURATION_CANDIDATE'
    assert [e['port'] for e in r['endpoints']]==ports
    assert all(e['ip'] is None and e['eni_id'] is None for e in r['endpoints'])
    assert r['session_status']=='UNKNOWN' and r['live_observation'] is False
    assert all(r[k]=='NOT_EVALUATED' for k in ('dns_status','route_status','policy_status','authentication_status'))
    assert '000000000000' not in json.dumps(r)
    if kind=='cluster':assert [m['role'] for m in r['members']]==['WRITER','READER']
    if name=='demo-mysql':assert r['configuration']['multi_az'] is True

@pytest.mark.parametrize('key,value,reason',[('inventory_identity','bad','RDS_INVENTORY_SCOPE_MISMATCH'),('region','us-east-1','RDS_INVENTORY_SCOPE_MISMATCH'),('complete',False,'RDS_EVIDENCE_INCOMPLETE'),('collected_at','2026-11-25T11:05:01+00:00','SNAPSHOT_TIME_GAP')])
def test_scope(data,key,value,reason):
    data[1][key]=value; assert run(data)['reason']==reason

@pytest.mark.parametrize('key,value,reason',[
 ('DBInstanceArn','arn:aws:rds:ap-northeast-2:111111111111:db:demo-mysql','RDS_INSTANCE_SCOPE_MISMATCH'),('DBInstanceStatus','creating','RDS_INSTANCE_STATE_UNCONFIRMED'),('PubliclyAccessible',True,'RDS_NETWORK_PROFILE_UNSUPPORTED'),('NetworkType','DUAL','RDS_NETWORK_PROFILE_UNSUPPORTED'),('Engine','custom-oracle','RDS_ENGINE_UNSUPPORTED'),('DBSubnetGroup',None,'RDS_SUBNET_GROUP_UNCONFIRMED'),('AvailabilityZone','ap-northeast-2b','RDS_AZ_UNCONFIRMED'),('VpcSecurityGroups',[],'RDS_SECURITY_GROUPS_UNCONFIRMED'),('VpcSecurityGroups',[{'VpcSecurityGroupId':'sg-aaaaaaaa','Status':'active'}],'RDS_SECURITY_GROUPS_UNCONFIRMED'),('Endpoint',None,'RDS_ENDPOINT_UNCONFIRMED'),('Endpoint',{'Address':'127.0.0.1','Port':3306},'RDS_ENDPOINT_UNCONFIRMED'),('Endpoint',{'Address':'demo.example.rds.amazonaws.com','Port':True},'RDS_ENDPOINT_UNCONFIRMED'),('MultiAZ',None,'RDS_DEPLOYMENT_UNCONFIRMED'),('DBClusterIdentifier','missing','RDS_CLUSTER_UNCONFIRMED')])
def test_instance_unknown(data,key,value,reason):
    data[1]['DBInstances'][0][key]=value; r=run(data);assert r['status']=='UNKNOWN' and r['reason']==reason and r['endpoints']==[]

@pytest.mark.parametrize('key,value,reason',[('Status','modifying','RDS_CLUSTER_STATE_UNCONFIRMED'),('EngineMode','serverless','RDS_CLUSTER_PROFILE_UNSUPPORTED'),('GlobalClusterIdentifier','global','RDS_CLUSTER_PROFILE_UNSUPPORTED'),('ServerlessV2ScalingConfiguration',{'MinCapacity':1},'RDS_CLUSTER_PROFILE_UNSUPPORTED'),('Endpoint','invalid','RDS_ENDPOINT_UNCONFIRMED'),('ReaderEndpoint','demo-aurora.cluster-example.ap-northeast-2.rds.amazonaws.com','RDS_ENDPOINT_UNCONFIRMED'),('DBClusterMembers',[],'RDS_CLUSTER_MEMBERS_UNCONFIRMED'),('DBClusterMembers',[{'DBInstanceIdentifier':'demo-writer','IsClusterWriter':False},{'DBInstanceIdentifier':'demo-reader','IsClusterWriter':False}],'RDS_CLUSTER_MEMBERS_UNCONFIRMED')])
def test_cluster_unknown(data,key,value,reason):
    data[1]['DBClusters'][0][key]=value;assert run(data,'cluster','demo-aurora')['reason']==reason

@pytest.mark.parametrize('mutation,reason',[('group_vpc','RDS_SUBNET_GROUP_UNCONFIRMED'),('subnet_az','RDS_SUBNET_GROUP_UNCONFIRMED'),('embedded_group','RDS_SUBNET_GROUP_CONFLICT'),('member_cluster','RDS_CLUSTER_MEMBER_CONFLICT'),('member_port','RDS_CLUSTER_MEMBER_CONFLICT'),('missing_member','RDS_CLUSTER_MEMBERS_UNCONFIRMED')])
def test_correlations(data,mutation,reason):
    d=data[1];kind,name='instance','demo-mysql'
    if mutation=='group_vpc':d['DBSubnetGroups'][0]['VpcId']='vpc-aaaaaaaa'
    elif mutation=='subnet_az':d['DBSubnetGroups'][0]['Subnets'][0]['SubnetAvailabilityZone']['Name']='ap-northeast-2b'
    elif mutation=='embedded_group':d['DBInstances'][0]['DBSubnetGroup']['Subnets'].pop()
    else:
        kind,name='cluster','demo-aurora'
        if mutation=='member_cluster':d['DBInstances'][2]['DBClusterIdentifier']='other'
        elif mutation=='member_port':d['DBInstances'][2]['Endpoint']['Port']=3306
        else:d['DBInstances'].pop()
    assert run(data,kind,name)['reason']==reason

@pytest.mark.parametrize('collection',['DBInstances','DBClusters','DBSubnetGroups'])
def test_duplicate(data,collection):
    data[1][collection].append(data[1][collection][0]);
    with pytest.raises(ValueError):run(data)

def test_sensitive_fields_not_echoed(data):
    data[1]['DBInstances'][0]['MasterUsername']='SECRET_MARKER';assert 'SECRET_MARKER' not in json.dumps(run(data))

def test_missing_resource(data):assert run(data,name='missing')['reason']=='RDS_INSTANCE_MISSING'

def test_zero_reader_cluster(data):
    data[1]['DBInstances'].pop();data[1]['DBClusters'][0]['DBClusterMembers'].pop()
    r=run(data,'cluster','demo-aurora');assert r['status']=='RDS_CONFIGURATION_CANDIDATE' and len(r['members'])==1 and r['session_status']=='UNKNOWN'
