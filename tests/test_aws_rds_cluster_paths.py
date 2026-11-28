import hashlib,json
from pathlib import Path
import pytest
from backend.aws.peering_evidence import _load
from backend.aws.rds_session_evidence import analyze_rds_session
from backend.aws.rds_failover_evidence import compare_rds_snapshots

ROOT=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
def enc(x):return json.dumps(x).encode()
def bundle(when='before',role='writer'):
    return tuple((ROOT/f'rds_transition_{when}_{x}.json').read_bytes() for x in ('inventory','configuration',role))
def changed(b,*,inventory=None,config=None,obs=None):
    i,d,o=map(json.loads,b)
    if inventory:inventory(i)
    i=enc(i);d['inventory_identity']=_load(i)[0]
    if config:config(d)
    d=enc(d);o.update(inventory_identity=_load(i)[0],rds_input_identity='sha256-rds-config-v1:'+hashlib.sha256(d).hexdigest())
    if obs:obs(o)
    return i,d,enc(o)
def run(b=None,role='WRITER'):
    return analyze_rds_session(*(b or bundle(role=role.lower())), 'demo-aurora','ec2',50000,client_ip='10.0.1.10',endpoint_kind=role)
def compare(a=None,b=None,cluster=True):
    return compare_rds_snapshots(a or bundle(role='writer' if cluster else 'instance'),b or bundle('after','writer' if cluster else 'instance'),'demo-aurora' if cluster else 'demo-mysql','10.0.1.10',50000,cluster=cluster)

@pytest.mark.parametrize('when,role,member,verdict',[('before','WRITER','demo-writer','CONDITIONAL_CANDIDATE'),('before','READER','demo-reader','CONDITIONAL_CANDIDATE'),('after','WRITER','demo-reader','BLOCKED'),('after','READER','demo-writer','BLOCKED')])
def test_cluster_path(when,role,member,verdict):
    r=run(bundle(when,role.lower()),role);assert r['status']=='RDS_CLUSTER_PATH_CONSTRAINTS_CANDIDATE';assert r['member_selection']['identifier']==member and r['member_selection']['actual_selection']=='NOT_EVALUATED';assert r['request_status']==verdict;assert r['live_observation'] is False and r['authentication_status']=='NOT_EVALUATED';assert all(e['ip'] is None for e in r['rds_configuration']['endpoints'])
    assert r['response_status']==('NOT_EVALUATED' if verdict=='BLOCKED' else 'CONDITIONAL_CANDIDATE')

@pytest.mark.parametrize('field,value,reason',[
 ('member_identifier','missing','RDS_CLUSTER_MEMBER_EVIDENCE_MISMATCH'),('member_hostname','incorrect','RDS_CLUSTER_MEMBER_EVIDENCE_MISMATCH'),('member_answers',['10.0.2.80'],'RDS_CLUSTER_MEMBER_DNS_MISMATCH'),('member_answers',['10.0.1.80','10.0.2.80'],'RDS_CLUSTER_MEMBER_DNS_MISMATCH'),('member_answers',[],'RDS_CLUSTER_MEMBER_DNS_MISMATCH'),('member_ttl_seconds',0,'RDS_CLUSTER_MEMBER_DNS_TIME_UNCONFIRMED'),('member_ttl_seconds',True,'RDS_CLUSTER_MEMBER_DNS_TIME_UNCONFIRMED'),('member_resolved_at','2026-11-25T10:59:00+00:00','RDS_CLUSTER_MEMBER_DNS_TIME_UNCONFIRMED'),('member_resolved_at','2026-11-25T11:00:01+00:00','RDS_CLUSTER_MEMBER_DNS_TIME_UNCONFIRMED'),('hostname','wrong','RDS_PATH_EVIDENCE_IDENTITY_MISMATCH'),('source_eni_id','eni-aaaaaaaa','RDS_PATH_EVIDENCE_IDENTITY_MISMATCH'),('complete',False,'RDS_PATH_PROFILE_UNCONFIRMED')])
def test_unknown(field,value,reason):
    r=run(changed(bundle(),obs=lambda o:o.update({field:value})));assert r['reason']==reason and r['request_status']=='UNKNOWN' and r['destination_endpoint'] is None

def test_role_conflict():
    b=changed(bundle('before','reader'),obs=lambda o:o.update(hostname=json.loads(bundle()[2])['hostname']));assert run(b)['reason']=='RDS_CLUSTER_ENDPOINT_ROLE_UNCONFIRMED'

def test_reader_fallback():
    def cfg(d):
        d['DBInstances']=[i for i in d['DBInstances'] if i['DBInstanceIdentifier']!='demo-reader'];d['DBClusters'][0]['DBClusterMembers']=d['DBClusters'][0]['DBClusterMembers'][:1]
    b=changed(bundle(),config=cfg,obs=lambda o:o.update(hostname=json.loads(bundle(role='reader')[2])['hostname']));r=run(b,'READER');assert r['member_selection']['reader_primary_fallback'] is True and r['member_selection']['role']=='WRITER'

def test_non_aurora_invalid_scope():
    def cfg(d):
        for i in d['DBInstances']:
            if i.get('DBClusterIdentifier'):i['Engine']='postgres'
        d['DBClusters'][0]['Engine']='postgres'
    assert run(changed(bundle(),config=cfg))['reason']=='RDS_MULTI_AZ_CLUSTER_SCOPE_UNCONFIRMED'

def test_missing():
    i,d,_=bundle();assert run((i,d,None))['reason']=='RDS_DNS_ENI_EVIDENCE_MISSING'

def test_compare_cluster():
    r=compare();assert r['reason']=='RDS_WRITER_ROLE_CHANGE_CANDIDATE' and r['status']=='RDS_SNAPSHOT_TRANSITION_CANDIDATE';assert r['changes']['before_request']=='CONDITIONAL_CANDIDATE' and r['changes']['after_request']=='BLOCKED';assert r['failover_status']==r['session_status']=='UNKNOWN'

def test_compare_instance():
    r=compare(cluster=False);assert r['reason']=='RDS_PRIMARY_AZ_CHANGE_CANDIDATE' and r['changes']['ip_changed'] and r['failover_status']=='UNKNOWN'

@pytest.mark.parametrize('mode',['same','reversed'])
def test_order(mode):assert compare(bundle('after'),bundle('after' if mode=='same' else 'before'))['reason']=='RDS_TRANSITION_TIME_ORDER_UNCONFIRMED'

@pytest.mark.parametrize('field,value',[('DbClusterResourceId','other'),('DbClusterResourceId',None)])
def test_resource_id(field,value):assert compare(b=changed(bundle('after'),config=lambda d:d['DBClusters'][0].update({field:value})))['reason']=='RDS_TRANSITION_RESOURCE_ID_UNCONFIRMED'

def test_member_identity():assert compare(b=changed(bundle('after'),config=lambda d:d['DBInstances'][-1].update(DbiResourceId='different')))['reason']=='RDS_TRANSITION_MEMBER_ID_UNCONFIRMED'

def test_uncorrelated_path():assert compare(b=changed(bundle('after'),obs=lambda o:o.update(complete=False)))['reason']=='RDS_TRANSITION_ENDPOINT_UNCONFIRMED'

def test_single_az_not_failover():assert compare(b=changed(bundle('after','instance'),config=lambda d:d['DBInstances'][0].update(MultiAZ=False)),cluster=False)['reason']=='RDS_MULTI_AZ_INSTANCE_SCOPE_UNCONFIRMED'

def test_no_role_change():
    def cfg(d):
        for m in d['DBClusters'][0]['DBClusterMembers']:m['IsClusterWriter']=not m['IsClusterWriter']
    b=changed(bundle('after','reader'),config=cfg,obs=lambda o:o.update(hostname=json.loads(bundle()[2])['hostname']));r=compare(b=b);assert r['reason']=='RDS_NO_WRITER_ROLE_CHANGE_OBSERVED' and r['failover_status']=='UNKNOWN'

@pytest.mark.parametrize('mode',['ecs','eks'])
def test_workload_source(mode):
    i,d,o=map(json.loads,bundle());kw={}
    if mode=='ecs':
        kw=dict(ecs_raw=(ROOT/'ecs_task_evidence.json').read_bytes(),task_id='2'*32)
        o.update(source_ip='10.0.2.60',source_eni_id='eni-44444444')
    else:
        e=json.loads((ROOT/'rds_path_eks_inventory.json').read_bytes());e['inventory']['NetworkInterfaces'].extend(i['inventory']['NetworkInterfaces'][-3:]);e['inventory']['SecurityGroups'][-1]=i['inventory']['SecurityGroups'][-1];i=e
        pod=json.loads((ROOT/'rds_path_eks_pods.json').read_bytes());pod['inventory_identity']=_load(enc(i))[0];pod=enc(pod)
        policy=json.loads((ROOT/'rds_path_eks_policy.json').read_bytes());policy['eks_input_identity']='sha256-eks-pod-v1:'+hashlib.sha256(pod).hexdigest();policy['networkPolicies'][-1]['spec']['egress'][0]['ports']=[{'port':5432}]
        kw=dict(eks_raw=pod,policy_raw=enc(policy),namespace='demo',pod_name='app-2');o.update(source_ip='10.0.2.70',source_eni_id='eni-87654321')
    i=enc(i);d['inventory_identity']=_load(i)[0];d=enc(d);o.update(inventory_identity=_load(i)[0],rds_input_identity='sha256-rds-config-v1:'+hashlib.sha256(d).hexdigest())
    r=analyze_rds_session(i,d,enc(o),'demo-aurora',mode,50000,endpoint_kind='WRITER',**kw);assert r['request_status']=='CONDITIONAL_CANDIDATE',r['reason'];assert r['destination_endpoint']['port']==5432
