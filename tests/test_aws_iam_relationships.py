import copy,json
from pathlib import Path
import pytest
from backend.aws.iam_relationships import inspect_iam_relationships
from backend.aws.iam_inventory import register_iam_inventory
D=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
A='arn:aws:iam::123456789012:'
USER=A+'user/demo-user'; GROUP=A+'group/demo-group'; ROLE=A+'role/demo-app'; EXEC=A+'role/demo-execution'

def raw(x): return json.dumps(x).encode()
@pytest.fixture
def data():
    return json.loads((D/'iam_relationship_inventory.json').read_text()),json.loads((D/'iam_relationships_demo.json').read_text())

def run(data, **kw):
    b,r=data
    return inspect_iam_relationships(raw(b),raw(r),**kw)

def rebind(data):
    b,r=data; r['base_identity']=register_iam_inventory(raw(b))['base_identity']

@pytest.mark.parametrize('svc,ref,aux', [('EC2','demo-instance',0),('ECS','demo-task',1),('EKS','demo-pod',1)])
def test_workload(data,svc,ref,aux):
    r=run(data,workload=(svc,ref))
    assert r['relationship_status']=='CONFIGURATION_CANDIDATE'
    assert r['principal_candidates']==[ROLE] and len(r['auxiliary_bindings'])==aux
    assert [p['identity_arn'] for p in r['policy_candidates']]==[ROLE]
    assert r['runtime_identity_status']==r['api_status']=='UNKNOWN' and r['authorization_status']=='NOT_EVALUATED'

def test_group(data):
    r=run(data,user_arn=USER)
    assert r['groups']==[GROUP] and r['principal_candidates']==[USER]
    assert r['policy_candidates'][0]['relationship']=='GROUP_INHERITED'
    assert r['relationship_status']=='CONFIGURATION_CANDIDATE'

def test_direct_and_group(data):
    b,_=data; b['attachments'].append(dict(identity_arn=USER,kind='IDENTITY_POLICY',policy_ref=b['policies'][0]['ref'])); rebind(data)
    assert {p['relationship'] for p in run(data,user_arn=USER)['policy_candidates']}=={'DIRECT','GROUP_INHERITED'}

def test_no_group(data):
    data[1]['memberships']=[]; r=run(data,user_arn=USER)
    assert r['groups']==[] and r['policy_candidates']==[] and r['authorization_status']=='NOT_EVALUATED'

@pytest.mark.parametrize('field,query,code',[('memberships',{'user_arn':USER},'MEMBERSHIP_INCOMPLETE'),('bindings',{'workload':('ECS','demo-task')},'BINDINGS_INCOMPLETE')])
def test_incomplete(data,field,query,code):
    data[1]['complete'][field]=False; r=run(data,**query)
    assert r['relationship_status']=='UNKNOWN' and code in r['issues']

@pytest.mark.parametrize('svc,ref',[('EC2','absent'),('ECS','absent'),('EKS','absent')])
def test_absent(data,svc,ref):
    r=run(data,workload=(svc,ref)); assert r['relationship_status']=='UNKNOWN' and not r['principal_candidates']

def test_execution_only(data):
    data[1]['bindings']=[x for x in data[1]['bindings'] if x['kind']!='TASK_ROLE']
    r=run(data,workload=('ECS','demo-task')); assert r['relationship_status']=='UNKNOWN' and not r['policy_candidates'] and len(r['auxiliary_bindings'])==1

def test_node_only(data):
    data[1]['bindings']=[x for x in data[1]['bindings'] if x['kind']!='IRSA']
    r=run(data,workload=('EKS','demo-pod')); assert r['relationship_status']=='UNKNOWN' and not r['policy_candidates']

def test_ambiguous(data):
    row=copy.deepcopy(data[1]['bindings'][3]); row['kind']='POD_IDENTITY'; row['role_arn']=EXEC; data[1]['bindings'].append(row)
    r=run(data,workload=('EKS','demo-pod')); assert r['relationship_status']=='UNKNOWN' and set(r['principal_candidates'])=={ROLE,EXEC}

def test_pod_identity(data):
    data[1]['bindings'][3]['kind']='POD_IDENTITY'; assert run(data,workload=('EKS','demo-pod'))['relationship_status']=='CONFIGURATION_CANDIDATE'

@pytest.mark.parametrize('arn,query',[(GROUP,{'user_arn':USER}),(ROLE,{'workload':('EC2','demo-instance')}),(EXEC,{'workload':('ECS','demo-task')})])
def test_unresolved(data,arn,query):
    b,_=data; b['identities']=[x for x in b['identities'] if x['arn']!=arn]; b['attachments']=[x for x in b['attachments'] if x['identity_arn']!=arn]; rebind(data)
    r=run(data,**query); assert r['relationship_status']=='UNKNOWN' and 'IDENTITY_REFERENCE_UNRESOLVED' in r['issues']

def test_boundary_separate(data):
    b,_=data; b['attachments'].append(dict(identity_arn=ROLE,kind='PERMISSIONS_BOUNDARY',policy_ref=b['policies'][0]['ref'])); rebind(data)
    r=run(data,workload=('EC2','demo-instance')); assert len(r['boundary_candidates'])==len(r['policy_candidates'])==1

@pytest.mark.parametrize('field,value',[('account_id','000000000000'),('base_identity','wrong'),('overlay_identity','wrong'),('schema','wrong'),('registered_at','bad'),('complete',{'memberships':1,'bindings':True})])
def test_metadata(data,field,value):
    data[1][field]=value
    with pytest.raises(ValueError): run(data,user_arn=USER)

@pytest.mark.parametrize('field,value',[('user_arn',ROLE),('group_arn',ROLE),('user_arn','arn:aws:iam::000000000000:user/x')])
def test_invalid_membership(data,field,value):
    data[1]['memberships'][0][field]=value
    with pytest.raises(ValueError): run(data,user_arn=USER)

@pytest.mark.parametrize('field,value',[('service','OTHER'),('kind','TASK_ROLE'),('role_arn',USER),('via_ref',''),('workload_ref','\n')])
def test_invalid_binding(data,field,value):
    data[1]['bindings'][0][field]=value
    with pytest.raises(ValueError): run(data,user_arn=USER)

@pytest.mark.parametrize('collection',['memberships','bindings'])
def test_duplicate(data,collection):
    data[1][collection].append(copy.deepcopy(data[1][collection][0]))
    with pytest.raises(ValueError): run(data,user_arn=USER)

@pytest.mark.parametrize('query',[{}, {'user_arn':USER,'workload':('EC2','demo-instance')},{'user_arn':ROLE},{'workload':('OTHER','x')}])
def test_selector(data,query):
    with pytest.raises(ValueError): run(data,**query)

def test_overlay_scenario(data):
    b,r=data; ref=b['policies'][0]['ref']; o=dict(schema='cloudpath-iam-overlay-v1',account_id=b['account_id'],base_identity=r['base_identity'],registered_at=b['registered_at'],operations=[dict(operation='DELETE',collection='attachments',key=[ROLE,'IDENTITY_POLICY',ref],record=None)])
    with pytest.raises(ValueError): run(data,workload=('EC2','demo-instance'),overlay_raw=raw(o))
    r['overlay_identity']=register_iam_inventory(raw(b),raw(o))['overlay_identity']
    out=run(data,workload=('EC2','demo-instance'),overlay_raw=raw(o))
    assert out['effective_mode']=='WHAT_IF' and out['policy_candidates']==[] and out['api_status']=='UNKNOWN'
    r['overlay_identity']=None
    assert len(run(data,workload=('EC2','demo-instance'))['policy_candidates'])==1
