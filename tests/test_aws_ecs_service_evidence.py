import hashlib,json
from pathlib import Path
import pytest
from backend.aws.ecs_service_evidence import inspect_ecs_service

ROOT=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
NAMES=['ecs_task_inventory.json','ecs_service_tasks.json','ecs_service_evidence.json','ecs_service_elbv2.json','ecs_service_target_health.json','alb_rules.json','ecs_service_nlb_attributes.json']
@pytest.fixture
def inputs(): return [json.loads((ROOT/n).read_text()) for n in NAMES]
def raw(x): return json.dumps(x).encode()
def run(x,nlb=False,bind=True):
    if bind:
        x[2]['ecs_input_identity']='sha256-ecs-task-v1:'+hashlib.sha256(raw(x[1])).hexdigest()
        for i in (4,6): x[i]['elbv2_input_identity']='sha256-elbv2-v1:'+hashlib.sha256(raw(x[3])).hexdigest()
    return inspect_ecs_service(*(raw(y) for y in x[:5]),'arn:aws:ecs:ap-northeast-2:000000000000:service/demo/'+('demo-tcp' if nlb else 'demo-api'),'2'*16 if nlb else '1'*16,443,'10.0.1.10',**({'attributes_raw':raw(x[6])} if nlb else {'rules_raw':raw(x[5]),'host':'api.example.com','path':'/api/items'}))
@pytest.mark.parametrize('nlb',[False,True])
def test_match(inputs,nlb):
    r=run(inputs,nlb); assert r['status']=='SERVICE_ELB_CORRELATION_CANDIDATE',r['reason']
    assert r['registrations'][0]['endpoint']['private_ip']==('10.0.2.60' if nlb else '10.0.1.60')
    assert r['registrations'][0]['registered_port']==(8080 if nlb else 8081)
    assert r['registrations'][0]['endpoint']['launch_type']==('EC2' if nlb else 'FARGATE')
    assert r['tasks'][0]['registration_status']=='MATCHED_REGISTRATION'
    assert r['session_status']=='UNKNOWN' and r['policy_status']=='NOT_EVALUATED' and r['target_selection']=='NOT_EVALUATED' and not r['live_observation']
@pytest.mark.parametrize('state',['unhealthy','draining','initial','unused'])
def test_health_independent(inputs,state):
    inputs[4]['target_groups'][0]['TargetHealthDescriptions'][0]['TargetHealth']['State']=state
    r=run(inputs); assert r['status']=='SERVICE_ELB_CORRELATION_CANDIDATE'; assert r['registrations'][0]['health_state']==state
@pytest.mark.parametrize('field,value,reason',[
 ('status','DRAINING','SERVICE_DEPLOYMENT_SCOPE_UNSUPPORTED'),('deploymentController',{'type':'CODE_DEPLOY'},'SERVICE_DEPLOYMENT_SCOPE_UNSUPPORTED'),('schedulingStrategy','DAEMON','SERVICE_DEPLOYMENT_SCOPE_UNSUPPORTED'),('clusterArn','wrong','SERVICE_SCOPE_UNCONFIRMED'),('taskDefinition','wrong','SERVICE_TASK_DEFINITION_UNCONFIRMED'),('loadBalancers',[],'SERVICE_SINGLE_TARGET_GROUP_REQUIRED')])
def test_service_scope(inputs,field,value,reason):
    inputs[2]['services'][0][field]=value; assert run(inputs)['reason']==reason
@pytest.mark.parametrize('field,value',[('group','service:other'),('lastStatus','STOPPED'),('taskDefinitionArn','wrong'),('containers',[]),('clusterArn','wrong')])
def test_task_scope(inputs,field,value):
    inputs[1]['tasks'][0][field]=value; r=run(inputs); assert r['status']=='UNKNOWN'; assert r['registrations'][0]['task_arn'] is None
@pytest.mark.parametrize('field,value',[('containerPort',8080),('hostPort',8080),('protocol','udp')])
def test_mapping(inputs,field,value):
    inputs[1]['taskDefinitions'][0]['containerDefinitions'][0]['portMappings'][0][field]=value
    assert run(inputs)['reason']=='CONTAINER_PORT_MAPPING_UNCONFIRMED'
def test_container_missing(inputs):
    inputs[1]['taskDefinitions'][0]['containerDefinitions']=[]; assert run(inputs)['reason']=='CONTAINER_DEFINITION_UNCONFIRMED'
def test_registration_port(inputs):
    inputs[4]['target_groups'][0]['TargetHealthDescriptions'][0]['Target']['Port']=9999
    r=run(inputs); assert r['status']=='UNKNOWN'; assert r['registrations'][0]['reason']=='REGISTERED_PORT_DIFFERS_FROM_SERVICE_CONTAINER_PORT'
def test_registration_missing(inputs):
    inputs[4]['target_groups'][0]['TargetHealthDescriptions']=[]; r=run(inputs); assert r['status']=='UNKNOWN'; assert r['tasks'][0]['registration_status']=='NOT_OBSERVED'
def test_registration_other_ip(inputs):
    inputs[4]['target_groups'][0]['TargetHealthDescriptions'][0]['Target']['Id']='10.0.2.60'; r=run(inputs); assert r['status']=='UNKNOWN'; assert r['registrations'][0]['task_arn'] is None
def test_instance_group(inputs):
    inputs[3]['TargetGroups'][2]['TargetType']='instance'; inputs[4]['target_groups'][0]['TargetHealthDescriptions'][0]['Target']['Id']='i-12345678'; assert run(inputs)['reason']=='AWS_VPC_MODE_REQUIRES_IP_TARGET_GROUP'
def test_selected_group_differs(inputs):
    inputs[2]['services'][0]['loadBalancers'][0]['targetGroupArn']=inputs[3]['TargetGroups'][1]['TargetGroupArn']; assert run(inputs)['reason']=='SERVICE_TARGET_GROUP_NOT_SELECTED'
def test_stale(inputs):
    inputs[2]['collected_at']='2026-11-25T11:06:00+00:00'; assert run(inputs)['reason']=='SNAPSHOT_TIME_GAP'
def test_incomplete(inputs):
    inputs[2]['complete']=False; assert run(inputs)['reason']=='SERVICE_COMPLETENESS_OR_IDENTITY_UNCONFIRMED'
def test_fingerprint(inputs):
    assert run(inputs,bind=False)['reason']=='SERVICE_COMPLETENESS_OR_IDENTITY_UNCONFIRMED'
def test_health_incomplete(inputs):
    inputs[4]['complete']=False; assert run(inputs)['reason']=='ELB_REGISTRATION_UNCONFIRMED'
def test_duplicate_registration(inputs):
    rows=inputs[4]['target_groups'][0]['TargetHealthDescriptions']; rows.append(rows[0]);
    with pytest.raises(ValueError): run(inputs)
def test_task_eni_mismatch(inputs):
    inputs[1]['tasks'][0]['attachments'][0]['details'][2]['value']='10.0.1.61'; r=run(inputs); assert r['status']=='UNKNOWN'; assert r['tasks'][0]['endpoint'] is None
