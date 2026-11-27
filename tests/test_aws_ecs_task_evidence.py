import json
from pathlib import Path
import pytest
from backend.aws.ecs_task_evidence import inspect_ecs_task

ROOT=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'

@pytest.fixture
def inputs():
    return [json.loads((ROOT/name).read_text()) for name in ('ecs_task_inventory.json','ecs_task_evidence.json')]


def run(inputs, task_id='1'*32):
    return inspect_ecs_task(*(json.dumps(d).encode() for d in inputs),task_id)

@pytest.mark.parametrize('task_id,launch,ip,eni',[('1'*32,'FARGATE','10.0.1.60','eni-33333333'),('2'*32,'EC2','10.0.2.60','eni-44444444')])
def test_candidate(inputs,task_id,launch,ip,eni):
    result=run(inputs,task_id)
    assert result['status']=='TASK_ENDPOINT_CANDIDATE'
    assert result['endpoint']['launch_type']==launch
    assert result['endpoint']['private_ip']==ip and result['endpoint']['eni_id']==eni
    assert result['endpoint']['security_group_ids']==['sg-12345678']
    assert result['route_status']==result['policy_status']=='NOT_EVALUATED'
    assert result['session_status']=='UNKNOWN' and result['live_observation'] is False
    assert '000000000000' not in json.dumps(result)

@pytest.mark.parametrize('mutation,reason',[
    ('time','SNAPSHOT_TIME_GAP'),('missing_task','TASK_MISSING_OR_AMBIGUOUS'),
    ('cluster','TASK_SCOPE_MISMATCH'),('stopped','TASK_NOT_RUNNING'),('desired','TASK_NOT_RUNNING'),
    ('launch','UNSUPPORTED_LAUNCH_TYPE'),('definition','TASK_DEFINITION_UNCONFIRMED'),
    ('bridge','UNSUPPORTED_NETWORK_MODE'),('host','UNSUPPORTED_NETWORK_MODE'),
    ('attachment','TASK_ENI_ATTACHMENT_UNCONFIRMED'),('multiple','TASK_ENI_ATTACHMENT_UNCONFIRMED'),
    ('duplicate_detail','TASK_ENI_DETAILS_AMBIGUOUS'),('missing_detail','TASK_ENI_DETAILS_MISSING'),
    ('invalid_ip','TASK_IPV4_INVALID'),('outside_vpc','PRIMARY_VPC_CIDR_UNCONFIRMED'),
    ('outside_subnet','TASK_SUBNET_UNCONFIRMED'),('az','TASK_AZ_UNCONFIRMED'),
    ('missing_eni','INVENTORY_ENI_UNCONFIRMED'),('wrong_ip','TASK_ENI_IDENTITY_MISMATCH'),
    ('eni_state','TASK_ENI_STATE_UNCONFIRMED'),('managed','TASK_ENI_STATE_UNCONFIRMED'),
    ('secondary','TASK_PRIMARY_IPV4_UNCONFIRMED'),('duplicate_ip','TASK_IPV4_AMBIGUOUS'),
    ('shared_eni','TASK_ENI_SHARED_OR_STALE'),('host_conflict','EC2_PRIMARY_OR_HOST_OWNERSHIP_CONFLICT'),
    ('no_groups','TASK_SECURITY_GROUPS_UNCONFIRMED'),('missing_group','TASK_SECURITY_GROUPS_UNCONFIRMED'),
])
def test_unknown(inputs,mutation,reason):
    a,b=inputs; inv=a['inventory']; t=b['tasks'][0]; d=b['taskDefinitions'][0]; att=t['attachments'][0]; details=att['details']; eni=inv['NetworkInterfaces'][-2]
    if mutation=='time': b['collected_at']='2026-11-25T11:06:00+00:00'
    elif mutation=='missing_task': b['tasks'].pop(0)
    elif mutation=='cluster': t['clusterArn']+='x'
    elif mutation=='stopped': t['lastStatus']='STOPPED'
    elif mutation=='desired': t['desiredStatus']='STOPPED'
    elif mutation=='launch': t['launchType']='EXTERNAL'
    elif mutation=='definition': t['taskDefinitionArn']+='0'
    elif mutation in ('bridge','host'): d['networkMode']=mutation
    elif mutation=='attachment': att['status']='DETACHED'
    elif mutation=='multiple': t['attachments'].append(att.copy())
    elif mutation=='duplicate_detail': details.append(details[0].copy())
    elif mutation=='missing_detail': details.pop()
    elif mutation in ('invalid_ip','outside_vpc','outside_subnet'): details[2]['value']={'invalid_ip':'::1','outside_vpc':'10.1.1.60','outside_subnet':'10.0.2.60'}[mutation]
    elif mutation=='az': t['availabilityZone']='ap-northeast-2c'
    elif mutation=='missing_eni': inv['NetworkInterfaces'].remove(eni)
    elif mutation=='wrong_ip': eni['PrivateIpAddress']='10.0.1.61'
    elif mutation=='eni_state': eni['Status']='available'
    elif mutation=='managed': eni['RequesterManaged']=False
    elif mutation=='secondary': eni['PrivateIpAddresses'].append({'PrivateIpAddress':'10.0.1.61','Primary':False})
    elif mutation=='duplicate_ip': inv['NetworkInterfaces'][-1]['PrivateIpAddresses'].append({'PrivateIpAddress':'10.0.1.60'})
    elif mutation=='shared_eni': b['tasks'][1]['attachments'][0]['details'][0]['value']=eni['NetworkInterfaceId']
    elif mutation=='host_conflict': eni['Attachment']={'InstanceId':'i-12345678','DeviceIndex':1}
    elif mutation=='no_groups': eni['Groups']=[]
    elif mutation=='missing_group': eni['Groups']=[{'GroupId':'sg-aaaaaaaa'}]
    r=run(inputs)
    assert r['status']=='UNKNOWN' and r['reason']==reason
    assert r['endpoint'] is None and r['session_status']=='UNKNOWN'

@pytest.mark.parametrize('mutation',['duplicate_task','duplicate_definition','bad_arn','bad_id','bad_format'])
def test_invalid(inputs,mutation):
    _,b=inputs; tid='1'*32
    if mutation=='duplicate_task': b['tasks'].append(b['tasks'][0])
    elif mutation=='duplicate_definition': b['taskDefinitions'].append(b['taskDefinitions'][0])
    elif mutation=='bad_arn': b['tasks'][0]['taskArn']='bad'
    elif mutation=='bad_id': tid='bad'
    elif mutation=='bad_format': b['format']='wrong'
    with pytest.raises(ValueError): run(inputs,tid)

def test_ec2_host_attachment_required(inputs):
    inputs[0]['inventory']['NetworkInterfaces'][-1]['Attachment']['DeviceIndex']=0
    assert run(inputs,'2'*32)['reason']=='EC2_PRIMARY_OR_HOST_OWNERSHIP_CONFLICT'
