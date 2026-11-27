import json
from pathlib import Path
import pytest
from backend.aws.ecs_session_evidence import analyze_ecs_task_session

ROOT=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'

@pytest.fixture
def inputs():
    return [json.loads((ROOT/n).read_text()) for n in ('ecs_task_inventory.json','ecs_task_evidence.json')]


def run(inputs, src='1'*32,dst='2'*32,sp=50000,dp=443):
    return analyze_ecs_task_session(*(json.dumps(x).encode() for x in inputs),src,dst,sp,dp)

@pytest.mark.parametrize('src,dst',[('1'*32,'2'*32),('2'*32,'1'*32)])
def test_candidate(inputs,src,dst):
    r=run(inputs,src,dst)
    assert r['request_status']==r['response_status']=='CONDITIONAL_CANDIDATE'
    assert r['session_status']=='UNKNOWN' and not r['live_observation']
    assert r['first_request_stop'] is None and r['conditional_first_response_stop'] is None
    assert all(x['evaluation_mode']=='PREDICTED_PATH' for x in r['request'])
    assert all(x['evaluation_mode']=='CONDITIONAL_CHECK' for x in r['response'])
    assert r['request'][0]['eni_id']==r['source_endpoint']['endpoint']['eni_id']
    assert r['response'][0]['eni_id']==r['destination_endpoint']['endpoint']['eni_id']
    assert r['request'][2]['route_evidence']['route_table_id']!=r['response'][2]['route_evidence']['route_table_id']
    assert r['response'][0]['status']==r['response'][-1]['status']=='CONDITIONAL'

@pytest.mark.parametrize('port',[80,8080,8443,65535])
def test_destination_sg_block(inputs,port):
    r=run(inputs,dp=port)
    assert r['request_status']==r['session_status']=='BLOCKED'
    assert r['first_request_stop']=='DESTINATION_SG_INGRESS'
    assert r['response_status']=='NOT_EVALUATED'
    assert all(x['evaluation_mode']=='INDEPENDENT_CHECK' for x in r['response'])

@pytest.mark.parametrize('port',[0,-1,65536,True,'443',None])
def test_invalid_port(inputs,port):
    with pytest.raises(ValueError): run(inputs,sp=port)

@pytest.mark.parametrize('which',['source','destination'])
def test_endpoint_unknown(inputs,which):
    inputs[1]['tasks'][0 if which=='source' else 1]['lastStatus']='STOPPED'
    r=run(inputs)
    assert r['first_request_stop']=='ECS_SCOPE' and r['reason']=='TASK_ENDPOINT_NOT_CONFIRMED'
    assert r['session_status']=='UNKNOWN' and r['response']==[]


def test_same_task(inputs):
    assert run(inputs,dst='1'*32)['reason']=='SAME_ENDPOINT_NOT_IN_SCOPE'


def test_missing_task(inputs):
    assert run(inputs,dst='3'*32)['reason']=='TASK_ENDPOINT_NOT_CONFIRMED'


def test_stale(inputs):
    inputs[1]['collected_at']='2026-11-25T11:06:00+00:00'
    assert run(inputs)['reason']=='TASK_ENDPOINT_NOT_CONFIRMED'


def test_source_sg_block(inputs):
    inputs[0]['inventory']['SecurityGroups'][0]['IpPermissionsEgress']=[]
    r=run(inputs)
    assert r['first_request_stop']=='SOURCE_SG_EGRESS'
    assert all(x['evaluation_mode']=='INDEPENDENT_CHECK' for x in r['request'][1:])

@pytest.mark.parametrize('egress,port,stop',[(True,443,'SOURCE_NACL_EGRESS'),(False,443,'DESTINATION_NACL_INGRESS')])
def test_nacl_request_block(inputs,egress,port,stop):
    inv=inputs[0]['inventory']; inv['NetworkAcls'][0]['Entries'].append(dict(RuleNumber=50,Protocol='6',RuleAction='deny',Egress=egress,CidrBlock='0.0.0.0/0',PortRange={'From':port,'To':port}))
    r=run(inputs)
    assert r['first_request_stop']==stop and r['request_status']=='BLOCKED'
    assert r['response_status']=='NOT_EVALUATED'

@pytest.mark.parametrize('egress,stop',[(True,'SOURCE_NACL_EGRESS'),(False,'DESTINATION_NACL_INGRESS')])
def test_reply_block(inputs,egress,stop):
    inputs[0]['inventory']['NetworkAcls'][0]['Entries'].append(dict(RuleNumber=50,Protocol='6',RuleAction='deny',Egress=egress,CidrBlock='0.0.0.0/0',PortRange={'From':50000,'To':50000}))
    r=run(inputs)
    assert r['request_status']=='CONDITIONAL_CANDIDATE' and r['response_status']=='BLOCKED'
    assert r['conditional_first_response_stop']==stop and r['session_status']=='UNKNOWN'


def test_unresolved_sg_reference(inputs):
    inputs[0]['inventory']['SecurityGroups'][0]['IpPermissions']=[dict(IpProtocol='tcp',FromPort=443,ToPort=443,UserIdGroupPairs=[{'GroupId':'sg-12345678'}])]
    r=run(inputs)
    assert r['first_request_stop']=='DESTINATION_SG_INGRESS' and r['request_status']=='UNKNOWN'
    assert r['session_status']=='UNKNOWN'


def test_route_blackhole(inputs):
    for t in inputs[0]['inventory']['RouteTables']:
        for route in t['Routes']:
            if route.get('GatewayId')=='local': route['State']='blackhole'
    r=run(inputs)
    assert r['first_request_stop']=='LOCAL_ROUTE' and r['request_status']=='BLOCKED'
    assert r['request'][2]['reason']=='SELECTED_ROUTE_BLACKHOLE'


def test_missing_route(inputs):
    for t in inputs[0]['inventory']['RouteTables']:
        t['Routes']=[r for r in t['Routes'] if r.get('GatewayId')!='local']
    r=run(inputs)
    assert r['first_request_stop']=='LOCAL_ROUTE' and r['request_status']=='UNKNOWN'
    assert r['request'][3]['evaluation_mode']=='INDEPENDENT_CHECK'


def test_unknown_acl(inputs):
    inputs[0]['inventory']['NetworkAcls'][0]['Associations']=[]
    r=run(inputs)
    assert r['first_request_stop']=='SOURCE_NACL_EGRESS' and r['request_status']=='UNKNOWN'


def test_unknown_precedes_later_block(inputs):
    inputs[0]['inventory']['NetworkAcls'][0]['Associations']=[]
    r=run(inputs,dp=8080)
    assert r['request_status']=='UNKNOWN' and r['session_status']=='UNKNOWN'
    assert r['request'][-1]['status']=='BLOCKED' and r['request'][-1]['evaluation_mode']=='INDEPENDENT_CHECK'


def test_task_sg_not_host_sg(inputs):
    inv=inputs[0]['inventory']
    inv['SecurityGroups'].append(dict(GroupId='sg-aaaaaaaa',VpcId='vpc-12345678',IpPermissions=[],IpPermissionsEgress=[]))
    inv['NetworkInterfaces'][-1]['Groups']=[{'GroupId':'sg-aaaaaaaa'}]
    r=run(inputs)
    assert r['destination_endpoint']['endpoint']['security_group_ids']==['sg-aaaaaaaa']
    assert r['request'][-1]['group_ids']==['sg-aaaaaaaa']
    assert r['first_request_stop']=='DESTINATION_SG_INGRESS'


def test_reverse_route_blackhole(inputs):
    for route in inputs[0]['inventory']['RouteTables'][0]['Routes']:
        if route.get('GatewayId')=='local': route['State']='blackhole'
    r=run(inputs)
    assert r['request_status']=='CONDITIONAL_CANDIDATE'
    assert r['response_status']=='BLOCKED' and r['conditional_first_response_stop']=='LOCAL_ROUTE'
    assert r['session_status']=='UNKNOWN'


def test_same_subnet(inputs):
    inv=inputs[0]['inventory']; task=inputs[1]['tasks'][0]; eni=inv['NetworkInterfaces'][-2]
    eni.update(SubnetId='subnet-87654321',PrivateIpAddress='10.0.2.61',PrivateIpAddresses=[{'PrivateIpAddress':'10.0.2.61','Primary':True}])
    task['availabilityZone']='ap-northeast-2c'
    for detail in task['attachments'][0]['details']:
        if detail['name']=='subnetId': detail['value']='subnet-87654321'
        if detail['name']=='privateIPv4Address': detail['value']='10.0.2.61'
    r=run(inputs)
    assert r['reason']=='SAME_SUBNET_NOT_IN_SCOPE' and r['response_status']=='NOT_EVALUATED'
