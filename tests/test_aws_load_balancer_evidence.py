import json
from pathlib import Path
import pytest
from backend.aws.load_balancer_evidence import inspect_load_balancer

ROOT=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'

@pytest.fixture
def inputs():
    return json.loads((ROOT/'elbv2_inventory.json').read_text()),json.loads((ROOT/'elbv2_evidence.json').read_text())


def run(inputs, lb='1'*16, port=443):
    a,b=inputs
    return inspect_load_balancer(json.dumps(a).encode(),json.dumps(b).encode(),lb,port)

@pytest.mark.parametrize('lb,protocol,backend',[('1'*16,'HTTPS','HTTP'),('2'*16,'TCP','TCP')])
def test_default_forward_candidate(inputs,lb,protocol,backend):
    out=run(inputs,lb)
    assert out['status']=='DEFAULT_FORWARD_CONFIG_CANDIDATE'
    assert out['listener']['protocol']==protocol
    assert out['default_target_groups'][0]['protocol']==backend
    assert out['default_target_groups'][0]['port']==8080
    assert out['rule_selection']==out['target_health']==out['target_selection']=='NOT_EVALUATED'
    assert out['session_status']=='UNKNOWN' and out['live_observation'] is False
    assert '000000000000' not in json.dumps(out)
    assert len(out['load_balancer']['subnets'])==2

@pytest.mark.parametrize('mutation,reason',[
    ('time','SNAPSHOT_TIME_GAP'),('missing_lb','LOAD_BALANCER_MISSING_OR_AMBIGUOUS'),
    ('vpc','LOAD_BALANCER_SCOPE_MISMATCH'),('type','UNSUPPORTED_LOAD_BALANCER_TYPE'),
    ('ipv6','UNSUPPORTED_ADDRESS_OR_SCHEME'),('state','LOAD_BALANCER_NOT_CONFIRMED_ACTIVE'),
    ('az','LOAD_BALANCER_SUBNETS_UNCONFIRMED'),('one_az','ALB_MULTI_AZ_UNCONFIRMED'),
    ('duplicate_az','LOAD_BALANCER_SUBNETS_UNCONFIRMED'),('missing_listener','LISTENER_MISSING_OR_AMBIGUOUS'),
    ('wrong_parent','LISTENER_PARENT_MISMATCH'),('listener_protocol','UNSUPPORTED_LISTENER_PROTOCOL'),
    ('action_chain','DEFAULT_ACTION_CHAIN_UNSUPPORTED'),('redirect','DEFAULT_ACTION_NOT_FORWARD'),
    ('empty_forward','FORWARD_CONFIG_UNCONFIRMED'),('weight','FORWARD_WEIGHT_INVALID'),
    ('zero_weight','NO_POSITIVE_FORWARD_WEIGHT'),('duplicate_ref','DUPLICATE_TARGET_GROUP_REFERENCE'),
    ('conflict','FORWARD_REFERENCES_CONFLICT'),('missing_group','TARGET_GROUP_LINK_UNCONFIRMED'),
    ('group_scope','TARGET_GROUP_LINK_UNCONFIRMED'),('group_protocol','UNSUPPORTED_TARGET_GROUP_CONFIGURATION'),
    ('group_type','UNSUPPORTED_TARGET_GROUP_CONFIGURATION'),('group_port','UNSUPPORTED_TARGET_GROUP_CONFIGURATION'),
])
def test_unknown(inputs,mutation,reason):
    a,b=inputs; lb=b['LoadBalancers'][0]; li=b['Listeners'][0]; g=b['TargetGroups'][0]; action=li['DefaultActions'][0]; ga=g['TargetGroupArn']; other=b['TargetGroups'][1]['TargetGroupArn']
    if mutation=='time': b['collected_at']='2026-11-25T11:06:00+00:00'
    elif mutation=='missing_lb': b['LoadBalancers'].pop(0)
    elif mutation=='vpc': lb['VpcId']='vpc-aaaaaaaa'
    elif mutation=='type': lb['Type']='network'
    elif mutation=='ipv6': lb['IpAddressType']='dualstack'
    elif mutation=='state': lb['State']['Code']='provisioning'
    elif mutation=='az': lb['AvailabilityZones'][1]['ZoneName']='ap-northeast-2b'
    elif mutation=='one_az': lb['AvailabilityZones'].pop()
    elif mutation=='duplicate_az': lb['AvailabilityZones'][1]=dict(lb['AvailabilityZones'][0])
    elif mutation=='missing_listener': b['Listeners'].pop(0)
    elif mutation=='wrong_parent': li['ListenerArn']=li['ListenerArn'].replace('demo-app','other-app')
    elif mutation=='listener_protocol': li['Protocol']='TCP'
    elif mutation=='action_chain': li['DefaultActions'].insert(0,{'Type':'authenticate-oidc'})
    elif mutation=='redirect': action['Type']='redirect'
    elif mutation=='empty_forward': action['ForwardConfig']={'TargetGroups':[]}
    elif mutation in ('weight','zero_weight','duplicate_ref','conflict'):
        rows=[{'TargetGroupArn':ga,'Weight':{'weight':1000,'zero_weight':0}.get(mutation,1)}]
        if mutation=='duplicate_ref': rows*=2; action.pop('TargetGroupArn')
        if mutation=='conflict': action['TargetGroupArn']=other
        action['ForwardConfig']={'TargetGroups':rows}
    elif mutation=='missing_group': b['TargetGroups'].pop(0)
    elif mutation=='group_scope': g['LoadBalancerArns']=[]
    elif mutation=='group_protocol': g['Protocol']='TCP'
    elif mutation=='group_type': g['TargetType']='lambda'
    elif mutation=='group_port': g['Port']=True
    out=run(inputs)
    assert out['status']=='UNKNOWN' and out['reason']==reason
    assert out['default_target_groups']==[] and out['session_status']=='UNKNOWN'


def test_weighted_group_refs_not_target_selection(inputs):
    _,b=inputs; g=b['TargetGroups'][0]; other=dict(g,TargetGroupArn=g['TargetGroupArn'].replace('5'*16,'7'*16),Port=8081)
    b['TargetGroups'].append(other)
    b['Listeners'][0]['DefaultActions']=[{'Type':'forward','ForwardConfig':{'TargetGroups':[{'TargetGroupArn':g['TargetGroupArn'],'Weight':90},{'TargetGroupArn':other['TargetGroupArn'],'Weight':10}]}}]
    out=run(inputs)
    assert out['status']=='DEFAULT_FORWARD_CONFIG_CANDIDATE'
    assert [g['configured_weight'] for g in out['default_target_groups']]==[90,10]
    assert out['target_selection']=='NOT_EVALUATED'

@pytest.mark.parametrize('mutation',['duplicate_arn','malformed_arn','invalid_port','invalid_id'])
def test_invalid(inputs,mutation):
    _,b=inputs; lb='1'*16; port=443
    if mutation=='duplicate_arn': b['Listeners'].append(b['Listeners'][0])
    elif mutation=='malformed_arn': b['TargetGroups'][0]['TargetGroupArn']='bad'
    elif mutation=='invalid_port': port=0
    else: lb='bad'
    with pytest.raises(ValueError): run(inputs,lb,port)
