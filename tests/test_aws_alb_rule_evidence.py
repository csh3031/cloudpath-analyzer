import copy
import json
from pathlib import Path
import pytest
from backend.aws.alb_rule_evidence import inspect_alb_rule

ROOT=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'

@pytest.fixture
def inputs():
    return [(ROOT/'elbv2_inventory.json').read_bytes(),json.loads((ROOT/'elbv2_rule_evidence.json').read_text()),json.loads((ROOT/'alb_rules.json').read_text())]

def run(inputs,host='api.example.com',path='/api/items',lb='1'*16):
    a,b,c=inputs
    return inspect_alb_rule(a,json.dumps(b).encode(),json.dumps(c).encode(),lb,443,host,path)

@pytest.mark.parametrize('host,path,priority,target',[
    ('api.example.com','/api/items','10','7'),('API.EXAMPLE.COM','/api/items','10','7'),
    ('sub.example.net','/api/','10','7'),('other.example.com','/api/items','20','5'),
    ('api.example.com','/API/items','default','5'),('api.example.com','/','default','5'),
    ('api.example.com','/api','default','5'),('example.net','/api/items','20','5')])
def test_selection(inputs,host,path,priority,target):
    out=run(inputs,host,path)
    assert out['status']=='RULE_FORWARD_CONFIG_CANDIDATE'
    assert out['selected_rule']['priority']==priority
    assert out['selected_target_groups'][0]['id']==target*16
    assert out['session_status']=='UNKNOWN' and out['target_selection']=='NOT_EVALUATED' and not out['live_observation']
    assert '000000000000' not in json.dumps(out)

@pytest.mark.parametrize('host,path,reason',[
    ('api.example.com:443','/','UNSUPPORTED_HOST_INPUT'),('a..b','/','UNSUPPORTED_HOST_INPUT'),
    ('api.example.com','/api/../x','UNSUPPORTED_PATH_INPUT'),('api.example.com','/api/%61','UNSUPPORTED_PATH_INPUT'),
    ('api.example.com','/api//x','UNSUPPORTED_PATH_INPUT'),('api.example.com','/api/x?q=1','UNSUPPORTED_PATH_INPUT')])
def test_input_bounds(inputs,host,path,reason):
    assert run(inputs,host,path)['reason']==reason

@pytest.mark.parametrize('mutation,reason',[
    ('incomplete','RULE_SET_INCOMPLETE'),('time','SNAPSHOT_TIME_GAP'),('wrong_listener','RULE_LISTENER_MISMATCH'),
    ('wrong_rule_parent','RULE_SET_INVALID'),('duplicate_id','RULE_SET_INVALID'),('duplicate_priority','RULE_PRIORITY_OR_CONDITIONS_INVALID'),
    ('missing_default','DEFAULT_RULE_UNCONFIRMED'),('default_conflict','DEFAULT_RULE_CONFLICT'),
    ('regex','EARLIER_RULE_UNRESOLVED'),('method','EARLIER_RULE_UNRESOLVED'),('conflict_values','EARLIER_RULE_UNRESOLVED'),
    ('transform','RULE_TRANSFORM_OR_FIELDS_UNSUPPORTED'),('auth','RULE_ACTION_CHAIN_UNSUPPORTED'),
    ('redirect','RULE_ACTION_NOT_FORWARD'),('missing_group','TARGET_GROUP_LINK_UNCONFIRMED'),('zero_weight','NO_POSITIVE_FORWARD_WEIGHT')])
def test_unknown(inputs,mutation,reason):
    _,b,c=inputs; rows=c['Rules']; default,other,first=rows; cond=first['Conditions'][0]
    if mutation=='incomplete': c['complete']=False
    elif mutation=='time': c['collected_at']='2026-11-25T11:06:00+00:00'
    elif mutation=='wrong_listener': c['ListenerArn']=b['Listeners'][1]['ListenerArn']
    elif mutation=='wrong_rule_parent': first['RuleArn']=first['RuleArn'].replace('demo-app','other')
    elif mutation=='duplicate_id': first['RuleArn']=other['RuleArn']
    elif mutation=='duplicate_priority': first['Priority']=other['Priority']
    elif mutation=='missing_default': rows.pop(0)
    elif mutation=='default_conflict': default['Actions']=[{'Type':'redirect'}]
    elif mutation=='regex': cond['HostHeaderConfig']={'RegexValues':['.*']}
    elif mutation=='method': first['Conditions'].append({'Field':'http-request-method','HttpRequestMethodConfig':{'Values':['GET']}})
    elif mutation=='conflict_values': cond['Values']=['other.example.com']
    elif mutation=='transform': first['Transforms']=[{'Type':'url-rewrite'}]
    elif mutation=='auth': first['Actions'].insert(0,{'Type':'authenticate-oidc'})
    elif mutation=='redirect': first['Actions']=[{'Type':'redirect'}]
    elif mutation=='missing_group': b['TargetGroups'].pop()
    elif mutation=='zero_weight': first['Actions']=[{'Type':'forward','ForwardConfig':{'TargetGroups':[{'TargetGroupArn':b['TargetGroups'][-1]['TargetGroupArn'],'Weight':0}]}}]
    out=run(inputs)
    assert out['status']=='UNKNOWN' and out['reason']==reason
    assert out['selected_target_groups']==[]

def test_false_and_unknown_can_skip(inputs):
    inputs[2]['Rules'][2]['Conditions'][0]={'Field':'http-header'}
    out=run(inputs,path='/other')
    assert out['selected_rule']['is_default'] and out['evaluated_rules'][0]['status']=='NO_MATCH'


def test_weight_candidates_not_runtime_target(inputs):
    _,b,c=inputs
    c['Rules'][2]['Actions']=[{'Type':'forward','ForwardConfig':{'TargetGroups':[{'TargetGroupArn':b['TargetGroups'][0]['TargetGroupArn'],'Weight':80},{'TargetGroupArn':b['TargetGroups'][-1]['TargetGroupArn'],'Weight':20}]}}]
    out=run(inputs)
    assert [r['configured_weight'] for r in out['selected_target_groups']]==[80,20]
    assert out['target_selection']=='NOT_EVALUATED'


def test_nlb_not_alb(inputs):
    assert run(inputs,lb='2'*16)['reason']=='ALB_LISTENER_UNCONFIRMED'


def test_nonforward_default_does_not_prevent_match(inputs):
    _,b,c=inputs
    b['Listeners'][0]['DefaultActions']=[{'Type':'fixed-response','FixedResponseConfig':{'StatusCode':'404'}}]
    c['Rules'][0]['Actions']=copy.deepcopy(b['Listeners'][0]['DefaultActions'])
    assert run(inputs)['status']=='RULE_FORWARD_CONFIG_CANDIDATE'
    assert run(inputs,path='/other')['reason']=='RULE_ACTION_NOT_FORWARD'


def test_duplicate_host_condition_unresolved(inputs):
    inputs[2]['Rules'][2]['Conditions'].append({'Field':'host-header','Values':['other.example.com']})
    assert run(inputs)['reason']=='EARLIER_RULE_UNRESOLVED'


def test_null_config_not_legacy_fallback(inputs):
    inputs[2]['Rules'][2]['Conditions'][0]={'Field':'host-header','HostHeaderConfig':None,'Values':['api.example.com']}
    assert run(inputs)['reason']=='EARLIER_RULE_UNRESOLVED'
