import hashlib
import json
from pathlib import Path
import pytest
from backend.aws.nlb_forwarding_evidence import inspect_nlb_forwarding

ROOT=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'

@pytest.fixture
def inputs():
    return [(ROOT/'elbv2_inventory.json').read_bytes(),json.loads((ROOT/'elbv2_evidence.json').read_text()),json.loads((ROOT/'nlb_attributes_preserve.json').read_text())]


def run(inputs, *, ip='10.0.1.10', lb='2'*16, bind=True):
    inv, ev, attrs=inputs
    ev=json.dumps(ev).encode()
    if bind: attrs['elbv2_input_identity']='sha256-elbv2-v1:'+hashlib.sha256(ev).hexdigest()
    return inspect_nlb_forwarding(inv,ev,json.dumps(attrs).encode(),lb,443,ip)


@pytest.mark.parametrize('preserve,cross,lb_cross,expected_cross,source', [
    ('true','use_load_balancer_configuration','false',False,'LOAD_BALANCER'),
    ('false','use_load_balancer_configuration','true',True,'LOAD_BALANCER'),
    ('true','true','false',True,'TARGET_GROUP'),
    ('false','false','true',False,'TARGET_GROUP'),
])
def test_candidate(inputs,preserve,cross,lb_cross,expected_cross,source):
    a=inputs[2]; a['TargetGroupAttributes'][0]['Value']=preserve; a['TargetGroupAttributes'][1]['Value']=cross; a['LoadBalancerAttributes'][0]['Value']=lb_cross
    out=run(inputs)
    assert out['status']=='NLB_FORWARD_CONFIG_CANDIDATE'
    assert out['address_processing']['backend_source_ip']==('10.0.1.10' if preserve=='true' else None)
    assert out['address_processing']['backend_source_ip_kind']==('CLIENT_IPV4_CANDIDATE' if preserve=='true' else 'NLB_NODE_PRIVATE_IPV4_CANDIDATE')
    assert out['address_processing']['backend_source_port'] is None and out['address_processing']['backend_destination_ip'] is None
    assert out['cross_zone']['enabled'] is expected_cross and out['cross_zone']['source']==source
    assert out['cross_zone']['ingress_node_zone'] is None
    assert out['session_status']=='UNKNOWN' and out['live_observation'] is False
    assert out['target_health']==out['target_selection']==out['policy_status']=='NOT_EVALUATED'
    assert out['transport']['configured_target_port']==8080
    assert '000000000000' not in json.dumps(out)

@pytest.mark.parametrize('listener,backend,mode',[('TCP','TCP','TCP_NO_LB_TLS_TERMINATION'),('TLS','TCP','TLS_TERMINATION_TCP_BACKEND_CONFIG'),('TLS','TLS','TLS_TERMINATION_REENCRYPTION_CONFIG')])
def test_transport(inputs,listener,backend,mode):
    inputs[1]['Listeners'][1]['Protocol']=listener; inputs[1]['TargetGroups'][1]['Protocol']=backend
    assert run(inputs)['transport']['tls_mode']==mode

@pytest.mark.parametrize('mutation,reason',[
    ('gap','ATTRIBUTES_IDENTITY_OR_TIME_MISMATCH'),('identity','ATTRIBUTES_IDENTITY_OR_TIME_MISMATCH'),
    ('scope','ATTRIBUTES_RESOURCE_SCOPE_MISMATCH'),('listener_scope','ATTRIBUTES_RESOURCE_SCOPE_MISMATCH'),
    ('group_scope','ATTRIBUTES_RESOURCE_SCOPE_MISMATCH'),('rules','DEFAULT_ONLY_LISTENER_UNCONFIRMED'),
    ('preserve_missing','CLIENT_IP_PRESERVATION_UNCONFIRMED'),('preserve_invalid','CLIENT_IP_PRESERVATION_UNCONFIRMED'),
    ('cross_missing','CROSS_ZONE_CONFIGURATION_UNCONFIRMED'),('lb_cross_missing','CROSS_ZONE_CONFIGURATION_UNCONFIRMED'),
    ('proxy_missing','PROXY_PROTOCOL_UNCONFIRMED'),('inactive','BASE_CONFIGURATION_UNCONFIRMED'),('alb','NLB_REQUIRED'),
])
def test_unknown(inputs,mutation,reason):
    _,e,a=inputs; lb='2'*16; bind=True
    if mutation=='gap': a['collected_at']='2026-11-25T11:06:00+00:00'
    elif mutation=='identity': bind=False
    elif mutation=='scope': a['LoadBalancerArn']=e['LoadBalancers'][0]['LoadBalancerArn']
    elif mutation=='listener_scope': a['ListenerArn']=e['Listeners'][0]['ListenerArn']
    elif mutation=='group_scope': a['TargetGroupArn']=e['TargetGroups'][0]['TargetGroupArn']
    elif mutation=='rules': a['default_only_asserted']=False
    elif mutation=='preserve_missing': a['TargetGroupAttributes'].pop(0)
    elif mutation=='preserve_invalid': a['TargetGroupAttributes'][0]['Value']='TRUE'
    elif mutation=='cross_missing': a['TargetGroupAttributes'].pop(1)
    elif mutation=='lb_cross_missing': a['LoadBalancerAttributes']=[]
    elif mutation=='proxy_missing': a['TargetGroupAttributes'].pop(2)
    elif mutation=='inactive': e['LoadBalancers'][1]['State']['Code']='provisioning'
    elif mutation=='alb': lb='1'*16
    out=run(inputs,lb=lb,bind=bind)
    assert out['status']=='UNKNOWN' and out['reason']==reason
    assert out['session_status']=='UNKNOWN'

@pytest.mark.parametrize('ip',['::1','0.0.0.0','224.0.0.1','127.0.0.1','169.254.1.1','invalid'])
def test_invalid_client(inputs,ip):
    with pytest.raises(ValueError): run(inputs,ip=ip)


def test_duplicate_attribute(inputs):
    inputs[2]['TargetGroupAttributes'].append(inputs[2]['TargetGroupAttributes'][0])
    with pytest.raises(ValueError): run(inputs)


def test_ip_type_does_not_guess_default(inputs):
    inputs[1]['TargetGroups'][1]['TargetType']='ip'; inputs[2]['TargetGroupAttributes'].pop(0)
    assert run(inputs)['reason']=='CLIENT_IP_PRESERVATION_UNCONFIRMED'


def test_proxy_protocol_not_address_rewrite(inputs):
    inputs[2]['TargetGroupAttributes'][2]['Value']='true'
    assert run(inputs)['proxy_protocol_v2'] is True

@pytest.mark.parametrize('name,preserve',[('preserve',True),('translate',False)])
def test_sample_raw_binding(name,preserve):
    out=inspect_nlb_forwarding((ROOT/'elbv2_inventory.json').read_bytes(),(ROOT/'elbv2_evidence.json').read_bytes(),(ROOT/f'nlb_attributes_{name}.json').read_bytes(),'2'*16,443,'10.0.1.10')
    assert out['status']=='NLB_FORWARD_CONFIG_CANDIDATE' and out['address_processing']['preserve_client_ip'] is preserve
