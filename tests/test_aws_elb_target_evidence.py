import json
from pathlib import Path
import pytest
from backend.aws.elb_target_evidence import inspect_elb_targets

P=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
def read(n): return (P/n).read_bytes()
def encode(d): return json.dumps(d).encode()
def run(kind='alb', health=None, **kw):
    alb=kind=='alb'; args=dict(rules_raw=read('alb_rules.json'),host='api.example.com',path='/api/items',backend_node_ip='10.0.1.50') if alb else dict(attributes_raw=read('nlb_attributes_preserve.json'))
    args.update(kw)
    return inspect_elb_targets(read('elbv2_inventory.json'),read('elbv2_rule_evidence.json' if alb else 'elbv2_evidence.json'),health if health is not None else read(f'{kind}_target_health.json'),'1111111111111111' if alb else '2222222222222222',443,'10.0.1.10',**args)
def mutate(fn,kind='alb'):
    d=json.loads(read(f'{kind}_target_health.json')); fn(d); return encode(d)
def targets(r): return r['groups'][0]['targets']

def test_alb_rule_and_registration():
    r=run(); assert r['status']=='TARGET_CONSTRAINTS_CANDIDATE'; assert r['groups'][0]['target_group']['id']=='7777777777777777'; assert {t['registered_port'] for t in targets(r)}=={8081,8091}
def test_healthy_does_not_imply_allowed():
    r=run(); t=targets(r)[0]; assert t['health_state']=='healthy' and t['policy_status']=='RULE_BLOCK_CANDIDATE'; assert r['session_status']=='UNKNOWN' and r['target_selection']=='NOT_EVALUATED'
def test_nlb_preserved():
    r=run('nlb'); assert r['backend_source_ip_kind']=='CLIENT_IPV4_CANDIDATE'; assert targets(r)[0]['policy_checks'][0]['status']=='BLOCKED'
def test_nlb_translated_unknown():
    r=run('nlb',attributes_raw=read('nlb_attributes_translate.json')); assert r['backend_source_ip_kind']=='LB_NODE_IPV4_UNCONFIRMED'; assert r['policy_status']=='NOT_EVALUATED'
def test_nlb_translated_hypothetical():
    r=run('nlb',attributes_raw=read('nlb_attributes_translate.json'),backend_node_ip='10.0.1.50'); assert r['backend_source_ip_kind']=='HYPOTHETICAL_LB_NODE_IPV4'; assert targets(r)[0]['policy_checks']
def test_alb_no_node():
    assert run(backend_node_ip=None)['policy_status']=='NOT_EVALUATED'
@pytest.mark.parametrize('ip',['10.0.3.50','10.0.1.1','10.0.1.255','10.0.1.10','10.0.2.30'])
def test_node_scope(ip): assert run(backend_node_ip=ip)['reason']=='HYPOTHETICAL_NODE_ADDRESS_OUT_OF_SCOPE'
@pytest.mark.parametrize('port',[0,65536,True])
def test_source_port_invalid(port):
    with pytest.raises(ValueError):run(backend_source_port=port)
def test_reply_port():
    r=run(backend_source_port=50000); assert targets(r)[0]['policy_checks'][-1]['status']=='ALLOW_CANDIDATE'
def test_reply_port_missing(): assert targets(run())[0]['policy_checks'][-1]['status']=='UNKNOWN'
def test_health_incomplete(): assert run(health=mutate(lambda d:d.update(complete=False)))['status']=='UNKNOWN'
def test_health_identity(): assert run(health=mutate(lambda d:d.update(elbv2_input_identity='wrong')))['status']=='UNKNOWN'
def test_health_time(): assert run(health=mutate(lambda d:d.update(collected_at='2026-11-25T11:06:00+00:00')))['reason']=='SNAPSHOT_TIME_GAP'
def test_missing_group(): assert run(health=mutate(lambda d:d.update(target_groups=[])))['status']=='UNKNOWN'
def test_duplicate_group():
    with pytest.raises(ValueError):run(health=mutate(lambda d:d['target_groups'].append(d['target_groups'][0])))
def test_duplicate_registration():
    def m(d):
        for g in d['target_groups']:g['TargetHealthDescriptions'].append(g['TargetHealthDescriptions'][0])
    with pytest.raises(ValueError):run(health=mutate(m))
def test_all_unhealthy():
    def m(d):
        for g in d['target_groups']:
            for t in g['TargetHealthDescriptions']:t['TargetHealth']['State']='unhealthy'
    assert run(health=mutate(m))['groups'][0]['health_warning']=='NO_HEALTHY_TARGETS_FAIL_OPEN_POSSIBLE'
def test_empty_group():
    def m(d):
        for g in d['target_groups']:g['TargetHealthDescriptions']=[]
    assert run(health=mutate(m))['groups'][0]['health_warning']=='EMPTY_TARGET_GROUP'
def test_missing_endpoint():
    def m(d):
        for g in d['target_groups']:g['TargetHealthDescriptions'][0]['Target']['Id']='i-aaaaaaaa'
    assert targets(run(health=mutate(m)))[0]['policy_status']=='NOT_EVALUATED'
def test_mismatched_zone():
    def m(d):
        for g in d['target_groups']:g['TargetHealthDescriptions'][0]['Target']['AvailabilityZone']='ap-northeast-2b'
    assert targets(run(health=mutate(m)))[0]['zone_status']=='UNKNOWN'
def test_rules_required():assert run(rules_raw=None)['reason']=='ALB_RULE_EVIDENCE_REQUIRED'
def test_attributes_required():assert run('nlb',attributes_raw=None)['reason']=='NLB_ATTRIBUTES_REQUIRED'
def test_no_live_assertion():
    r=run(); assert not r['live_observation'] and r['session_status']=='UNKNOWN'; assert all(x['evaluation_mode']=='INDEPENDENT_RULE_CHECK' for t in targets(r) for x in t['policy_checks'])

def test_positive_target_rule_match():
    inv=json.loads(read('elbv2_inventory.json'))
    inv['inventory']['SecurityGroups'][0]['IpPermissions'][0]['ToPort']=9000
    r=inspect_elb_targets(encode(inv),read('elbv2_rule_evidence.json'),read('alb_target_health.json'),'1111111111111111',443,'10.0.1.10',rules_raw=read('alb_rules.json'),host='api.example.com',path='/api/items',backend_node_ip='10.0.1.50',backend_source_port=50000)
    assert targets(r)[0]['policy_status']=='RULE_ALLOW_CANDIDATE'; assert r['session_status']=='UNKNOWN'
def test_ip_registration():
    import hashlib
    elb=json.loads(read('elbv2_evidence.json'))
    for g in elb['TargetGroups']:
        if g['TargetGroupArn'].endswith('6666666666666666'):g['TargetType']='ip'
    raw=encode(elb); fp='sha256-elbv2-v1:'+hashlib.sha256(raw).hexdigest()
    attrs=json.loads(read('nlb_attributes_preserve.json')); attrs['elbv2_input_identity']=fp
    h=json.loads(read('nlb_target_health.json')); h['elbv2_input_identity']=fp
    for t,ip in zip(h['target_groups'][0]['TargetHealthDescriptions'],['10.0.2.10','10.0.1.10']):t['Target']['Id']=ip
    r=inspect_elb_targets(read('elbv2_inventory.json'),raw,encode(h),'2222222222222222',443,'10.0.1.10',attributes_raw=encode(attrs))
    assert targets(r)[0]['endpoint']['instance_id']=='i-87654321'
