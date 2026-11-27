import json
from pathlib import Path
import pytest
from backend.aws.elb_path_evidence import inspect_elb_paths

P=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
def read(n): return (P/n).read_bytes()
def encode(d): return json.dumps(d).encode()
def run(kind='alb',edit=None,inventory=None,**kw):
    alb=kind=='alb'; evidence=json.loads(read(f'{kind}_path_evidence.json'))
    if edit: edit(evidence)
    args=dict(frontend_node_ip='10.0.2.50',backend_node_ip='10.0.1.50',client_port=50000,backend_source_port=51000,health_source_port=52000)
    args.update(dict(rules_raw=read('alb_rules.json'),host='api.example.com',path='/api/items') if alb else dict(attributes_raw=read('nlb_attributes_translate.json')))
    args.update(kw)
    return inspect_elb_paths(inventory or read('elbv2_inventory.json'),read('elbv2_rule_evidence.json' if alb else 'elbv2_evidence.json'),read(f'{kind}_target_health.json'),encode(evidence),'1111111111111111' if alb else '2222222222222222',443,'10.0.1.10',**args)
def first(r): return r['targets'][0]
def stage(flow,name,side='request'): return next(x for x in flow[side] if x['stage']==name)

def test_alb_separate_flows():
    r=run(); t=first(r); assert r['status']=='ELB_PATH_CONSTRAINTS_CANDIDATE'; assert r['frontend']['request_status']=='CONDITIONAL_CANDIDATE'; assert t['backend_status']=='RULE_BLOCK_CANDIDATE'; assert t['health_check_status']=='CONDITIONAL_CANDIDATE'
    assert (r['frontend']['destination_port'],t['backend']['destination_port'],t['health_check']['destination_port'])==(443,8081,443)
def test_registered_port_override(): assert run()['targets'][1]['backend']['destination_port']==8091
def test_health_traffic_port():
    r=run(edit=lambda d:[x.update(port='traffic-port') for x in d['health_checks']]); assert first(r)['health_check']['destination_port']==8081; assert first(r)['health_check_status']=='RULE_BLOCK_CANDIDATE'
def test_distinct_reply_ports():
    r=run(); t=first(r); assert r['frontend']['source_port']==50000 and t['backend']['source_port']==51000 and t['health_check']['source_port']==52000
    assert stage(t['backend'],'DESTINATION_SG_REPLY','response')['status']=='CONDITIONAL'
def test_reverse_route_independent():
    f=run()['frontend']; assert stage(f,'LOCAL_ROUTE')['route_evidence']['route_table_id']=='rtb-87654321'; assert stage(f,'LOCAL_ROUTE','response')['route_evidence']['route_table_id']=='rtb-12345678'
def test_nlb_translation():
    r=run('nlb'); assert first(r)['backend']['source_ip']=='10.0.1.50'; assert first(r)['backend']['destination_port']==8080
def test_nlb_preservation_not_composed():
    r=run('nlb',attributes_raw=read('nlb_attributes_preserve.json')); t=first(r); assert t['backend'] is None and t['backend_status']=='UNKNOWN_PRESERVED_NLB_PATH_NOT_COMPOSED'; assert t['health_check']['source_ip']=='10.0.1.50'
def test_same_subnet_unknown(): assert run(frontend_node_ip='10.0.1.60')['frontend']['request_status']=='UNKNOWN'
@pytest.mark.parametrize('ip',['10.0.3.50','10.0.2.1','10.0.2.255','10.0.2.10'])
def test_frontend_node_scope(ip): assert run(frontend_node_ip=ip)['reason']=='NODE_OR_CLIENT_UNCONFIRMED'
@pytest.mark.parametrize('key,val',[('complete',False),('elbv2_input_identity','wrong'),('load_balancer_arn','arn:aws:elasticloadbalancing:ap-northeast-2:000000000000:loadbalancer/net/demo-net/2222222222222222')])
def test_evidence_binding(key,val): assert run(edit=lambda d:d.update({key:val}))['status']=='UNKNOWN'
def test_timestamp_gap(): assert run(edit=lambda d:d.update(collected_at='2026-11-25T11:06:00+00:00'))['reason']=='SNAPSHOT_TIME_GAP'
def test_alb_empty_sg(): assert run(edit=lambda d:d.update(security_group_ids=[]))['reason']=='LB_SECURITY_GROUPS_UNCONFIRMED'
def test_unknown_sg(): assert run(edit=lambda d:d.update(security_group_ids=['sg-aaaaaaaa']))['reason']=='LB_SECURITY_GROUPS_UNCONFIRMED'
def test_nlb_no_sg(): assert stage(run('nlb',edit=lambda d:d.update(security_group_ids=[]))['frontend'],'DESTINATION_SG_INGRESS')['status']=='NOT_APPLICABLE'
def test_no_health_config(): assert first(run(edit=lambda d:d.update(health_checks=[])))['health_check_status']=='UNKNOWN_CONFIGURATION_MISSING'
def test_health_disabled(): assert first(run(edit=lambda d:[x.update(enabled=False) for x in d['health_checks']]))['health_check_status']=='NOT_APPLICABLE_DISABLED'
@pytest.mark.parametrize('change',[{'protocol':'UDP'},{'port':0},{'path':'health'},{'enabled':None}])
def test_bad_health_config(change): assert first(run(edit=lambda d:[x.update(change) for x in d['health_checks']]))['health_check_status']=='UNKNOWN_CONFIGURATION_UNSUPPORTED'
@pytest.mark.parametrize('key',['client_port','backend_source_port','health_source_port'])
def test_bad_port(key):
    with pytest.raises(ValueError): run(**{key:0})
def test_duplicate_health():
    with pytest.raises(ValueError): run(edit=lambda d:d['health_checks'].append(d['health_checks'][0]))
def test_no_live_claim():
    r=run(); assert r['session_status']=='UNKNOWN' and not r['live_observation']; assert r['target_analysis']['target_selection']=='NOT_EVALUATED'; assert all(x['evaluation_mode']=='INDEPENDENT_RULE_CHECK' for x in r['frontend']['request'])
def test_target_sg_allow_positive():
    inv=json.loads(read('elbv2_inventory.json')); inv['inventory']['SecurityGroups'][0]['IpPermissions'][0]['ToPort']=9000
    assert first(run(inventory=encode(inv)))['backend_status']=='CONDITIONAL_CANDIDATE'
def test_route_blackhole():
    inv=json.loads(read('elbv2_inventory.json')); inv['inventory']['RouteTables'][1]['Routes'][0]['State']='blackhole'
    assert stage(run(inventory=encode(inv))['frontend'],'LOCAL_ROUTE')['status']=='BLOCKED'
