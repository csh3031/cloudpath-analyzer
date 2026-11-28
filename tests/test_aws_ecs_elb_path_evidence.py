import copy,hashlib,json
from pathlib import Path
import pytest
from backend.aws.ecs_elb_path_evidence import inspect_ecs_elb_paths
from backend.aws.peering_evidence import _load

ROOT=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
def raw(x):return json.dumps(x).encode()
def read(n):return json.loads((ROOT/(n+'.json')).read_text())
@pytest.fixture
def inputs():
    return {k:read(v) for k,v in dict(inv='ecs_elb_path_inventory',ecs='ecs_service_tasks',svc='ecs_service_evidence',elb='ecs_elb_path_elbv2',health='ecs_elb_path_health',alb='ecs_elb_path_alb_nodes',nlb='ecs_elb_path_nlb_nodes',rules='alb_rules',translate='ecs_elb_path_nlb_translate',preserve='ecs_elb_path_nlb_preserve').items()}
def run(x,mode='alb',bind=True,**kwargs):
    nlb=mode!='alb';node=x['nlb' if nlb else 'alb']; attrs=x[mode] if nlb else None
    if bind:
        node['inventory_identity']=_load(raw(x['inv']))[0]; ident='sha256-elbv2-v1:'+hashlib.sha256(raw(x['elb'])).hexdigest()
        node['elbv2_input_identity']=x['health']['elbv2_input_identity']=ident
        if attrs is not None:attrs['elbv2_input_identity']=ident
        x['svc']['ecs_input_identity']='sha256-ecs-task-v1:'+hashlib.sha256(raw(x['ecs'])).hexdigest()
    opts=dict(node_eni_id='eni-55555556' if nlb else 'eni-55555555',client_port=50000,backend_source_port=51000,health_source_port=52000)
    opts.update(kwargs)
    return inspect_ecs_elb_paths(*(raw(x[k]) for k in ('inv','ecs','svc','elb','health')),raw(node),'arn:aws:ecs:ap-northeast-2:000000000000:service/demo/'+('demo-tcp' if nlb else 'demo-api'),'2'*16 if nlb else '1'*16,443,'10.0.1.10',**opts,**({'attributes_raw':raw(attrs)} if nlb else {'rules_raw':raw(x['rules']),'host':'api.example.com','path':'/api/items'}))
def test_alb(inputs):
    r=run(inputs); t=r['targets'][0];assert r['status']=='ECS_ELB_PATH_CONSTRAINTS_CANDIDATE';assert t['backend_status']=='CONDITIONAL_CANDIDATE';assert t['health_check_status']=='BLOCKED';assert t['composition_status']=='TWO_LEGS_CONDITIONAL_CANDIDATE';assert r['session_status']=='UNKNOWN' and r['target_selection']=='NOT_EVALUATED' and not r['live_observation'];assert t['backend']['request'][-1]['reason']=='MATCHING_DIRECT_PEER_SG_REFERENCE'
def test_nlb_translate(inputs):
    r=run(inputs,'translate');t=r['targets'][0];assert t['backend_status']=='BLOCKED' and t['backend_reason']=='DESTINATION_SG_INGRESS';assert t['health_check_status']=='CONDITIONAL_CANDIDATE';assert t['backend']['source_ip']=='10.0.3.51';assert t['backend']['response_status']=='NOT_EVALUATED';assert all(z['evaluation_mode']=='INDEPENDENT_CHECK' for z in t['backend']['response'])
def test_preserve(inputs):
    t=run(inputs,'preserve')['targets'][0];assert t['backend'] is None and t['backend_source_ip_candidate']=='10.0.1.10' and t['backend_reason']=='NLB_PRESERVED_CLIENT_PATH_NOT_COMPOSED';assert t['health_check_status']=='CONDITIONAL_CANDIDATE'
@pytest.mark.parametrize('key,value,reason',[('complete',False,'NODE_EVIDENCE_IDENTITY_OR_COMPLETENESS_UNCONFIRMED'),('load_balancer_arn','arn:aws:elasticloadbalancing:ap-northeast-2:000000000000:loadbalancer/net/demo-net/2222222222222222','NODE_EVIDENCE_IDENTITY_OR_COMPLETENESS_UNCONFIRMED'),('collected_at','2026-11-25T11:06:00+00:00','SNAPSHOT_TIME_GAP')])
def test_wrapper(inputs,key,value,reason):
    inputs['alb'][key]=value;assert run(inputs)['reason']==reason
@pytest.mark.parametrize('key,value',[('private_ip','10.0.3.52'),('subnet_id','subnet-12345678'),('eni_id','eni-77777777')])
def test_node_record(inputs,key,value):
    inputs['alb']['nodes'][0][key]=value;assert run(inputs)['status']=='UNKNOWN'
@pytest.mark.parametrize('key,value',[('Status','available'),('RequesterManaged',False),('InterfaceType','interface'),('Attachment',{'InstanceId':'i-12345678','DeviceIndex':1}),('Groups',[]),('PrivateIpAddresses',[{'PrivateIpAddress':'10.0.3.50','Primary':False}]),('Association',{'PublicIp':'198.51.100.5'})])
def test_eni_mismatch(inputs,key,value):
    inputs['inv']['inventory']['NetworkInterfaces'][-2][key]=value;assert run(inputs)['reason']=='LB_NODE_ENI_UNCONFIRMED'
def test_node_identity(inputs):
    assert run(inputs,bind=False)['status']=='UNKNOWN'
def test_wrong_node(inputs):
    assert run(inputs,node_eni_id='eni-55555556')['reason']=='SELECTED_NODE_NOT_IN_EVIDENCE'
def test_duplicate_node(inputs):
    inputs['alb']['nodes']*=2
    with pytest.raises(ValueError):run(inputs)
@pytest.mark.parametrize('port',[0,65536,True])
def test_port(inputs,port):
    with pytest.raises(ValueError):run(inputs,client_port=port)
def test_group_conflict(inputs):
    inputs['elb']['LoadBalancers'][0]['SecurityGroups']=['sg-12345678'];assert run(inputs)['reason']=='LB_NODE_ENI_UNCONFIRMED'
def test_external(inputs):
    inputs['elb']['LoadBalancers'][0]['Scheme']='internet-facing';assert run(inputs)['reason']=='INTERNAL_PRIMARY_VPC_SCOPE_REQUIRED'
@pytest.mark.parametrize('enabled',[False,None])
def test_cross_zone(inputs,enabled):
    inputs['alb']['alb_cross_zone_enabled']=enabled;t=run(inputs)['targets'][0];assert t['backend_reason']=='CROSS_ZONE_ELIGIBILITY_UNCONFIRMED' and t['health_check'] is not None
@pytest.mark.parametrize('field,value',[('enabled',False),('protocol','UDP'),('port',0),('path',None)])
def test_bad_health(inputs,field,value):
    inputs['alb']['health_check'][field]=value;t=run(inputs)['targets'][0];assert t['health_check_reason']=='HEALTH_CONFIGURATION_UNSUPPORTED' and t['backend_status']=='CONDITIONAL_CANDIDATE'
def test_health_traffic_port(inputs):
    inputs['alb']['health_check']['port']='traffic-port';t=run(inputs)['targets'][0];assert t['health_check_status']=='CONDITIONAL_CANDIDATE' and t['health_check']['destination_port']==8081
def test_front_block_independent(inputs):
    inputs['inv']['inventory']['SecurityGroups'][-1]['IpPermissions']=[];r=run(inputs);assert r['frontend']['request_status']=='BLOCKED';assert r['targets'][0]['backend_status']=='CONDITIONAL_CANDIDATE';assert r['targets'][0]['composition_status']=='UNKNOWN'
def test_health_history_independent(inputs):
    inputs['health']['target_groups'][0]['TargetHealthDescriptions'][0]['TargetHealth']['State']='unhealthy';t=run(inputs)['targets'][0];assert t['health_state']=='unhealthy' and t['backend_status']=='CONDITIONAL_CANDIDATE'
def test_no_registration(inputs):
    inputs['health']['target_groups'][0]['TargetHealthDescriptions']=[];assert run(inputs)['reason']=='SERVICE_CORRELATION_UNCONFIRMED'
def test_return_port(inputs):
    t=run(inputs)['targets'][0]['backend'];assert t['source_port']==51000 and t['response_status']=='CONDITIONAL_CANDIDATE';assert t['response'][0]['status']=='CONDITIONAL'
def test_nlb_proxy(inputs):
    for a in inputs['translate']['TargetGroupAttributes']:
        if a['Key']=='proxy_protocol_v2.enabled':a['Value']='true'
    assert run(inputs,'translate')['targets'][0]['backend_reason']=='NLB_PROXY_PROTOCOL_SCOPE_UNSUPPORTED'
def test_nlb_cross_zone(inputs):
    inputs['translate']['LoadBalancerAttributes'][0]['Value']='false';assert run(inputs,'translate')['targets'][0]['backend_reason']=='CROSS_ZONE_ELIGIBILITY_UNCONFIRMED'

def test_prefix_list(inputs):
    inv=inputs['inv']['inventory'];inv['SecurityGroups'][0]['IpPermissions'][-1]=dict(IpProtocol='tcp',FromPort=8081,ToPort=8081,PrefixListIds=[dict(PrefixListId='pl-11111111')])
    prefix=read('ecs_prefix_list_evidence');prefix['inventory_identity']=_load(raw(inputs['inv']))[0];prefix['prefix_lists'][0]['entries']=['10.0.3.0/24']
    t=run(inputs,prefix_list_raw=raw(prefix))['targets'][0];assert t['backend_status']=='CONDITIONAL_CANDIDATE';assert t['backend']['request'][-1]['reason']=='MATCHING_IPV4_PREFIX_LIST_RULE'
    t=run(inputs)['targets'][0];assert t['backend_status']=='UNKNOWN'

def test_same_subnet(inputs):
    e=inputs['inv']['inventory']['NetworkInterfaces'][-2];e['SubnetId']='subnet-12345678';e['PrivateIpAddress']='10.0.1.50';e['PrivateIpAddresses']=[dict(PrivateIpAddress='10.0.1.50',Primary=True)]
    inputs['alb']['nodes'][0].update(private_ip='10.0.1.50',subnet_id='subnet-12345678');r=run(inputs);assert r['frontend']['request_status']=='CONDITIONAL_CANDIDATE';assert r['targets'][0]['backend_status']=='CONDITIONAL_CANDIDATE';assert r['targets'][0]['backend']['request'][1]['status']=='NOT_APPLICABLE'

def test_nlb_without_sg(inputs):
    inputs['elb']['LoadBalancers'][1]['SecurityGroups']=[];inputs['inv']['inventory']['NetworkInterfaces'][-1]['Groups']=[]
    r=run(inputs,'translate');assert r['frontend']['request'][-1]['status']=='NOT_APPLICABLE';assert r['targets'][0]['health_check']['request'][0]['status']=='NOT_APPLICABLE'

def test_health_group(inputs):
    inputs['alb']['health_check']['target_group_arn']=inputs['elb']['TargetGroups'][0]['TargetGroupArn'];assert run(inputs)['reason']=='HEALTH_GROUP_IDENTITY_MISMATCH'
