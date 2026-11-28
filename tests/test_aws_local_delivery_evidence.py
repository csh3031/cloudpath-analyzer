"""Direct same-subnet / node-local regressions; entirely synthetic snapshots."""
import copy, json, hashlib
from pathlib import Path
import pytest
from backend.aws.session_evidence import analyze_observed_session
from backend.aws.eks_session_evidence import analyze_eks_pod_session
from backend.aws.peering_evidence import _load
from backend.aws.ecs_session_evidence import analyze_ecs_task_session
from test_aws_forwarding_evidence import pair, SRC, S
from test_aws_inventory import raw, G
from test_aws_web_session import app
from test_aws_local_path_display import plan
from test_attachment_topology import payload
P=Path('samples/aws/phase7_demo')
DST='10.0.1.11'

def ec2():
    d=pair(DST,S); inv=d['inventory']; inv['SecurityGroups'][0]['IpPermissionsEgress']=[dict(IpProtocol='-1',IpRanges=[dict(CidrIp='0.0.0.0/0')])]; return d

def run(d,port=443): return analyze_observed_session(raw(d),SRC,DST,50000,port)

def test_ec2_deny_acl_not_applied():
    d=ec2();d['inventory']['NetworkAcls'][0]['Entries']=[dict(RuleNumber=100,Protocol='-1',RuleAction='deny',Egress=x,CidrBlock='0.0.0.0/0') for x in (True,False)]
    r=run(d);assert r['request']['status']==r['response']['status']=='REACHABLE' and r['predicted_connectivity']=='UNKNOWN'
    assert all(f['status']=='NOT_APPLICABLE' for f in r['findings'] if '_NACL_' in f['stage'])
    assert r['evidence']['forwarding']['request']['route_lookup'] is None

@pytest.mark.parametrize('field,stage',[('IpPermissionsEgress','SOURCE_SG_EGRESS'),('IpPermissions','DESTINATION_SG_INGRESS')])
def test_ec2_sg_block(field,stage):
    d=ec2();d['inventory']['SecurityGroups'][0][field]=[];r=run(d);assert r['first_blocker']=='request:'+stage and r['predicted_connectivity']=='BLOCKED' and not r['response']['trace']

def test_ec2_self_reference():
    d=ec2();d['inventory']['SecurityGroups'][0]['IpPermissions']=[dict(IpProtocol='tcp',FromPort=443,ToPort=443,UserIdGroupPairs=[dict(GroupId=G)])];r=run(d);assert r['request']['status']=='REACHABLE' and r['findings'][5]['reason']=='MATCHING_DIRECT_PEER_SG_REFERENCE'

@pytest.mark.parametrize('mode',['blackhole','missing','middlebox','prefix','propagation','association'])
def test_nonstandard_route_unknown(mode):
    d=ec2();t=d['inventory']['RouteTables'][0]
    if mode=='blackhole':t['Routes'][0]['State']='blackhole'
    elif mode=='missing':t['Routes']=[]
    elif mode=='middlebox':t['Routes'][0].pop('GatewayId');t['Routes'][0]['NetworkInterfaceId']='eni-12345678'
    elif mode=='prefix':t['Routes'].append(dict(DestinationPrefixListId='pl-12345678',GatewayId='local',State='active'))
    elif mode=='propagation':t['PropagatingVgws']=[dict(GatewayId='vgw-12345678')]
    else:t['Associations'][0]['AssociationState']['State']='associating'
    r=run(d);assert r['request']['status']=='UNKNOWN' and r['first_blocker'] is None and r['request']['trace']==['request:ENDPOINT_SCOPE']

def test_web_skip_anchors():
    a=app(ec2());b=dict(source=next(i for i,e in enumerate(a.endpoints) if e['ip']==SRC),destination=next(i for i,e in enumerate(a.endpoints) if e['ip']==DST),protocol='tcp',source_port=50000,destination_port=443,input_identity=a.identity)
    r=a.analyze_aws(b);g=payload(a)['network_graph'];
    for direction in ('request','response'):
        p=plan(r,g,direction);assert p['complete']; assert [x['stage'] for x in p['anchors']]==['SOURCE_ENDPOINT','SOURCE_SG_EGRESS','DESTINATION_SG_INGRESS','DESTINATION_ENDPOINT'];assert p['path_kind']=='SAME_SUBNET_DIRECT';assert not any('network_acl' in x['id'] or 'route_table' in x['id'] for x in p['anchors'])

def pod_inputs(same_node):
    inv=json.loads((P/'eks_pod_inventory.json').read_bytes());eks=json.loads((P/'eks_policy_pods.json').read_bytes());pol=json.loads((P/'eks_network_policy_evidence.json').read_bytes()); i=inv['inventory'];p=eks['pods'][1];e=i['NetworkInterfaces'][1];inst=i['Reservations'][0]['Instances'][1]
    # move pod 2 to the first subnet; preserve distinct node for cross-node tests
    if same_node:
        e['PrivateIpAddresses']=[x for x in e['PrivateIpAddresses'] if x['PrivateIpAddress']!='10.0.2.70'];i['NetworkInterfaces'][0]['PrivateIpAddresses'].append(dict(PrivateIpAddress='10.0.1.71',Primary=False));p['spec']['nodeName']='node-1';p['status']['hostIP']='10.0.1.10'
    else:
        inst.update(SubnetId=S,PrivateIpAddress='10.0.1.20');e.update(SubnetId=S,PrivateIpAddress='10.0.1.20',PrivateIpAddresses=[dict(PrivateIpAddress='10.0.1.20',Primary=True),dict(PrivateIpAddress='10.0.1.71',Primary=False)]);n=eks['nodes'][1];n['metadata']['labels']['topology.kubernetes.io/zone']='ap-northeast-2a';n['spec']['providerID']='aws:///ap-northeast-2a/i-87654321';n['status']['addresses'][0]['address']='10.0.1.20';p['status']['hostIP']='10.0.1.20'
    p['status']['podIP']='10.0.1.71';p['status']['podIPs']=[dict(ip='10.0.1.71')]
    i['NetworkAcls'][0]['Entries']=[dict(RuleNumber=100,Protocol='-1',RuleAction='deny',Egress=x,CidrBlock='0.0.0.0/0') for x in (True,False)]
    return inv,eks,pol

def pod_run(data,port=443):
    inv,eks,pol=copy.deepcopy(data);ir=raw(inv);eks['inventory_identity']=_load(ir)[0];er=raw(eks);pol['eks_input_identity']='sha256-eks-pod-v1:'+hashlib.sha256(er).hexdigest();return analyze_eks_pod_session(ir,er,raw(pol),'demo','app-1','demo','app-2',50000,port)

@pytest.mark.parametrize('node',[False,True])
@pytest.mark.parametrize('port',[443,8080,8443])
def test_pod_modes(node,port):
    r=pod_run(pod_inputs(node),port); assert r['path_kind']==('SAME_NODE_POD_DIRECT' if node else 'SAME_SUBNET_DIRECT'),r
    expected='BLOCKED' if port==8080 or (port==8443 and not node) else 'CONDITIONAL_CANDIDATE';assert r['request_status']==expected
    assert all(x['status']=='NOT_APPLICABLE' for x in r['request'] if '_NACL_' in x['stage'])
    if node:assert all(x['status']=='NOT_APPLICABLE' for x in r['request'] if '_SG_' in x['stage'])
    assert r['session_status']==('BLOCKED' if expected=='BLOCKED' else 'UNKNOWN')

def test_node_policy_profile_unknown():
    d=pod_inputs(True);d[2]['profile']['settled']=False;r=pod_run(d);assert r['request_status']=='UNKNOWN' and r['first_request_stop']=='SOURCE_NETWORK_POLICY_EGRESS';assert all(x['status']=='UNKNOWN' for x in r['request'] if '_SG_' in x['stage'] or '_NACL_' in x['stage'])

def test_same_node_ingress_deny():
    d=pod_inputs(True);d[2]['networkPolicies'][1]['spec']['ingress']=[];r=pod_run(d);assert r['first_request_stop']=='DESTINATION_NETWORK_POLICY_INGRESS'


def test_same_subnet_web_guard_missing():
    a=app(ec2());b=dict(source=next(i for i,e in enumerate(a.endpoints) if e['ip']==SRC),destination=next(i for i,e in enumerate(a.endpoints) if e['ip']==DST),protocol='tcp',source_port=50000,destination_port=443,input_identity=a.identity)
    r=a.analyze_aws(b);g=payload(a)['network_graph'];g['route_rules']=[];p=plan(r,g);assert not p['complete'] and p['stop']=='ROUTE_LOOKUP'


def test_same_node_cni_events_unresolved():
    from backend.aws.eks_cni_evidence import inspect_eks_cni
    inv,eks,pol=pod_inputs(True);ir=raw(inv);eks['inventory_identity']=_load(ir)[0];er=raw(eks);pol['eks_input_identity']='sha256-eks-pod-v1:'+hashlib.sha256(er).hexdigest();pr=raw(pol)
    obs=json.loads((P/'eks_cni_observation.json').read_bytes());obs.update(eks_input_identity=pol['eks_input_identity'],policy_input_identity='sha256-eks-network-policy-v1:'+hashlib.sha256(pr).hexdigest())
    r=inspect_eks_cni(ir,er,pr,raw(obs),'demo','app-1','demo','app-2',50000,443);assert r['reason']=='SAME_NODE_EVENT_DIRECTION_UNCONFIRMED' and r['comparisons']==[] and r['session_status']=='UNKNOWN'


def test_cross_node_same_subnet_service():
    from backend.aws.eks_service_session_evidence import analyze_eks_service_session
    inv,eks,_=pod_inputs(False);ir=raw(inv);base=json.loads((P/'eks_service_session_pods.json').read_bytes());base['inventory_identity']=_load(ir)[0];base['nodes']=eks['nodes']
    base['pods'][1]['status']=eks['pods'][1]['status'];er=raw(base);eid='sha256-eks-pod-v1:'+hashlib.sha256(er).hexdigest()
    svc=json.loads((P/'eks_service_session_services.json').read_bytes());pol=json.loads((P/'eks_service_session_policy.json').read_bytes());tr=json.loads((P/'eks_service_translation_evidence.json').read_bytes())
    svc['eks_input_identity']=pol['eks_input_identity']=tr['eks_input_identity']=eid
    for sl in svc['endpointSlices']:
        for ep in sl['endpoints']:
            if ep['targetRef']['name']=='app-2':ep['addresses']=['10.0.1.71']
    sr,pr=raw(svc),raw(pol);tr['service_input_identity']='sha256-eks-service-v1:'+hashlib.sha256(sr).hexdigest();tr['policy_input_identity']='sha256-eks-network-policy-v1:'+hashlib.sha256(pr).hexdigest()
    r=analyze_eks_service_session(ir,er,sr,pr,raw(tr),'demo','app-1','demo','demo-tls-443',50000,443);assert r['backend_summary']=='ALL_BACKEND_CHECKS_CONDITIONAL',r
    assert r['branches'][0]['backend_check']['path_kind']=='SAME_SUBNET_DIRECT'
