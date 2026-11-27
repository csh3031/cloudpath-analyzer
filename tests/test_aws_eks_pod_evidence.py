import json
from pathlib import Path
import pytest
from backend.aws.eks_pod_evidence import inspect_eks_pod
from backend.aws.peering_evidence import _load

ROOT=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
@pytest.fixture
def inputs():
    return [json.loads((ROOT/n).read_text()) for n in ('eks_pod_inventory.json','eks_pod_evidence.json')]

def run(inputs,pod='app-1',ns='demo',bind=True):
    a,b=inputs; raw=json.dumps(a).encode()
    if bind: b['inventory_identity']=_load(raw)[0]
    return inspect_eks_pod(raw,json.dumps(b).encode(),ns,pod)

@pytest.mark.parametrize('pod,ip,eni,instance',[('app-1','10.0.1.70','eni-12345678','i-12345678'),('app-2','10.0.2.70','eni-87654321','i-87654321')])
def test_candidate(inputs,pod,ip,eni,instance):
    r=run(inputs,pod)
    assert r['status']=='POD_ENDPOINT_CANDIDATE'
    assert r['endpoint']['private_ip']==ip and r['endpoint']['eni_id']==eni
    assert r['node']['instance_id']==instance and r['endpoint']['kind']=='EKS_POD'
    assert r['node']['private_ip']!=ip and r['endpoint']['eni_security_group_ids']==['sg-12345678']
    assert r['policy_status']==r['route_status']=='NOT_EVALUATED'
    assert r['session_status']=='UNKNOWN' and r['live_observation'] is False

@pytest.mark.parametrize('mutation,reason',[
 ('identity','INVENTORY_IDENTITY_MISMATCH'),('incomplete','EKS_EVIDENCE_INCOMPLETE'),('time','SNAPSHOT_TIME_GAP'),
 ('cluster_vpc','CLUSTER_SCOPE_MISMATCH'),('cluster_status','CLUSTER_NOT_ACTIVE'),('cluster_subnet','CLUSTER_SUBNETS_UNCONFIRMED'),
 ('prefix','UNSUPPORTED_OR_UNCONFIRMED_CNI_PROFILE'),('branch','UNSUPPORTED_OR_UNCONFIRMED_CNI_PROFILE'),('custom','UNSUPPORTED_OR_UNCONFIRMED_CNI_PROFILE'),('auto','UNSUPPORTED_OR_UNCONFIRMED_CNI_PROFILE'),
 ('namespace','NAMESPACE_UNCONFIRMED'),('missing_pod','POD_NOT_FOUND'),('pending','POD_NOT_RUNNING'),('terminating','POD_NOT_RUNNING'),
 ('host_network','HOST_NETWORK_UNSUPPORTED'),('missing_node','NODE_UNCONFIRMED'),('provider','UNSUPPORTED_NODE_PROVIDER'),('fargate','UNSUPPORTED_NODE_PROVIDER'),('duplicate_provider','NODE_PROVIDER_AMBIGUOUS'),
 ('stopped','NODE_INSTANCE_UNCONFIRMED'),('zone','NODE_AZ_OR_SUBNET_MISMATCH'),('host_ip','NODE_HOST_IP_MISMATCH'),('primary','NODE_PRIMARY_ENI_UNCONFIRMED'),
 ('ipv6','POD_IPV4_UNCONFIRMED'),('dual','POD_IP_LIST_UNSUPPORTED'),('outside','POD_SUBNET_OR_CIDR_UNSUPPORTED'),('duplicate_pod_ip','POD_IP_AMBIGUOUS'),('host_primary','POD_IP_IS_INSTANCE_PRIMARY'),
 ('missing_ip','POD_ENI_MISSING_OR_AMBIGUOUS'),('duplicate_eni_ip','POD_ENI_MISSING_OR_AMBIGUOUS'),('no_secondary_flag','POD_SECONDARY_IP_UNCONFIRMED'),('managed','POD_ENI_NODE_ATTACHMENT_UNCONFIRMED'),('groups','POD_ENI_GROUPS_UNCONFIRMED'),('containers','POD_CONTAINERS_UNCONFIRMED')])
def test_unknown(inputs,mutation,reason):
    a,b=inputs; inv=a['inventory']; p=b['pods'][0]; n=b['nodes'][0]; e=inv['NetworkInterfaces'][0]; i=inv['Reservations'][0]['Instances'][0]
    if mutation=='identity': b['inventory_identity']='invalid'
    elif mutation=='incomplete': b['complete']=False
    elif mutation=='time': b['collected_at']='2026-11-25T11:06:00+00:00'
    elif mutation=='cluster_vpc': b['cluster']['resourcesVpcConfig']['vpcId']='vpc-aaaaaaaa'
    elif mutation=='cluster_status': b['cluster']['status']='CREATING'
    elif mutation=='cluster_subnet': b['cluster']['resourcesVpcConfig']['subnetIds']=['subnet-aaaaaaaa']
    elif mutation in ('prefix','branch','custom','auto'): b['cni'][{'prefix':'prefix_delegation','branch':'security_groups_for_pods','custom':'custom_networking','auto':'auto_mode'}[mutation]]=True
    elif mutation=='namespace': b['namespaces'][0]['status']['phase']='Terminating'
    elif mutation=='missing_pod': b['pods'].pop(0)
    elif mutation=='pending': p['status']['phase']='Pending'
    elif mutation=='terminating': p['metadata']['deletionTimestamp']='2026-11-25T11:00:00Z'
    elif mutation=='host_network': p['spec']['hostNetwork']=True
    elif mutation=='missing_node': p['spec']['nodeName']='other'
    elif mutation=='provider': n['spec']['providerID']='invalid'
    elif mutation=='fargate': n['metadata']['labels']['eks.amazonaws.com/compute-type']='fargate'
    elif mutation=='duplicate_provider': b['nodes'][1]['spec']['providerID']=n['spec']['providerID']
    elif mutation=='stopped': i['State']['Name']='stopped'
    elif mutation=='zone': n['metadata']['labels']['topology.kubernetes.io/zone']='ap-northeast-2c'
    elif mutation=='host_ip': p['status']['hostIP']='10.0.1.99'
    elif mutation=='primary': e['Attachment']['DeviceIndex']=1
    elif mutation in ('ipv6','outside','host_primary'):
        ip={'ipv6':'::1','outside':'10.1.1.70','host_primary':'10.0.1.10'}[mutation];p['status'].update(podIP=ip,podIPs=[{'ip':ip}])
    elif mutation=='dual': p['status']['podIPs'].append({'ip':'::1'})
    elif mutation=='duplicate_pod_ip': b['pods'][1]['status']['podIP']=p['status']['podIP']
    elif mutation=='missing_ip': e['PrivateIpAddresses'].pop()
    elif mutation=='duplicate_eni_ip': inv['NetworkInterfaces'][1]['PrivateIpAddresses'].append({'PrivateIpAddress':'10.0.1.70','Primary':False})
    elif mutation=='no_secondary_flag': e['PrivateIpAddresses'][-1].pop('Primary')
    elif mutation=='managed': e['RequesterManaged']=True
    elif mutation=='groups': e['Groups']=[]
    elif mutation=='containers': p['spec']['containers']=[]
    r=run(inputs,bind=mutation!='identity')
    assert r['status']=='UNKNOWN' and r['reason']==reason and r['endpoint'] is None
    assert r['session_status']=='UNKNOWN'

@pytest.mark.parametrize('mutation',['format','duplicate_node','duplicate_pod','uid','invalid_namespace'])
def test_invalid(inputs,mutation):
    _,b=inputs;ns='demo'
    if mutation=='format': b['format']='bad'
    elif mutation=='duplicate_node': b['nodes'].append(b['nodes'][0])
    elif mutation=='duplicate_pod': b['pods'].append(b['pods'][0])
    elif mutation=='uid': b['pods'][0]['metadata']['uid']='bad'
    elif mutation=='invalid_namespace': ns='INVALID'
    with pytest.raises(ValueError): run(inputs,ns=ns)

def test_secondary_eni(inputs):
    a,_=inputs; inv=a['inventory']; first=inv['NetworkInterfaces'][0]; sec=dict(first,NetworkInterfaceId='eni-55555555',PrivateIpAddress='10.0.1.71',Attachment={'InstanceId':'i-12345678','DeviceIndex':1},PrivateIpAddresses=[{'PrivateIpAddress':'10.0.1.71','Primary':True},first['PrivateIpAddresses'].pop()]); inv['NetworkInterfaces'].append(sec);inv['Reservations'][0]['Instances'][0]['NetworkInterfaces'].append({'NetworkInterfaceId':'eni-55555555'})
    assert run(inputs)['endpoint']['eni_id']=='eni-55555555'

def test_container_sensitive_fields_not_returned(inputs):
    inputs[1]['pods'][0]['spec']['containers'][0]['env']=[{'name':'TOKEN','value':'DO_NOT_EXPORT'}]
    assert 'DO_NOT_EXPORT' not in json.dumps(run(inputs))
