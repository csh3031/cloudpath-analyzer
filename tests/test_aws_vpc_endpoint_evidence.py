import hashlib,json
from pathlib import Path
import pytest
from backend.aws.vpc_endpoint_evidence import inspect_vpc_endpoint

D=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
I='vpce-11111111'; G='vpce-22222222'
@pytest.fixture
def data():
    return json.loads((D/'vpc_endpoint_inventory.json').read_text()),json.loads((D/'vpc_endpoint_configuration.json').read_text())

def run(data,eid=I,bind=True):
    inv,doc=data; raw=json.dumps(inv).encode()
    if bind: doc['inventory_identity']='sha256-aws-v2:'+hashlib.sha256(raw).hexdigest()
    return inspect_vpc_endpoint(raw,json.dumps(doc).encode(),eid)

@pytest.mark.parametrize('eid,kind,reason,count',[(I,'Interface','MATCHED_INTERFACE_ENDPOINT_ENI_CONFIGURATION',2),(G,'Gateway','MATCHED_GATEWAY_ENDPOINT_ROUTE_CONFIGURATION',2)])
def test_candidate(data,eid,kind,reason,count):
    r=run(data,eid); assert r['status']=='VPC_ENDPOINT_CONFIGURATION_CANDIDATE' and r['reason']==reason and r['endpoint_type']==kind
    assert len(r['network_interfaces' if kind=='Interface' else 'route_tables'])==count
    assert not r['route_tables' if kind=='Interface' else 'network_interfaces']
    assert r['session_status']=='UNKNOWN' and r['live_observation'] is False
    assert all(r[k]=='NOT_EVALUATED' for k in ('dns_status','route_status','policy_status','authorization_status'))
    if kind=='Gateway':assert all(x['prefix_list_membership']=='NOT_EVALUATED' for x in r['route_tables'])

@pytest.mark.parametrize('key,value,reason',[('region','us-east-1','ENDPOINT_INVENTORY_SCOPE_MISMATCH'),('complete',False,'ENDPOINT_EVIDENCE_INCOMPLETE'),('collected_at','2026-11-25T11:05:01+00:00','SNAPSHOT_TIME_GAP')])
def test_wrapper(data,key,value,reason):
    data[1][key]=value;assert run(data)['reason']==reason

def test_identity(data):assert run(data,bind=False)['reason']=='ENDPOINT_INVENTORY_SCOPE_MISMATCH'
def test_missing(data):assert run(data,'vpce-aaaaaaaa')['reason']=='VPC_ENDPOINT_MISSING'

@pytest.mark.parametrize('key,value,reason',[('VpcId','vpc-aaaaaaaa','ENDPOINT_VPC_OR_REGION_MISMATCH'),('ServiceRegion','us-west-2','ENDPOINT_VPC_OR_REGION_MISMATCH'),('State','pending','ENDPOINT_STATE_UNCONFIRMED'),('VpcEndpointType','GatewayLoadBalancer','ENDPOINT_TYPE_UNSUPPORTED'),('ServiceName','com.amazonaws.vpce.us-east-1.vpce-svc-aaaaaaaa','ENDPOINT_SERVICE_SCOPE_UNSUPPORTED'),('IpAddressType','dualstack','ENDPOINT_IPV4_PROFILE_UNCONFIRMED'),('NetworkInterfaceIds',[],'INTERFACE_RELATIONSHIPS_UNCONFIRMED'),('SubnetIds',[],'INTERFACE_RELATIONSHIPS_UNCONFIRMED'),('RouteTableIds',['rtb-12345678'],'INTERFACE_RELATIONSHIPS_UNCONFIRMED'),('PrivateDnsEnabled',None,'INTERFACE_DNS_CONFIGURATION_UNCONFIRMED'),('DnsEntries',[],'INTERFACE_DNS_CONFIGURATION_UNCONFIRMED'),('DnsEntries',[{'DnsName':'evil.example.org'}],'INTERFACE_DNS_CONFIGURATION_UNCONFIRMED'),('Groups',[{'GroupId':'sg-aaaaaaaa'}],'INTERFACE_SECURITY_GROUP_UNCONFIRMED')])
def test_interface_row(data,key,value,reason):
    data[1]['VpcEndpoints'][0][key]=value; r=run(data);assert r['status']=='UNKNOWN' and r['reason']==reason and not r['network_interfaces']

@pytest.mark.parametrize('key,value,reason',[('Status','available','INTERFACE_ENI_PROFILE_UNCONFIRMED'),('InterfaceType','interface','INTERFACE_ENI_PROFILE_UNCONFIRMED'),('RequesterManaged',False,'INTERFACE_ENI_PROFILE_UNCONFIRMED'),('Attachment',{'InstanceId':'i-12345678'},'INTERFACE_ENI_PROFILE_UNCONFIRMED'),('Groups',[],'INTERFACE_SECURITY_GROUP_CONFLICT'),('SubnetId','subnet-87654321','INTERFACE_SUBNET_UNCONFIRMED'),('PrivateIpAddresses',[],'INTERFACE_ENI_PROFILE_UNCONFIRMED')])
def test_eni(data,key,value,reason):
    data[0]['inventory']['NetworkInterfaces'][-2][key]=value; assert run(data)['reason']==reason

def test_missing_eni(data):
    data[0]['inventory']['NetworkInterfaces'].pop();assert run(data)['reason']=='INTERFACE_ENI_UNCONFIRMED'
def test_shared_eni(data):
    data[1]['VpcEndpoints'][1]['NetworkInterfaceIds']=['eni-99999991'];assert run(data)['reason']=='INTERFACE_ENI_OWNERSHIP_CONFLICT'
def test_duplicate_ip(data):
    rows=data[0]['inventory']['NetworkInterfaces'];rows[-1]['PrivateIpAddress']='10.0.1.90';rows[-1]['PrivateIpAddresses']=[{'PrivateIpAddress':'10.0.1.90','Primary':True}];assert run(data)['reason']=='INTERFACE_ENI_OWNERSHIP_CONFLICT'

@pytest.mark.parametrize('change,reason',[('missing','GATEWAY_ROUTE_UNCONFIRMED'),('inactive','GATEWAY_ROUTE_UNCONFIRMED'),('extra_target','GATEWAY_ROUTE_UNCONFIRMED'),('prefix_conflict','GATEWAY_ROUTE_TABLE_CONFLICT'),('unlisted_table','GATEWAY_ROUTE_TABLE_CONFLICT'),('unknown_table','GATEWAY_ROUTE_TABLE_CONFLICT'),('wrong_service','ENDPOINT_SERVICE_SCOPE_UNSUPPORTED'),('eni','GATEWAY_RELATIONSHIPS_UNCONFIRMED')])
def test_gateway(data,change,reason):
    tables=data[0]['inventory']['RouteTables']; row=data[1]['VpcEndpoints'][1]
    if change=='missing':tables[0]['Routes'].pop()
    elif change=='inactive':tables[0]['Routes'][-1]['State']='blackhole'
    elif change=='extra_target':tables[0]['Routes'][-1]['NatGatewayId']='nat-12345678'
    elif change=='prefix_conflict':tables[0]['Routes'][-1]['DestinationPrefixListId']='pl-22222222'
    elif change=='unlisted_table':row['RouteTableIds'].pop()
    elif change=='unknown_table':row['RouteTableIds'].append('rtb-aaaaaaaa')
    elif change=='wrong_service':row['ServiceName']='com.amazonaws.ap-northeast-2.ec2'
    else:row['NetworkInterfaceIds']=['eni-99999991']
    r=run(data,G);assert r['status']=='UNKNOWN' and r['reason']==reason and not r['route_tables']

def test_vpc_endpoint_id_target(data):
    r=data[0]['inventory']['RouteTables'][0]['Routes'][-1];r['VpcEndpointId']=r.pop('GatewayId');assert run(data,G)['status']=='VPC_ENDPOINT_CONFIGURATION_CANDIDATE'

def test_policy_not_echoed(data):
    data[1]['VpcEndpoints'][0]['PolicyDocument']='SECRET_MARKER';r=run(data);assert r['endpoint_policy_present'] is True and 'SECRET_MARKER' not in json.dumps(r)

@pytest.mark.parametrize('key,value',[('NetworkInterfaceIds',['eni-99999991']*2),('SubnetIds',[{}]),('Groups',[{'GroupId':None}]),('DnsEntries','invalid')])
def test_malformed(data,key,value):
    data[1]['VpcEndpoints'][0][key]=value
    with pytest.raises(ValueError):run(data)

def test_duplicate_endpoint(data):
    data[1]['VpcEndpoints'].append(data[1]['VpcEndpoints'][0]);
    with pytest.raises(ValueError):run(data)
