import json
from pathlib import Path
import pytest
from backend.aws.tgw_evidence import trace_transit_gateway

P=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'

@pytest.fixture
def data():
    return [json.loads((P/f'tgw_{name}.json').read_text()) for name in ('source','destination','evidence')]

def trace(data):
    return trace_transit_gateway(*(json.dumps(d).encode() for d in data),'10.0.1.10','10.1.2.10')

def test_bidirectional(data):
    r=trace(data)
    assert r['status']=='BIDIRECTIONAL_ROUTE_CANDIDATE'
    assert r['request_status']==r['response_status']=='TGW_ROUTE_CANDIDATE'
    assert r['request']['tgw_route_table_id']!=r['response']['tgw_route_table_id']
    assert r['session_status']=='UNKNOWN' and r['live_observation'] is False
    assert r['policy_status']=='NOT_EVALUATED'

@pytest.mark.parametrize('index',[0,1])
def test_tgw_blackhole(data,index):
    r=data[2]['route_exports'][index]['Routes'][0]; r.update(State='blackhole',TransitGatewayAttachments=[])
    out=trace(data); assert out['status']=='BLOCKED'; assert out[['request_status','response_status'][index]]=='BLOCKED'

@pytest.mark.parametrize('index',[0,1])
def test_vpc_blackhole(data,index):
    data[index]['inventory']['RouteTables'][0]['Routes'][-1]['State']='blackhole'
    assert trace(data)['status']=='BLOCKED'

@pytest.mark.parametrize('field,value,reason',[
    ('State','pending','ATTACHMENT_STATE_OR_MODE_UNCONFIRMED'),
    ('Options',{'ApplianceModeSupport':'enable'},'ATTACHMENT_STATE_OR_MODE_UNCONFIRMED'),
    ('SubnetIds',[],'SAME_AZ_ATTACHMENT_SUBNET_NOT_CONFIRMED'),
    ('TransitGatewayId','tgw-99999999','SHARED_TGW_NOT_CONFIRMED'),
])
def test_attachment_scope(data,field,value,reason):
    data[2]['TransitGatewayVpcAttachments'][0][field]=value
    assert trace(data)['reason']==reason

@pytest.mark.parametrize('field,value,reason',[
    ('complete',False,'TGW_ROUTE_EXPORT_INCOMPLETE'),
    ('AdditionalRoutesAvailable',True,'TGW_ROUTE_EXPORT_INCOMPLETE'),
    ('Routes',[],'TGW_MATCHING_ROUTE_NOT_OBSERVED'),
    ('Routes',[{'PrefixListId':'pl-12345678'}],'TGW_DESTINATION_UNRESOLVED'),
])
def test_route_export(data,field,value,reason):
    data[2]['route_exports'][0][field]=value
    assert trace(data)['request']['reason']==reason

def test_longest_prefix(data):
    data[2]['route_exports'][0]['Routes'].append(dict(DestinationCidrBlock='10.1.2.10/32',State='blackhole',Type='static'))
    assert trace(data)['request']['tgw_route']['selected_route']['DestinationCidrBlock']=='10.1.2.10/32'
    assert trace(data)['request_status']=='BLOCKED'

def test_equal_prefix_unknown(data):
    rows=data[2]['route_exports'][0]['Routes']; rows.append(dict(rows[0],Type='static'))
    assert trace(data)['request']['reason']=='TGW_EQUAL_PREFIX_PRIORITY_UNSUPPORTED'

def test_wrong_attachment(data):
    data[2]['route_exports'][0]['Routes'][0]['TransitGatewayAttachments'][0]['TransitGatewayAttachmentId']='tgw-attach-11111111'
    assert trace(data)['request']['reason']=='TGW_ROUTE_NOT_DESTINATION_ATTACHMENT'

def test_association(data):
    data[2]['TransitGatewayVpcAttachments'][0]['Association']['State']='associating'
    assert trace(data)['request']['reason']=='TGW_ASSOCIATION_NOT_CONFIRMED'

def test_destination_route(data):
    data[1]['inventory']['RouteTables'][0]['Routes'][0]['State']='blackhole'
    assert trace(data)['request']['destination_local_route']['status']=='BLOCKED'

def test_time(data):
    data[2]['collected_at']='2026-11-25T11:06:00Z'
    assert trace(data)['reason']=='SNAPSHOT_TIME_GAP'

def test_missing_az(data):
    del data[0]['inventory']['Subnets'][0]['AvailabilityZone']
    assert trace(data)['reason']=='SAME_AZ_ATTACHMENT_SUBNET_NOT_CONFIRMED'

def test_wrong_tgw_table(data):
    data[2]['TransitGatewayRouteTables'][0]['TransitGatewayId']='tgw-99999999'
    assert trace(data)['request']['reason']=='TGW_TABLE_NOT_CONFIRMED'

def test_duplicate_evidence(data):
    rows=data[2]['TransitGatewayVpcAttachments']; rows.append(rows[0])
    with pytest.raises(ValueError,match='Duplicate'): trace(data)

def test_missing_gateway(data):
    data[2]['TransitGateways']=[]
    assert trace(data)['reason']=='SHARED_TGW_NOT_CONFIRMED'
