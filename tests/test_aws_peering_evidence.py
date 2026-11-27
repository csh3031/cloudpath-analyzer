import json
from pathlib import Path
import pytest
from backend.aws.peering_evidence import trace_direct_peering

BASE=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'

@pytest.fixture
def inputs():
    return [json.loads((BASE/n).read_text()) for n in ('peering_source.json','peering_destination.json','peering_connections.json')]

def run(items,source='10.0.1.10',destination='10.1.2.10'):
    return trace_direct_peering(*(json.dumps(x).encode() for x in items),source,destination)

def route(items,i):
    return items[i]['inventory']['RouteTables'][0]['Routes'][-1]

def test_both_directions(inputs):
    r=run(inputs)
    assert r['status']=='BIDIRECTIONAL_ROUTE_CANDIDATE'
    assert r['request_status']==r['response_status']=='PEERING_ROUTE_CANDIDATE'
    assert r['session_status']=='UNKNOWN' and r['policy_status']=='NOT_EVALUATED' and not r['live_observation']
    assert r['request_route']['route_table_id']!=r['response_route']['route_table_id']

def test_reverse_orientation(inputs):
    r=run([inputs[1],inputs[0],inputs[2]],'10.1.2.10','10.0.1.10')
    assert r['status']=='BIDIRECTIONAL_ROUTE_CANDIDATE'

@pytest.mark.parametrize('side',[0,1])
def test_missing_peer_route(inputs,side):
    inputs[side]['inventory']['RouteTables'][0]['Routes'].pop()
    r=run(inputs)
    assert r['status']=='UNKNOWN' and r[['request_route','response_route'][side]]['reason']=='SELECTED_ROUTE_NOT_DIRECT_PEER'

@pytest.mark.parametrize('side',[0,1])
def test_blackhole(inputs,side):
    route(inputs,side)['State']='blackhole'
    r=run(inputs)
    assert r['status']=='BLOCKED' and r[['request_status','response_status'][side]]=='BLOCKED'
    assert r['session_status']=='UNKNOWN'

@pytest.mark.parametrize('state',['pending-acceptance','deleted','failed',None])
def test_inactive(inputs,state):
    inputs[2]['VpcPeeringConnections'][0]['Status']['Code']=state
    assert run(inputs)['reason']=='PEERING_NOT_CONFIRMED_ACTIVE'

def test_wrong_target(inputs):
    route(inputs,0)['VpcPeeringConnectionId']='pcx-11111111'
    assert run(inputs)['request_route']['reason']=='SELECTED_ROUTE_NOT_DIRECT_PEER'

def test_more_specific_route(inputs):
    inputs[0]['inventory']['RouteTables'][0]['Routes'].append(dict(DestinationCidrBlock='10.1.2.10/32',GatewayId='igw-12345678',State='active'))
    assert run(inputs)['request_route']['reason']=='SELECTED_ROUTE_NOT_DIRECT_PEER'

def test_no_direct_peer(inputs):
    inputs[2]['VpcPeeringConnections'][0]['AccepterVpcInfo']['VpcId']='vpc-cccccccc'
    assert run(inputs)['reason']=='DIRECT_PEERING_MISSING_OR_AMBIGUOUS'

def test_duplicate_peer(inputs):
    inputs[2]['VpcPeeringConnections']*=2
    with pytest.raises(ValueError,match='duplicate'): run(inputs)

def test_time_gap(inputs):
    inputs[2]['collected_at']='2026-11-25T11:05:01+00:00'
    assert run(inputs)['reason']=='SNAPSHOT_TIME_GAP'

def test_time_boundary(inputs):
    inputs[2]['collected_at']='2026-11-25T11:05:00+00:00'
    assert run(inputs)['status']=='BIDIRECTIONAL_ROUTE_CANDIDATE'

def test_endpoint_missing(inputs):
    assert run(inputs,destination='10.1.2.99')['reason']=='ENDPOINT_NOT_CONFIRMED'

def test_peer_cidr_mismatch(inputs):
    inputs[2]['VpcPeeringConnections'][0]['AccepterVpcInfo']['CidrBlock']='10.2.0.0/16'
    assert run(inputs)['reason']=='PEERING_VPC_METADATA_MISMATCH'

def test_secondary_cidr(inputs):
    inputs[0]['inventory']['Vpcs'][0]['CidrBlockAssociationSet']=[{'CidrBlock':'10.2.0.0/16'}]
    assert run(inputs)['reason']=='SECONDARY_CIDR_UNSUPPORTED'

def test_same_vpc(inputs):
    inputs[1]=inputs[0]
    assert run(inputs)['reason']=='SAME_VPC_NOT_PEERING'

def test_other_region(inputs):
    inputs[1]['region']='us-east-1'
    assert run(inputs)['reason']=='INTER_REGION_UNSUPPORTED'

def test_v2_compatible(inputs):
    inputs[0]['format']='cloudpath-aws-inventory-v2'
    assert run(inputs)['status']=='BIDIRECTIONAL_ROUTE_CANDIDATE'

def test_untrusted_fields_not_returned(inputs):
    inputs[2]['VpcPeeringConnections'][0]['RequesterVpcInfo']['OwnerId']='SECRET_TEST'
    assert 'SECRET_TEST' not in json.dumps(run(inputs))
