import json
from pathlib import Path
import pytest
from backend.aws.peering_session_evidence import analyze_peering_session

BASE=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'

@pytest.fixture
def inputs():
    return [json.loads((BASE/n).read_text()) for n in ('peering_source_policy_candidate.json','peering_destination_policy_candidate.json','peering_connections.json')]

def run(items,ports=(50000,443),ips=('10.0.1.10','10.1.2.10')):
    return analyze_peering_session(*(json.dumps(x).encode() for x in items),*ips,*ports)

def acl(items,side):
    return items[side]['inventory']['NetworkAcls'][0]['Entries']

def sg(items,side):
    return items[side]['inventory']['SecurityGroups'][0]

def row(result,stage,direction='request'):
    return next(x for x in result[direction] if x['stage']==stage)

def deny(items,side,egress,port,peer):
    acl(items,side).append(dict(RuleNumber=50,Protocol='6',RuleAction='deny',Egress=egress,CidrBlock=peer,PortRange={'From':port,'To':port}))

def test_candidate(inputs):
    r=run(inputs)
    assert r['request_status']==r['response_status']=='CONDITIONAL_CANDIDATE'
    assert r['session_status']=='UNKNOWN' and not r['live_observation']
    assert r['first_request_stop'] is None
    assert all(x['evaluation_mode']=='PREDICTED_PATH' for x in r['request'])
    assert all(x['evaluation_mode']=='CONDITIONAL_CHECK' for x in r['response'])
    assert r['route']['policy_status']=='NOT_EVALUATED'

def test_original_blocks(inputs):
    inputs[:2]=[json.loads((BASE/f'peering_{s}.json').read_text()) for s in ('source','destination')]
    r=run(inputs)
    assert r['route']['status']=='BIDIRECTIONAL_ROUTE_CANDIDATE'
    assert r['first_request_stop']=='SOURCE_NACL_EGRESS' and r['session_status']=='BLOCKED'
    assert r['response_status']=='NOT_EVALUATED'
    assert all(x['evaluation_mode']=='INDEPENDENT_CHECK' for x in r['response'])

def test_source_sg_block(inputs):
    sg(inputs,0)['IpPermissionsEgress']=[]
    r=run(inputs)
    assert r['first_request_stop']=='SOURCE_SG_EGRESS'
    assert row(r,'PEERING_ROUTE')['evaluation_mode']=='INDEPENDENT_CHECK'

def test_destination_sg_block(inputs):
    sg(inputs,1)['IpPermissions']=[]
    assert run(inputs)['first_request_stop']=='DESTINATION_SG_INGRESS'

@pytest.mark.parametrize('side,egress,stage,peer',[(0,True,'SOURCE_NACL_EGRESS','10.1.0.0/16'),(1,False,'DESTINATION_NACL_INGRESS','10.0.0.0/16')])
def test_request_nacl_deny(inputs,side,egress,stage,peer):
    deny(inputs,side,egress,443,peer)
    r=run(inputs)
    assert r['first_request_stop']==stage and row(r,stage)['rule_number']==50

@pytest.mark.parametrize('side,egress,stage,peer',[(1,True,'SOURCE_NACL_EGRESS','10.0.0.0/16'),(0,False,'DESTINATION_NACL_INGRESS','10.1.0.0/16')])
def test_reply_port_deny(inputs,side,egress,stage,peer):
    deny(inputs,side,egress,50000,peer)
    r=run(inputs)
    assert r['request_status']=='CONDITIONAL_CANDIDATE' and r['response_status']=='BLOCKED'
    assert r['conditional_first_response_stop']==stage and r['session_status']=='UNKNOWN'

def test_reply_stateful(inputs):
    sg(inputs,0)['IpPermissions']=[];sg(inputs,1)['IpPermissionsEgress']=[]
    r=run(inputs)
    assert row(r,'SOURCE_SG_EGRESS','response')['status']=='CONDITIONAL'
    assert row(r,'DESTINATION_SG_INGRESS','response')['status']=='CONDITIONAL'
    assert r['response_status']=='CONDITIONAL_CANDIDATE'

@pytest.mark.parametrize('side',[0,1])
def test_blackhole(inputs,side):
    inputs[side]['inventory']['RouteTables'][0]['Routes'][-1]['State']='blackhole'
    r=run(inputs)
    assert r[['request_status','response_status'][side]]=='BLOCKED'
    assert r['session_status']==('BLOCKED' if side==0 else 'UNKNOWN')

@pytest.mark.parametrize('side',[0,1])
def test_wrong_route(inputs,side):
    inputs[side]['inventory']['RouteTables'][0]['Routes'][-1]['VpcPeeringConnectionId']='pcx-11111111'
    r=run(inputs)
    assert r[['request_status','response_status'][side]]=='UNKNOWN'
    assert r['session_status']=='UNKNOWN'

@pytest.mark.parametrize('kind',['UserIdGroupPairs','PrefixListIds'])
def test_unresolved_sg(inputs,kind):
    rule=sg(inputs,1)['IpPermissions'][0];rule.pop('IpRanges')
    rule[kind]=[{'GroupId':'sg-12345678'}] if kind=='UserIdGroupPairs' else [{'PrefixListId':'pl-12345678'}]
    r=run(inputs)
    assert r['request_status']=='UNKNOWN' and r['first_request_stop']=='DESTINATION_SG_INGRESS'
    assert r['response_status']=='NOT_EVALUATED'

def test_unknown_then_independent_block(inputs):
    sg(inputs,0)['IpPermissionsEgress']=[dict(IpProtocol='-1',UserIdGroupPairs=[{'GroupId':'sg-aaaaaaaa'}])]
    deny(inputs,0,True,443,'10.1.0.0/16')
    r=run(inputs)
    assert r['request_status']=='UNKNOWN' and r['first_request_stop']=='SOURCE_SG_EGRESS'
    assert row(r,'SOURCE_NACL_EGRESS')['status']=='BLOCKED' and row(r,'SOURCE_NACL_EGRESS')['evaluation_mode']=='INDEPENDENT_CHECK'

def test_scope_inactive(inputs):
    inputs[2]['VpcPeeringConnections'][0]['Status']['Code']='deleted'
    r=run(inputs)
    assert r['first_request_stop']=='PEERING_SCOPE' and not r['response']

def test_scope_gap(inputs):
    inputs[2]['collected_at']='2026-11-25T11:05:01+00:00'
    assert run(inputs)['request'][0]['reason']=='SNAPSHOT_TIME_GAP'

def test_scope_endpoint(inputs):
    assert run(inputs,ips=('10.0.1.99','10.1.2.10'))['first_request_stop']=='PEERING_SCOPE'

def test_missing_acl(inputs):
    inputs[0]['inventory']['NetworkAcls'][0]['Associations']=[]
    assert run(inputs)['first_request_stop']=='SOURCE_NACL_EGRESS'

def test_vpc_evidence_scoped(inputs):
    r=run(inputs)
    assert row(r,'SOURCE_NACL_EGRESS')['vpc_id']=='vpc-12345678'
    assert row(r,'DESTINATION_NACL_INGRESS')['vpc_id']=='vpc-aaaaaaaa'
    assert row(r,'SOURCE_NACL_EGRESS','response')['vpc_id']=='vpc-aaaaaaaa'

def test_wrong_destination_port(inputs):
    assert run(inputs,ports=(50000,80))['first_request_stop']=='DESTINATION_SG_INGRESS'

@pytest.mark.parametrize('ports',[(0,443),(50000,65536),(True,443)])
def test_invalid_ports(inputs,ports):
    with pytest.raises(ValueError,match='TCP ports'): run(inputs,ports=ports)

def test_reverse(inputs):
    r=run([inputs[1],inputs[0],inputs[2]],ips=('10.1.2.10','10.0.1.10'))
    assert r['request_status']==r['response_status']=='CONDITIONAL_CANDIDATE'
