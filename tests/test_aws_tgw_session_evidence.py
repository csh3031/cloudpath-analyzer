import json
from pathlib import Path
import pytest
from backend.aws.tgw_session_evidence import analyze_tgw_session

P=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
@pytest.fixture
def data():
    return [json.loads((P/f'tgw_{n}.json').read_text()) for n in ('source_policy_candidate','destination_policy_candidate','evidence')]

def run(data,sp=50000,dp=443):
    return analyze_tgw_session(*(json.dumps(d).encode() for d in data),'10.0.1.10','10.1.2.10',sp,dp)

def row(r,stage,d='request'):
    return next(x for x in r[d] if x['stage']==stage)

def test_positive(data):
    r=run(data); assert r['request_status']==r['response_status']=='CONDITIONAL_CANDIDATE'
    assert r['session_status']=='UNKNOWN' and r['live_observation'] is False
    assert r['route']['policy_status']=='NOT_EVALUATED'
    assert row(r,'SOURCE_ATTACHMENT_NACL_INGRESS')['rule_number']==100
    assert row(r,'DESTINATION_WORKLOAD_NACL_INGRESS')['status']=='NOT_APPLICABLE'
    assert row(r,'SOURCE_SG_EGRESS','response')['status']=='CONDITIONAL'
    assert row(r,'TGW_ROUTE')['route_table_id']!=row(r,'TGW_ROUTE','response')['route_table_id']

@pytest.mark.parametrize('sp,dp',[(0,443),(50000,65536),(True,443),(50000,'443')])
def test_bad_port(data,sp,dp):
    with pytest.raises(ValueError):run(data,sp,dp)

@pytest.mark.parametrize('index,stage',[(0,'SOURCE_WORKLOAD_NACL_EGRESS'),(1,'DESTINATION_SG_INGRESS')])
def test_policy_block(data,index,stage):
    inv=data[index]['inventory']
    if index==0: inv['NetworkAcls'][0]['Entries']=[x for x in inv['NetworkAcls'][0]['Entries'] if x['RuleNumber']!=110]
    else: inv['SecurityGroups'][0]['IpPermissions']=[]
    r=run(data); assert r['first_request_stop']==stage and r['session_status']=='BLOCKED'
    assert r['response_status']=='NOT_EVALUATED'
    assert all(x['evaluation_mode']=='INDEPENDENT_CHECK' for x in r['response'])

@pytest.mark.parametrize('index',[0,1])
def test_blackhole(data,index):
    data[2]['route_exports'][index]['Routes'][0].update(State='blackhole',TransitGatewayAttachments=[])
    r=run(data)
    if index==0: assert r['first_request_stop']=='TGW_ROUTE' and r['session_status']=='BLOCKED'
    else: assert r['conditional_first_response_stop']=='TGW_ROUTE' and r['session_status']=='UNKNOWN'

@pytest.mark.parametrize('key,value',[('State','pending'),('SubnetIds',[])])
def test_scope(data,key,value):
    data[2]['TransitGatewayVpcAttachments'][0][key]=value
    r=run(data);assert r['first_request_stop']=='TGW_SCOPE' and r['session_status']=='UNKNOWN'

def test_tgw_wrong_target(data):
    data[2]['route_exports'][0]['Routes'][0]['TransitGatewayAttachments'][0]['TransitGatewayAttachmentId']='tgw-attach-11111111'
    assert run(data)['first_request_stop']=='TGW_ROUTE'

def test_dest_local_blackhole(data):
    data[1]['inventory']['RouteTables'][0]['Routes'][0]['State']='blackhole'
    assert run(data)['first_request_stop']=='DESTINATION_ATTACHMENT_LOCAL_ROUTE'

def test_source_attachment_ingress(data):
    a=data[0]['inventory']['NetworkAcls'][0]
    a['Entries']=[x for x in a['Entries'] if x['Egress'] or x['RuleNumber']!=100]
    r=run(data);assert r['first_request_stop']=='SOURCE_ATTACHMENT_NACL_INGRESS'

def test_same_subnet_no_destination_nacl(data):
    a=data[1]['inventory']['NetworkAcls'][0]
    a['Entries']=[x for x in a['Entries'] if x['Egress'] or x['RuleNumber']!=110]
    r=run(data);assert r['request_status']=='CONDITIONAL_CANDIDATE'
    assert row(r,'DESTINATION_WORKLOAD_NACL_INGRESS')['status']=='NOT_APPLICABLE'

def separate_dest(data):
    data[2]['TransitGatewayVpcAttachments'][1]['SubnetIds']=['subnet-aaaaaaaa']

def test_distinct_attachment(data):
    separate_dest(data);r=run(data)
    assert row(r,'DESTINATION_ATTACHMENT_NACL_EGRESS')['subnet_id']=='subnet-aaaaaaaa'
    assert row(r,'DESTINATION_ATTACHMENT_NACL_EGRESS')['status']=='ALLOW_CANDIDATE'
    assert row(r,'DESTINATION_WORKLOAD_NACL_INGRESS')['status']=='ALLOW_CANDIDATE'
    assert row(r,'SOURCE_ATTACHMENT_NACL_INGRESS','response')['subnet_id']=='subnet-aaaaaaaa'

def test_distinct_destination_workload_deny(data):
    separate_dest(data)
    a=data[1]['inventory']['NetworkAcls'][0];a['Entries']=[x for x in a['Entries'] if x['Egress'] or x['RuleNumber']!=110]
    assert run(data)['first_request_stop']=='DESTINATION_WORKLOAD_NACL_INGRESS'

def test_distinct_destination_attachment_deny(data):
    separate_dest(data)
    a=data[1]['inventory']['NetworkAcls'][0];a['Entries']=[x for x in a['Entries'] if not x['Egress'] or x['RuleNumber']!=100]
    assert run(data)['first_request_stop']=='DESTINATION_ATTACHMENT_NACL_EGRESS'

def test_reply_port(data):
    a=data[1]['inventory']['NetworkAcls'][0];next(x for x in a['Entries'] if x['RuleNumber']==110 and x['Egress'])['PortRange']={'From':443,'To':443}
    r=run(data);assert r['request_status']=='CONDITIONAL_CANDIDATE' and r['conditional_first_response_stop']=='SOURCE_WORKLOAD_NACL_EGRESS'
