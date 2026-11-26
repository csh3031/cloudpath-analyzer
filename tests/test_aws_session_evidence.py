import json
import pytest
from backend.aws.session_evidence import analyze_observed_session
from backend.aws.snapshot import load_aws_snapshot
from test_aws_policy_evidence import setup
from test_aws_forwarding_evidence import SRC, DST, D, explicit, pair
from test_aws_inventory import raw, S, G


def run(d, src=SRC, dst=DST, sp=50000, dp=443):
    b = raw(d)
    result = analyze_observed_session(b, src, dst, sp, dp)
    assert result['analysis_type'] == 'STATIC_AWS_INVENTORY_PREDICTION'
    assert result['input_identity'] == load_aws_snapshot(b)[1]
    assert result['live_observation'] is False
    assert load_aws_snapshot(b)[2]['analysis_restricted'] is True
    assert len(result['findings']) == len({f['id'] for f in result['findings']}) == 12
    assert json.loads(json.dumps(result)) == result
    return result


def find(r, name, stage):
    return next(f for f in r['findings'] if f['id'] == name+':'+stage)


def test_candidate_requires_tracked_reply():
    r=run(setup())
    assert r['predicted_connectivity']=='UNKNOWN' and r['conditional_connectivity']=='REACHABLE'
    assert r['request']['path_complete'] and r['response']['path_complete']
    assert r['first_blocker'] is None and r['conditional_first_blocker'] is None
    assert len(r['request']['trace'])==len(r['response']['trace'])==6
    assert all(f['evaluation_mode']=='CONDITIONAL_CHECK' for f in r['findings'] if f['direction']=='response')
    assert find(r,'response','SOURCE_SG_EGRESS')['status']=='CONDITIONAL'
    assert 'TCP_REPLY_CONNECTION_TRACKED' in r['response']['assumptions']
    assert r['evidence']['session_status']=='NOT_EVALUATED'


@pytest.mark.parametrize('stage', ['SOURCE_SG_EGRESS','SOURCE_NACL_EGRESS','ROUTE_LOOKUP','DESTINATION_NACL_INGRESS','DESTINATION_SG_INGRESS'])
def test_first_request_blocker(stage):
    d=setup(); inv=d['inventory']; sg=inv['SecurityGroups'][0]; a=inv['NetworkAcls'][0]
    if stage=='SOURCE_SG_EGRESS': sg['IpPermissionsEgress']=[]
    elif stage=='DESTINATION_SG_INGRESS': sg['IpPermissions']=[]
    elif stage=='ROUTE_LOOKUP': explicit(d,S)['Routes'][0]['State']='blackhole'
    else: a['Entries'].append(dict(RuleNumber=50,Protocol='6',RuleAction='deny',Egress=stage=='SOURCE_NACL_EGRESS',CidrBlock='10.0.0.0/16',PortRange={'From':443,'To':443}))
    r=run(d); fid='request:'+stage
    assert r['predicted_connectivity']=='BLOCKED' and r['first_blocker']==fid
    assert r['request']['trace'][-1]==fid and not r['request']['path_complete']
    assert r['response']['trace']==[] and r['response']['status']=='NOT_EVALUATED'
    assert r['conditional_connectivity']=='NOT_EVALUATED'
    assert r['conditional_first_blocker'] is None
    for f in r['findings'][len(r['request']['trace']):]:
        assert f['evaluation_mode']=='INDEPENDENT_CHECK'
    assert find(r,'request',stage)['status']=='BLOCKED'


def test_multiple_blocks_preserved():
    d=setup();d['inventory']['SecurityGroups'][0]['IpPermissionsEgress']=[]
    d['inventory']['SecurityGroups'][0]['IpPermissions']=[]
    explicit(d,S)['Routes'][0]['State']='blackhole'
    r=run(d)
    assert r['first_blocker']=='request:SOURCE_SG_EGRESS'
    for stage in ('ROUTE_LOOKUP','DESTINATION_SG_INGRESS'):
        f=find(r,'request',stage);assert f['status']=='BLOCKED' and f['evaluation_mode']=='INDEPENDENT_CHECK'
        assert r['first_blocker'] in f['dependencies']


def test_unknown_before_block_is_not_first_blocker():
    d=setup();d['inventory']['SecurityGroups'][0]['IpPermissionsEgress']=[dict(IpProtocol='tcp',FromPort=443,ToPort=443,UserIdGroupPairs=[{'GroupId':G}])]
    explicit(d,S)['Routes'][0]['State']='blackhole'
    r=run(d);assert r['predicted_connectivity']=='UNKNOWN' and r['first_blocker'] is None
    assert r['request']['stopped_at']=='request:SOURCE_SG_EGRESS'
    assert find(r,'request','ROUTE_LOOKUP')['status']=='BLOCKED'
    assert r['response']['trace']==[]


@pytest.mark.parametrize('case', ['missing_route','propagation','unknown_acl'])
def test_unknown_stops_path(case):
    d=setup()
    if case=='missing_route':explicit(d,S)['Routes']=[]
    elif case=='propagation':explicit(d,S)['PropagatingVgws']=[{'GatewayId':'vgw-12345678'}]
    else:d['inventory']['NetworkAcls'][0]['Associations']=[]
    r=run(d);assert r['predicted_connectivity']=='UNKNOWN' and r['first_blocker'] is None
    assert r['request']['stopped_at']=='request:'+('SOURCE_NACL_EGRESS' if case=='unknown_acl' else 'ROUTE_LOOKUP')
    assert not r['request']['path_complete'] and r['response']['trace']==[]


@pytest.mark.parametrize('stage',['SOURCE_NACL_EGRESS','ROUTE_LOOKUP','DESTINATION_NACL_INGRESS'])
def test_conditional_reply_blocker(stage):
    d=setup()
    if stage=='ROUTE_LOOKUP':explicit(d,D)['Routes'][0]['State']='blackhole'
    else:d['inventory']['NetworkAcls'][0]['Entries'].append(dict(RuleNumber=50,Protocol='6',RuleAction='deny',Egress=stage=='SOURCE_NACL_EGRESS',CidrBlock='10.0.0.0/16',PortRange={'From':50000,'To':50000}))
    r=run(d);fid='response:'+stage
    assert r['request']['status']=='REACHABLE' and r['first_blocker'] is None
    assert r['predicted_connectivity']=='UNKNOWN' and r['conditional_connectivity']=='BLOCKED'
    assert r['conditional_first_blocker']==fid and r['response']['trace'][-1]==fid
    assert find(r,'response',stage)['evaluation_mode']=='CONDITIONAL_CHECK'
    assert all(f['evaluation_mode']=='INDEPENDENT_CHECK' for f in r['findings'][6+len(r['response']['trace']):])


def test_unknown_reply_route():
    d=setup();explicit(d,D)['Routes']=[]
    r=run(d);assert r['predicted_connectivity']==r['conditional_connectivity']=='UNKNOWN'
    assert r['response']['stopped_at']=='response:ROUTE_LOOKUP'
    assert r['conditional_first_blocker'] is None


@pytest.mark.parametrize('case',['stopped','same','same_subnet','reserved','ipv6'])
def test_unsupported_endpoint_scope(case):
    d=setup();dst=DST
    if case=='stopped':d['inventory']['Reservations'][0]['Instances'][1]['State']['Name']='stopped'
    elif case=='same':dst=SRC
    elif case=='same_subnet':dst='10.0.1.11';d=pair(dst,S)
    elif case=='reserved':dst='10.0.2.1';d=pair(dst)
    else:dst='2001:db8::1'
    r=run(d,dst=dst);assert r['predicted_connectivity']=='UNKNOWN' and r['first_blocker'] is None
    assert r['request']['trace']==['request:ENDPOINT_SCOPE'] and r['response']['trace']==[]
    assert find(r,'request','ROUTE_LOOKUP')['status']=='NOT_EVALUATED'


@pytest.mark.parametrize('port',[0,65536,True,'443'])
def test_invalid_port(port):
    with pytest.raises(ValueError):run(setup(),dp=port)


def test_invalid_inventory():
    d=setup();del d['inventory']['RouteTables']
    with pytest.raises(ValueError):run(d)


def test_coverage_and_tuple():
    r=run(setup(),sp=12345,dp=443)
    assert r['scenario']['source_port']==12345 and r['scenario']['destination_port']==443
    assert r['evidence']['response']['destination_port']==12345
    assert 'actual connection tracking' in r['coverage']['unverified']
    assert 'snapshot authenticity, completeness, freshness and atomicity' in r['coverage']['unverified']
    assert r['response']['dependency']==r['request']['trace'][-1]
