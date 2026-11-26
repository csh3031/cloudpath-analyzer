import copy
import pytest
from backend.aws.forwarding_evidence import trace_observed_forwarding
from backend.aws.snapshot import load_aws_snapshot
from test_aws_inventory import fixture, raw, V, S, T, E, I

SRC = '10.0.1.10'
DST = '10.0.2.10'
D = 'subnet-87654321'
E2 = 'eni-87654321'
I2 = 'i-87654321'
T2 = 'rtb-87654321'


def pair(dst=DST, subnet=D):
    d = fixture(); inv = d['inventory']
    if subnet != S:
        inv['Subnets'].append(dict(SubnetId=subnet, VpcId=V, CidrBlock='10.0.2.0/24', State='available'))
    e = copy.deepcopy(inv['NetworkInterfaces'][0]); i = copy.deepcopy(inv['Reservations'][0]['Instances'][0])
    e.update(NetworkInterfaceId=E2, SubnetId=subnet, PrivateIpAddress=dst,
             PrivateIpAddresses=[{'PrivateIpAddress':dst}], Attachment={'InstanceId':I2,'DeviceIndex':0})
    i.update(InstanceId=I2, SubnetId=subnet, PrivateIpAddress=dst, NetworkInterfaces=[{'NetworkInterfaceId':E2}])
    inv['NetworkInterfaces'].append(e); inv['Reservations'][0]['Instances'].append(i)
    return d


def explicit(d, subnet=D):
    t = copy.deepcopy(d['inventory']['RouteTables'][0]); t['RouteTableId'] = T2
    t['Associations'] = [dict(RouteTableAssociationId='rtbassoc-87654321', Main=False, SubnetId=subnet, AssociationState={'State':'associated'})]
    d['inventory']['RouteTables'].append(t)
    return t


def run(d, src=SRC, dst=DST):
    b = raw(d); r = trace_observed_forwarding(b, src, dst)
    assert r['analysis_type'] == 'STATIC_AWS_INVENTORY_FORWARDING'
    assert r['input_identity'] == load_aws_snapshot(b)[1]
    assert r['live_observation'] is False and r['session_status'] == 'NOT_EVALUATED'
    assert r['request']['conditional'] is False and r['response']['conditional'] is True
    for direction in ('request', 'response'):
        p = r[direction]
        assert p['policy_status'] == 'NOT_EVALUATED'
        assert [h['sequence'] for h in p['hops']] == list(range(1,len(p['hops'])+1))
        assert p['path_complete'] == (p['status']=='FORWARDING_CANDIDATE')
    return r


def test_bidirectional_candidate():
    r = run(pair())
    for name, start, end in [('request',E,E2), ('response',E2,E)]:
        p = r[name]; assert p['status'] == 'FORWARDING_CANDIDATE'
        assert [h['stage'] for h in p['hops']] == ['SOURCE_ENDPOINT','ROUTE_LOOKUP','VPC_LOCAL','DESTINATION_ENDPOINT']
        assert [h['resource_id'] for h in p['hops']] == [start,T,V,end]
        assert p['packet_stopped'] is None
        assert p['route_lookup']['input_identity'] == r['input_identity']
    assert r['endpoints']['source']['instance_id'] == I
    assert r['endpoints']['destination']['instance_id'] == I2


def test_distinct_directional_tables():
    d = pair(); explicit(d)
    r = run(d); assert r['request']['route_lookup']['route_table_id'] == T
    assert r['response']['route_lookup']['route_table_id'] == T2


@pytest.mark.parametrize('blocked_direction,subnet,cidr', [('request',S,'10.0.2.0/24'),('response',D,'10.0.1.0/24')])
def test_asymmetric_blackhole(blocked_direction,subnet,cidr):
    d = pair(); t = explicit(d,subnet)
    t['Routes'].append(dict(DestinationCidrBlock=cidr, NetworkInterfaceId=E2, State='blackhole'))
    r = run(d); p = r[blocked_direction]
    assert p['status'] == 'BLOCKED' and p['reason'] == 'SELECTED_ROUTE_BLACKHOLE'
    assert [h['stage'] for h in p['hops']] == ['SOURCE_ENDPOINT','ROUTE_LOOKUP']
    assert p['packet_stopped']['resource_id'] == T2
    other = 'request' if blocked_direction == 'response' else 'response'
    assert r[other]['status'] == 'FORWARDING_CANDIDATE'


@pytest.mark.parametrize('case,reason', [
    ('no_route','NO_EXPLICIT_MATCHING_ROUTE'), ('pending','ROUTE_ASSOCIATION_NOT_CONFIRMED'),
    ('target','SELECTED_ROUTE_TARGET_OUT_OF_SCOPE'), ('prefix','PREFIX_LIST_CONTENTS_NOT_COLLECTED'),
    ('propagation','ROUTE_PROPAGATION_NOT_IN_SCOPE'), ('state','SELECTED_ROUTE_STATE_UNCONFIRMED'),
])
def test_asymmetric_unknown(case, reason):
    d = pair(); t = explicit(d,S)
    if case=='no_route': t['Routes']=[]
    elif case=='pending': t['Associations'][0]['AssociationState']['State']='associating'
    elif case=='target': t['Routes'][0]['GatewayId']='igw-12345678'
    elif case=='prefix': t['Routes'].append(dict(DestinationPrefixListId='pl-12345678',GatewayId='local',State='active'))
    elif case=='propagation': t['PropagatingVgws']=[{'GatewayId':'vgw-12345678'}]
    elif case=='state': del t['Routes'][0]['State']
    r=run(d); p=r['request']; assert (p['status'],p['reason'])==('UNKNOWN',reason)
    assert p['packet_stopped'] is None and not any(h['stage']=='DESTINATION_ENDPOINT' for h in p['hops'])
    assert r['response']['status']=='FORWARDING_CANDIDATE'


@pytest.mark.parametrize('case,reason', [('stopped','INSTANCE_STATE_NOT_RUNNING'),('missing_eni','ENI_IP_OWNER_MISSING_OR_AMBIGUOUS'),('missing_sg','SECURITY_GROUP_EVIDENCE_MISSING'),('multi_ip','ENI_ADDRESS_CONFIGURATION_UNSUPPORTED')])
def test_invalid_destination_prevents_route(case,reason):
    d=pair(); inv=d['inventory']
    if case=='stopped': inv['Reservations'][0]['Instances'][1]['State']['Name']='stopped'
    elif case=='missing_eni': inv['NetworkInterfaces'].pop()
    elif case=='missing_sg': inv['SecurityGroups']=[]
    elif case=='multi_ip': inv['NetworkInterfaces'][1]['PrivateIpAddresses'].append({'PrivateIpAddress':'10.0.2.11'})
    r=run(d)
    assert r['endpoints']['destination']['reason']==reason
    for name in ('request','response'):
        assert r[name]['status']=='UNKNOWN' and r[name]['route_lookup'] is None
        assert r[name]['packet_stopped'] is None


def test_same_endpoint_unknown():
    r=run(pair(),dst=SRC); assert r['request']['reason']=='SAME_ENDPOINT_NOT_IN_SCOPE'
    assert r['response']['route_lookup'] is None


def test_same_subnet_unknown():
    r=run(pair('10.0.1.11',S),dst='10.0.1.11')
    assert r['request']['reason']==r['response']['reason']=='SAME_SUBNET_FORWARDING_NOT_IN_SCOPE'
    assert r['request']['route_lookup'] is None


@pytest.mark.parametrize('ip',['10.0.2.0','10.0.2.1','10.0.2.2','10.0.2.3','10.0.2.255'])
def test_reserved_ip(ip):
    r=run(pair(ip),dst=ip)
    assert r['request']['reason']=='DESTINATION_AWS_RESERVED_SUBNET_ADDRESS'
    assert r['response']['reason']=='SOURCE_AWS_RESERVED_SUBNET_ADDRESS'
    assert r['request']['route_lookup'] is None


def test_invalid_ipv4():
    r=run(pair(),dst='2001:db8::1'); assert r['request']['reason']=='DESTINATION_INVALID_IPV4_ENDPOINT'


def test_invalid_snapshot():
    d=pair(); del d['inventory']['RouteTables']
    with pytest.raises(ValueError): trace_observed_forwarding(raw(d),SRC,DST)


def test_immutable_input_required():
    with pytest.raises(ValueError): trace_observed_forwarding(bytearray(raw(pair())),SRC,DST)


def test_policy_and_web_guard_unchanged():
    d=pair(); d['inventory']['NetworkAcls']=[]
    r=run(d); assert r['request']['status']=='FORWARDING_CANDIDATE'
    assert r['request']['policy_status']=='NOT_EVALUATED'
    assert load_aws_snapshot(raw(d))[2]['analysis_restricted'] is True
