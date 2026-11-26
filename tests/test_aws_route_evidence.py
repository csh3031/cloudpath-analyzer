import copy
import pytest
from backend.aws.route_evidence import lookup_observed_route
from test_aws_inventory import fixture, raw, S, T, V

D = 'subnet-87654321'
IP = '10.0.2.10'


def setup():
    d = fixture()
    d['inventory']['Subnets'].append(dict(SubnetId=D, VpcId=V,
        CidrBlock='10.0.2.0/24', State='available'))
    return d


def lookup(d, ip=IP):
    r = lookup_observed_route(raw(d), S, ip)
    assert r['live_observation'] is False
    assert r['analysis_type'] == 'STATIC_AWS_INVENTORY_ROUTE_LOOKUP'
    return r


def table(d):
    return d['inventory']['RouteTables'][0]


def test_main_local_candidate():
    r = lookup(setup())
    assert r['status'] == 'LOCAL_CANDIDATE'
    assert r['route_table_id'] == T and r['association_type'] == 'MAIN'
    assert r['selected_route']['DestinationCidrBlock'] == '10.0.0.0/16'


def test_explicit_precedes_main():
    d = setup(); t = copy.deepcopy(table(d)); t['RouteTableId'] = 'rtb-87654321'
    t['Associations'] = [dict(RouteTableAssociationId='rtbassoc-87654321',
        Main=False, SubnetId=S, AssociationState={'State':'associated'})]
    d['inventory']['RouteTables'].append(t)
    r = lookup(d); assert r['route_table_id'] == t['RouteTableId']
    assert r['association_type'] == 'EXPLICIT'


def test_pending_explicit_does_not_fallback():
    d = setup(); t = copy.deepcopy(table(d)); t['RouteTableId'] = 'rtb-87654321'
    t['Associations'] = [dict(RouteTableAssociationId='rtbassoc-87654321',
        Main=False, SubnetId=S, AssociationState={'State':'associating'})]
    d['inventory']['RouteTables'].append(t)
    assert lookup(d)['reason'] == 'ROUTE_ASSOCIATION_NOT_CONFIRMED'


def test_longer_blackhole_wins():
    d = setup(); table(d)['Routes'].append(dict(DestinationCidrBlock='10.0.2.0/24',
        NetworkInterfaceId='eni-87654321', State='blackhole'))
    r = lookup(d); assert r['status'] == 'BLOCKED'
    assert r['reason'] == 'SELECTED_ROUTE_BLACKHOLE'


def test_more_specific_middlebox_unknown():
    d = setup(); table(d)['Routes'].append(dict(DestinationCidrBlock='10.0.2.0/24',
        NetworkInterfaceId='eni-87654321', State='active'))
    assert lookup(d)['reason'] == 'SELECTED_ROUTE_TARGET_OUT_OF_SCOPE'


@pytest.mark.parametrize('case,reason', [
    ('missing_assoc','ROUTE_TABLE_MISSING_OR_AMBIGUOUS'),
    ('missing_local','NO_EXPLICIT_MATCHING_ROUTE'),
    ('unknown_state','SELECTED_ROUTE_STATE_UNCONFIRMED'),
    ('prefix_list','PREFIX_LIST_CONTENTS_NOT_COLLECTED'),
    ('equal_prefix','EQUAL_PREFIX_ROUTE_PRIORITY_UNSUPPORTED'),
    ('subnet_state','SUBNET_STATE_NOT_AVAILABLE'),
    ('vpc_state','VPC_STATE_NOT_AVAILABLE'),
    ('missing_subnet','SUBNET_MISSING_OR_AMBIGUOUS'),
    ('same_subnet','SAME_SUBNET_LOOKUP_NOT_IN_SCOPE'),
    ('outside','DESTINATION_OUTSIDE_PRIMARY_VPC_CIDR'),
    ('ipv6','INVALID_IPV4_DESTINATION'),
    ('replaced_local','SELECTED_ROUTE_TARGET_OUT_OF_SCOPE'),
])
def test_unknown(case, reason):
    d = setup(); t = table(d); ip = IP
    if case == 'missing_assoc': t['Associations'] = []
    elif case == 'missing_local': t['Routes'] = []
    elif case == 'unknown_state': del t['Routes'][0]['State']
    elif case == 'prefix_list': t['Routes'].append(dict(DestinationPrefixListId='pl-12345678', GatewayId='local', State='active'))
    elif case == 'equal_prefix': t['Routes'].append(copy.deepcopy(t['Routes'][0]))
    elif case == 'subnet_state': d['inventory']['Subnets'][1]['State'] = 'pending'
    elif case == 'vpc_state': d['inventory']['Vpcs'][0]['State'] = 'pending'
    elif case == 'missing_subnet': d['inventory']['Subnets'].pop()
    elif case == 'same_subnet': ip = '10.0.1.10'
    elif case == 'outside': ip = '192.0.2.10'
    elif case == 'ipv6': ip = '2001:db8::1'
    elif case == 'replaced_local': t['Routes'][0]['GatewayId'] = 'igw-12345678'
    r = lookup(d, ip); assert r['status'] == 'UNKNOWN' and r['reason'] == reason


def test_existing_inventory_guard_remains():
    from backend.aws.snapshot import load_aws_snapshot
    assert load_aws_snapshot(raw(setup()))[2]['analysis_restricted'] is True
