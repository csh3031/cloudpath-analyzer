import copy
import json
from pathlib import Path

import pytest

from backend.aws.egress_evidence import trace_internet_egress
from backend.aws.route_evidence import lookup_observed_route

SAMPLE = Path(__file__).resolve().parents[1] / 'samples/aws/phase62_demo/aws_static_tcp_example.json'
SRC = '10.0.1.10'
DST = '8.8.8.8'  # only a static input; never contacted
S1 = 'subnet-12345678'
S2 = 'subnet-87654321'
NAT = 'nat-12345678'
IGW = 'igw-12345678'


def setup(nat=False):
    d = json.loads(SAMPLE.read_text())
    inv = d['inventory']
    if nat:
        inv['NatGateways'] = [dict(NatGatewayId=NAT, VpcId=d['vpc_id'], SubnetId=S2,
                                   State='available', ConnectivityType='public')]
        t = copy.deepcopy(inv['RouteTables'][0]); t['RouteTableId'] = 'rtb-87654321'
        t['Associations'] = [dict(RouteTableAssociationId='rtbassoc-87654321', SubnetId=S1,
                                 Main=False, AssociationState={'State':'associated'})]
        t['Routes'][1] = dict(DestinationCidrBlock='0.0.0.0/0', NatGatewayId=NAT, State='active')
        inv['RouteTables'].append(t)
    return d


def run(d, dst=DST, src=SRC):
    result = trace_internet_egress(json.dumps(d).encode(), src, dst)
    assert result['live_observation'] is False
    assert result['internet_reachability'] == 'UNKNOWN'
    assert result['session_status'] == result['response_status'] == result['policy_status'] == 'NOT_EVALUATED'
    assert not any(h['stage']=='DESTINATION_ENDPOINT' for h in result['hops'])
    return result


def test_direct_igw():
    r = run(setup())
    assert r['status'] == 'EGRESS_ROUTE_CANDIDATE'
    assert r['reason'] == 'OBSERVED_DIRECT_IGW_ROUTE'
    assert [h['stage'] for h in r['hops']] == ['SOURCE_ENDPOINT','ROUTE_LOOKUP','INTERNET_GATEWAY']
    assert r['translation']['translated_public_ip'] is None


def test_public_nat_igw():
    r = run(setup(True))
    assert r['status'] == 'EGRESS_ROUTE_CANDIDATE'
    assert r['reason'] == 'OBSERVED_PUBLIC_NAT_IGW_ROUTE'
    assert [h['stage'] for h in r['hops']] == ['SOURCE_ENDPOINT','ROUTE_LOOKUP','PUBLIC_NAT_GATEWAY','ROUTE_LOOKUP','INTERNET_GATEWAY']
    assert len(r['route_lookups']) == 2
    assert r['translation']['state'] == 'NOT_EVALUATED'
    assert r['translation']['translated_private_ip'] is None


@pytest.mark.parametrize('dst,reason', [('10.0.2.10','DESTINATION_NOT_PUBLIC_UNICAST_IPV4'), ('224.0.0.1','DESTINATION_NOT_PUBLIC_UNICAST_IPV4'),('100.64.0.1','DESTINATION_NOT_PUBLIC_UNICAST_IPV4'), ('2001:db8::1','INVALID_IPV4_DESTINATION'), ('invalid','INVALID_IPV4_DESTINATION')])
def test_out_of_scope_address(dst, reason):
    assert run(setup(),dst)['reason']==reason


@pytest.mark.parametrize('mutation,reason,status',[
    ('missing_igw','IGW_MISSING_OR_AMBIGUOUS','UNKNOWN'),
    ('igw_state','IGW_ATTACHMENT_NOT_AVAILABLE','UNKNOWN'),
    ('blackhole','SELECTED_ROUTE_BLACKHOLE','BLOCKED'),
    ('longer_blackhole','SELECTED_ROUTE_BLACKHOLE','BLOCKED'),
    ('missing_default','NO_EXPLICIT_MATCHING_ROUTE','UNKNOWN'),
    ('prefix_list','PREFIX_LIST_CONTENTS_NOT_COLLECTED','UNKNOWN'),
    ('route_propagation','ROUTE_PROPAGATION_NOT_IN_SCOPE','UNKNOWN'),
    ('route_tie','EQUAL_PREFIX_ROUTE_PRIORITY_UNSUPPORTED','UNKNOWN'),
    ('pending_association','ROUTE_ASSOCIATION_NOT_CONFIRMED','UNKNOWN'),
    ('ambiguous_target','ROUTE_TARGET_AMBIGUOUS','UNKNOWN'),
    ('stopped','INSTANCE_STATE_NOT_RUNNING','UNKNOWN'),
])
def test_direct_failures(mutation,reason,status):
    d=setup(); inv=d['inventory']; t=inv['RouteTables'][0]; route=t['Routes'][1]
    if mutation=='missing_igw': inv['InternetGateways']=[]
    elif mutation=='igw_state': inv['InternetGateways'][0]['Attachments'][0]['State']='attaching'
    elif mutation=='blackhole': route['State']='blackhole'
    elif mutation=='longer_blackhole': t['Routes'].append(dict(DestinationCidrBlock='8.8.8.0/24', GatewayId=IGW,State='blackhole'))
    elif mutation=='missing_default': t['Routes'].pop()
    elif mutation=='prefix_list': t['Routes'].append(dict(DestinationPrefixListId='pl-12345678',GatewayId=IGW,State='active'))
    elif mutation=='route_propagation': t['PropagatingVgws']=[{'GatewayId':'vgw-12345678'}]
    elif mutation=='route_tie': t['Routes'].append(copy.deepcopy(route))
    elif mutation=='pending_association': t['Associations'][0]['AssociationState']['State']='associating'
    elif mutation=='ambiguous_target': route['NatGatewayId']=NAT
    elif mutation=='stopped': inv['Reservations'][0]['Instances'][0]['State']['Name']='stopped'
    r=run(d); assert (r['reason'],r['status'])==(reason,status)
    assert not any(h['stage']=='INTERNET_GATEWAY' for h in r['hops'])


@pytest.mark.parametrize('mutation,reason,status',[
    ('missing_nat','NAT_GATEWAY_MISSING_OR_AMBIGUOUS','UNKNOWN'),
    ('nat_state','NAT_GATEWAY_STATE_NOT_AVAILABLE','UNKNOWN'),
    ('private_nat','PUBLIC_NAT_CONNECTIVITY_NOT_CONFIRMED','UNKNOWN'),
    ('same_subnet','NAT_SUBNET_MISSING_OR_UNSUPPORTED','UNKNOWN'),
    ('unknown_subnet','NAT_SUBNET_MISSING_OR_UNSUPPORTED','UNKNOWN'),
    ('second_blackhole','SELECTED_ROUTE_BLACKHOLE','BLOCKED'),
    ('second_nat','NAT_EGRESS_NOT_DIRECT_IGW','UNKNOWN'),
    ('second_missing','NO_EXPLICIT_MATCHING_ROUTE','UNKNOWN'),
])
def test_nat_failures(mutation,reason,status):
    d=setup(True); inv=d['inventory']; nat=inv['NatGateways'][0]; t=inv['RouteTables'][0]
    if mutation=='missing_nat': inv['NatGateways']=[]
    elif mutation=='nat_state': nat['State']='pending'
    elif mutation=='private_nat': nat['ConnectivityType']='private'
    elif mutation=='same_subnet': nat['SubnetId']=S1
    elif mutation=='unknown_subnet': nat['SubnetId']='subnet-aaaaaaaa'
    elif mutation=='second_blackhole': t['Routes'][1]['State']='blackhole'
    elif mutation=='second_nat': t['Routes'][1]=dict(DestinationCidrBlock='0.0.0.0/0',NatGatewayId=NAT,State='active')
    elif mutation=='second_missing': t['Routes'].pop()
    r=run(d); assert (r['reason'],r['status'])==(reason,status)
    assert not any(h['stage']=='INTERNET_GATEWAY' for h in r['hops'])


def test_legacy_local_and_outside_scope_unchanged():
    raw=json.dumps(setup(True)).encode()
    assert lookup_observed_route(raw,S1,'10.0.2.10')['status']=='LOCAL_CANDIDATE'
    assert lookup_observed_route(raw,S1,DST)['reason']=='DESTINATION_OUTSIDE_PRIMARY_VPC_CIDR'
