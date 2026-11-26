import copy
import pytest
from backend.aws.endpoint_evidence import lookup_observed_endpoint
from backend.aws.snapshot import load_aws_snapshot
from test_aws_inventory import fixture, raw, E, I, S, G, V

IP = '10.0.1.10'


def lookup(d, ip=IP):
    r = lookup_observed_endpoint(raw(d), ip)
    assert r['analysis_type'] == 'STATIC_AWS_INVENTORY_ENDPOINT_LOOKUP'
    assert r['live_observation'] is False
    assert r['input_identity'].startswith('sha256-aws-v1:')
    return r


def test_primary_candidate():
    r = lookup(fixture())
    assert (r['status'], r['eni_id'], r['instance_id'], r['subnet_id']) == ('ENDPOINT_CANDIDATE', E, I, S)
    assert r['security_group_ids'] == [G]


@pytest.mark.parametrize('case,reason', [
    ('invalid_ip','INVALID_IPV4_ENDPOINT'),
    ('outside','ENDPOINT_OUTSIDE_PRIMARY_VPC_CIDR'),
    ('vpc_state','VPC_STATE_NOT_AVAILABLE'),
    ('missing_subnet','SUBNET_MISSING_OR_AMBIGUOUS'),
    ('overlap','SUBNET_MISSING_OR_AMBIGUOUS'),
    ('subnet_state','SUBNET_STATE_NOT_AVAILABLE'),
    ('missing_eni','ENI_IP_OWNER_MISSING_OR_AMBIGUOUS'),
    ('duplicate_ip','ENI_IP_OWNER_MISSING_OR_AMBIGUOUS'),
    ('eni_subnet','ENI_SUBNET_MISMATCH'),
    ('eni_state','ENI_STATE_NOT_IN_USE'),
    ('eni_type','ENI_TYPE_OR_MANAGEMENT_UNSUPPORTED'),
    ('managed_unknown','ENI_TYPE_OR_MANAGEMENT_UNSUPPORTED'),
    ('secondary_ip','ENI_ADDRESS_CONFIGURATION_UNSUPPORTED'),
    ('missing_ips','ENI_ADDRESS_CONFIGURATION_UNSUPPORTED'),
    ('missing_attach','PRIMARY_ATTACHMENT_NOT_CONFIRMED'),
    ('device_index','PRIMARY_ATTACHMENT_NOT_CONFIRMED'),
    ('device_bool','PRIMARY_ATTACHMENT_NOT_CONFIRMED'),
    ('missing_instance','INSTANCE_MISSING_OR_AMBIGUOUS'),
    ('missing_instance_eni','INSTANCE_ENI_RELATIONSHIP_UNSUPPORTED_OR_INCONSISTENT'),
    ('extra_eni','INSTANCE_ENI_RELATIONSHIP_UNSUPPORTED_OR_INCONSISTENT'),
    ('competing_instance','INSTANCE_ENI_RELATIONSHIP_UNSUPPORTED_OR_INCONSISTENT'),
    ('instance_ip','INSTANCE_IP_OR_SUBNET_MISMATCH'),
    ('instance_subnet','INSTANCE_IP_OR_SUBNET_MISMATCH'),
    ('stopped','INSTANCE_STATE_NOT_RUNNING'),
    ('empty_groups','SECURITY_GROUP_RELATIONSHIP_INCONSISTENT'),
    ('different_groups','SECURITY_GROUP_RELATIONSHIP_INCONSISTENT'),
    ('duplicate_groups','SECURITY_GROUP_RELATIONSHIP_INCONSISTENT'),
    ('missing_group','SECURITY_GROUP_EVIDENCE_MISSING'),
])
def test_unknown(case, reason):
    d = fixture(); inv = d['inventory']; e = inv['NetworkInterfaces'][0]; i = inv['Reservations'][0]['Instances'][0]; ip = IP
    if case == 'invalid_ip': ip = '2001:db8::1'
    elif case == 'outside': ip = '192.0.2.1'
    elif case == 'vpc_state': inv['Vpcs'][0]['State'] = 'pending'
    elif case == 'missing_subnet': inv['Subnets'] = []
    elif case == 'overlap': inv['Subnets'].append(dict(SubnetId='subnet-87654321', VpcId=V, CidrBlock='10.0.1.0/25', State='available'))
    elif case == 'subnet_state': inv['Subnets'][0]['State'] = 'pending'
    elif case == 'missing_eni': inv['NetworkInterfaces'] = []
    elif case == 'duplicate_ip':
        other = copy.deepcopy(e); other['NetworkInterfaceId'] = 'eni-87654321'; other['PrivateIpAddress'] = '10.0.1.11'; inv['NetworkInterfaces'].append(other)
    elif case == 'eni_subnet': e['SubnetId'] = 'subnet-87654321'
    elif case == 'eni_state': e['Status'] = 'available'
    elif case == 'eni_type': e['InterfaceType'] = 'nat_gateway'
    elif case == 'managed_unknown': del e['RequesterManaged']
    elif case == 'secondary_ip': e['PrivateIpAddresses'].append({'PrivateIpAddress':'10.0.1.11'})
    elif case == 'missing_ips': del e['PrivateIpAddresses']
    elif case == 'missing_attach': del e['Attachment']
    elif case == 'device_index': e['Attachment']['DeviceIndex'] = 1
    elif case == 'device_bool': e['Attachment']['DeviceIndex'] = False
    elif case == 'missing_instance': inv['Reservations'] = []
    elif case == 'missing_instance_eni': i['NetworkInterfaces'] = []
    elif case == 'extra_eni':
        other = copy.deepcopy(e); other.update(NetworkInterfaceId='eni-87654321', PrivateIpAddress='10.0.1.11', PrivateIpAddresses=[{'PrivateIpAddress':'10.0.1.11'}]); inv['NetworkInterfaces'].append(other)
    elif case == 'competing_instance':
        other = copy.deepcopy(i); other['InstanceId'] = 'i-87654321'; inv['Reservations'][0]['Instances'].append(other)
    elif case == 'instance_ip': i['PrivateIpAddress'] = '10.0.1.11'
    elif case == 'instance_subnet': i['SubnetId'] = 'subnet-87654321'
    elif case == 'stopped': i['State']['Name'] = 'stopped'
    elif case == 'empty_groups': e['Groups'] = []
    elif case == 'different_groups': i['SecurityGroups'] = [{'GroupId':'sg-87654321'}]
    elif case == 'duplicate_groups': e['Groups'].append({'GroupId':G})
    elif case == 'missing_group': inv['SecurityGroups'] = []
    r = lookup(d, ip); assert (r['status'], r['reason']) == ('UNKNOWN', reason)


def test_invalid_inventory_raises():
    d = fixture(); del d['inventory']['NetworkInterfaces']
    with pytest.raises(ValueError): lookup(d)


def test_inventory_analysis_remains_restricted():
    assert load_aws_snapshot(raw(fixture()))[2]['analysis_restricted'] is True
