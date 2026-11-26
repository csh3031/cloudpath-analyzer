"""Conservative endpoint evidence for an uploaded AWS inventory, not a session verdict."""
from ipaddress import IPv4Address, IPv4Network

from backend.aws.snapshot import load_aws_snapshot, sanitize_inventory
from backend.iac.plan_adapter import _read


def lookup_observed_endpoint(raw: bytes, private_ip: str) -> dict:
    """Check a single primary IPv4 / single ENI EC2 endpoint in one VPC.

    Invalid inventory raises ValueError. Missing or unsupported evidence is UNKNOWN.
    ENDPOINT_CANDIDATE is not proof of reachability, policy, or live availability.
    """
    _, identity, metadata = load_aws_snapshot(raw)
    inv = sanitize_inventory(_read(raw)['inventory'])
    result = dict(analysis_type='STATIC_AWS_INVENTORY_ENDPOINT_LOOKUP',
                  input_identity=identity, collected_at=metadata['collected_at'],
                  private_ip=private_ip, vpc_id=metadata['vpc_id'], subnet_id=None,
                  eni_id=None, instance_id=None, security_group_ids=[],
                  live_observation=False, limitations=[
                      'Uploaded snapshot is unauthenticated and sequential, not atomic.',
                      'Freshness, completeness and live state are not established.',
                      'Attachment status is not collected by inventory v1.',
                      'Primary IPv4 / single ENI EC2 only; no policy or path verdict.'])

    def finish(reason, status='UNKNOWN'):
        return dict(result, status=status, reason=reason)

    try:
        if not isinstance(private_ip, str):
            raise ValueError()
        ip = IPv4Address(private_ip)
    except ValueError:
        return finish('INVALID_IPV4_ENDPOINT')
    vpc = inv['Vpcs'][0]
    if vpc.get('State') != 'available':
        return finish('VPC_STATE_NOT_AVAILABLE')
    primary = IPv4Network(vpc['CidrBlock'])
    if ip not in primary:
        return finish('ENDPOINT_OUTSIDE_PRIMARY_VPC_CIDR')
    subnets = [s for s in inv['Subnets'] if ip in IPv4Network(s['CidrBlock'])]
    if len(subnets) != 1:
        return finish('SUBNET_MISSING_OR_AMBIGUOUS')
    subnet = subnets[0]
    if subnet.get('State') != 'available':
        return finish('SUBNET_STATE_NOT_AVAILABLE')
    net = IPv4Network(subnet['CidrBlock'])
    if not net.subnet_of(primary):
        return finish('SUBNET_OUTSIDE_PRIMARY_VPC_CIDR')
    result['subnet_id'] = subnet['SubnetId']
    enis = inv['NetworkInterfaces']
    # Check ownership across all collected ENIs, including secondary addresses.
    # An unlisted primary address still counts as a possible conflicting claim.
    owners = [e for e in enis if e.get('PrivateIpAddress') == private_ip or
              any(a.get('PrivateIpAddress') == private_ip for a in e.get('PrivateIpAddresses', []))]
    if len(owners) != 1:
        return finish('ENI_IP_OWNER_MISSING_OR_AMBIGUOUS')
    eni = owners[0]
    result['eni_id'] = eni['NetworkInterfaceId']
    if eni['SubnetId'] != subnet['SubnetId']:
        return finish('ENI_SUBNET_MISMATCH')
    if eni.get('Status') != 'in-use':
        return finish('ENI_STATE_NOT_IN_USE')
    if eni.get('InterfaceType') != 'interface' or eni.get('RequesterManaged') is not False:
        return finish('ENI_TYPE_OR_MANAGEMENT_UNSUPPORTED')
    addresses = [a.get('PrivateIpAddress') for a in eni.get('PrivateIpAddresses', [])]
    if eni.get('PrivateIpAddress') != private_ip or addresses != [private_ip]:
        return finish('ENI_ADDRESS_CONFIGURATION_UNSUPPORTED')
    attachment = eni.get('Attachment', {})
    instance_id = attachment.get('InstanceId')
    if not instance_id or type(attachment.get('DeviceIndex')) is not int or attachment['DeviceIndex'] != 0:
        return finish('PRIMARY_ATTACHMENT_NOT_CONFIRMED')
    result['instance_id'] = instance_id
    instances = [i for r in inv['Reservations'] for i in r['Instances']]
    candidates = [i for i in instances if i['InstanceId'] == instance_id]
    if len(candidates) != 1:
        return finish('INSTANCE_MISSING_OR_AMBIGUOUS')
    instance = candidates[0]
    # Check both sides of the association and competing ENI/IP claims.
    listed = [e['NetworkInterfaceId'] for e in instance.get('NetworkInterfaces', [])]
    attached = [e['NetworkInterfaceId'] for e in enis if e.get('Attachment', {}).get('InstanceId') == instance_id]
    claimants = [i['InstanceId'] for i in instances if any(e['NetworkInterfaceId'] == eni['NetworkInterfaceId'] for e in i.get('NetworkInterfaces', []))]
    ip_claimants = [i['InstanceId'] for i in instances if i.get('PrivateIpAddress') == private_ip]
    if listed != [eni['NetworkInterfaceId']] or attached != listed or claimants != [instance_id]:
        return finish('INSTANCE_ENI_RELATIONSHIP_UNSUPPORTED_OR_INCONSISTENT')
    if instance.get('SubnetId') != subnet['SubnetId'] or ip_claimants != [instance_id]:
        return finish('INSTANCE_IP_OR_SUBNET_MISMATCH')
    if instance.get('State', {}).get('Name') != 'running':
        return finish('INSTANCE_STATE_NOT_RUNNING')
    groups = [g['GroupId'] for g in eni['Groups']]
    instance_groups = [g['GroupId'] for g in instance.get('SecurityGroups', [])]
    if not groups or len(groups) != len(set(groups)) or len(instance_groups) != len(set(instance_groups)) or set(groups) != set(instance_groups):
        return finish('SECURITY_GROUP_RELATIONSHIP_INCONSISTENT')
    if not set(groups).issubset({g['GroupId'] for g in inv['SecurityGroups']}):
        return finish('SECURITY_GROUP_EVIDENCE_MISSING')
    result['security_group_ids'] = sorted(groups)
    return finish('OBSERVED_PRIMARY_EC2_ENDPOINT_CANDIDATE', 'ENDPOINT_CANDIDATE')
