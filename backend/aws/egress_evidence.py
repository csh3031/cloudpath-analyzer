"""Bounded, offline IPv4 internet egress route evidence (Phase 7-A1)."""
from ipaddress import IPv4Address, IPv4Network

from backend.aws.endpoint_evidence import lookup_observed_endpoint
from backend.aws.route_evidence import select_subnet_ipv4_route
from backend.aws.snapshot import load_aws_snapshot, sanitize_inventory, FORMAT_V2
from backend.iac.plan_adapter import _read
from backend.aws.translation_evidence import mapping_evidence

_TARGETS = ('GatewayId', 'NatGatewayId', 'TransitGatewayId', 'VpcPeeringConnectionId',
            'NetworkInterfaceId', 'InstanceId', 'EgressOnlyInternetGatewayId',
            'LocalGatewayId', 'CarrierGatewayId', 'CoreNetworkArn', 'VpcEndpointId')


def trace_internet_egress(raw: bytes, source_ip: str, destination_ip: str) -> dict:
    """Inspect EC2 -> IGW or EC2 -> public NAT -> IGW configuration only.

    No network calls, no policy or session verdict, no synthesized NAT mapping.
    The path ends at an IGW candidate, never at the external destination.
    """
    if not isinstance(raw, bytes):
        raise ValueError('Expected immutable AWS inventory bytes')
    _, identity, meta = load_aws_snapshot(raw)
    doc = _read(raw)
    inv = sanitize_inventory(doc['inventory'], version=doc['format'])
    out = dict(analysis_type='STATIC_AWS_INTERNET_EGRESS', input_identity=identity,
               region=meta['region'], vpc_id=meta['vpc_id'], collected_at=meta['collected_at'],
               source_ip=source_ip, destination_ip=destination_ip, endpoint=None,
               route_lookups=[], hops=[], translation=None, session_status='NOT_EVALUATED',
               policy_status='NOT_EVALUATED', response_status='NOT_EVALUATED',
               live_observation=False, internet_reachability='UNKNOWN', limitations=[
                   'Uploaded snapshot is unauthenticated and non-atomic.',
                   'Only same-VPC IPv4 EC2 egress route evidence; no external path or host state.',
                   ('Address mapping candidates use v2 configuration; runtime NAT state and source port are unknown.' if doc['format']==FORMAT_V2 else 'Inventory v1 does not collect EC2 public IP associations or NAT address mappings.'),
                   'No SG/NACL, gateway ingress routing, translation state or return path evaluation.',
                   'No AWS API calls or packets transmitted.'])

    def finish(status, reason):
        return dict(out, status=status, reason=reason)

    def add(stage, resource_id):
        out['hops'].append(dict(sequence=len(out['hops'])+1, stage=stage, resource_id=resource_id))

    try:
        if not isinstance(destination_ip, str):
            raise ValueError()
        dst = IPv4Address(destination_ip)
    except ValueError:
        return finish('UNKNOWN', 'INVALID_IPV4_DESTINATION')
    if not dst.is_global or dst.is_multicast or dst.is_reserved or dst.is_loopback or dst.is_link_local:
        return finish('UNKNOWN', 'DESTINATION_NOT_PUBLIC_UNICAST_IPV4')
    vpc = inv['Vpcs'][0]
    nets = [IPv4Network(vpc['CidrBlock'])] + [IPv4Network(a['CidrBlock']) for a in vpc.get('CidrBlockAssociationSet', [])]
    if any(dst in n for n in nets) or any(dst in IPv4Network(s['CidrBlock']) for s in inv['Subnets']):
        return finish('UNKNOWN', 'DESTINATION_IN_COLLECTED_VPC')
    endpoint = lookup_observed_endpoint(raw, source_ip)
    out['endpoint'] = endpoint
    if endpoint['status'] != 'ENDPOINT_CANDIDATE':
        return finish('UNKNOWN', endpoint['reason'])
    subnets = {s['SubnetId']: s for s in inv['Subnets']}
    tables = {t['RouteTableId']: t for t in inv['RouteTables']}
    source_subnet = endpoint['subnet_id']
    ip = IPv4Address(endpoint['private_ip'])
    net = IPv4Network(subnets[source_subnet]['CidrBlock'])
    if int(ip)-int(net.network_address) < 4 or ip == net.broadcast_address:
        return finish('UNKNOWN', 'AWS_RESERVED_SUBNET_ADDRESS')
    # Scope to a single unambiguous primary VPC CIDR and subnet placement.
    if any(n != nets[0] for n in nets):
        return finish('UNKNOWN', 'SECONDARY_VPC_CIDR_NOT_IN_SCOPE')
    if any(IPv4Network(s['CidrBlock']).overlaps(net) for k,s in subnets.items() if k != source_subnet):
        return finish('UNKNOWN', 'OVERLAPPING_SOURCE_SUBNETS')
    add('SOURCE_ENDPOINT', endpoint['eni_id'])

    def select(subnet_id):
        selected = select_subnet_ipv4_route(inv, subnet_id, dst)
        out['route_lookups'].append(dict(selected, source_subnet_id=subnet_id))
        tid = selected['route_table_id']
        if tid is not None:
            add('ROUTE_LOOKUP', tid)
            if tables[tid].get('PropagatingVgws'):
                return 'UNKNOWN', 'ROUTE_PROPAGATION_NOT_IN_SCOPE', None
        if selected['status'] != 'ACTIVE_ROUTE_CANDIDATE':
            return selected['status'], selected['reason'], None
        route = selected['selected_route']
        targets = [k for k in _TARGETS if k in route]
        if len(targets) != 1:
            return 'UNKNOWN', 'ROUTE_TARGET_AMBIGUOUS', None
        return 'ACTIVE_ROUTE_CANDIDATE', None, (targets[0], route[targets[0]])

    status, reason, target = select(source_subnet)
    if target is None:
        return finish(status, reason)
    via_nat = target[0] == 'NatGatewayId'
    if via_nat:
        matches = [g for g in inv['NatGateways'] if g['NatGatewayId'] == target[1]]
        if len(matches) != 1:
            return finish('UNKNOWN', 'NAT_GATEWAY_MISSING_OR_AMBIGUOUS')
        nat = matches[0]
        if nat.get('State') != 'available':
            return finish('UNKNOWN', 'NAT_GATEWAY_STATE_NOT_AVAILABLE')
        if nat.get('ConnectivityType') != 'public':
            return finish('UNKNOWN', 'PUBLIC_NAT_CONNECTIVITY_NOT_CONFIRMED')
        nid = nat.get('SubnetId')
        subnet = subnets.get(nid)
        if not subnet or nid == source_subnet or subnet.get('State') != 'available':
            return finish('UNKNOWN', 'NAT_SUBNET_MISSING_OR_UNSUPPORTED')
        natnet = IPv4Network(subnet['CidrBlock'])
        if not natnet.subnet_of(nets[0]) or any(IPv4Network(s['CidrBlock']).overlaps(natnet) for k,s in subnets.items() if k != nid):
            return finish('UNKNOWN', 'NAT_SUBNET_SCOPE_UNCONFIRMED')
        add('PUBLIC_NAT_GATEWAY', nat['NatGatewayId'])
        out['translation'] = dict(kind='PUBLIC_NAT_THEN_IGW', state='NOT_EVALUATED',
                                  original_source_ip=source_ip, translated_private_ip=None, translated_public_ip=None)
        status, reason, target = select(nid)
        if target is None:
            return finish(status, reason)
        if target[0] != 'GatewayId' or not isinstance(target[1], str) or not target[1].startswith('igw-'):
            return finish('UNKNOWN', 'NAT_EGRESS_NOT_DIRECT_IGW')
    if target[0] != 'GatewayId' or not isinstance(target[1], str) or not target[1].startswith('igw-'):
        return finish('UNKNOWN', 'EGRESS_TARGET_NOT_IN_SCOPE')
    matches = [g for g in inv['InternetGateways'] if g['InternetGatewayId'] == target[1]]
    if len(matches) != 1:
        return finish('UNKNOWN', 'IGW_MISSING_OR_AMBIGUOUS')
    attachments = matches[0].get('Attachments', [])
    if len(attachments) != 1 or attachments[0].get('VpcId') != meta['vpc_id'] or attachments[0].get('State') != 'available':
        return finish('UNKNOWN', 'IGW_ATTACHMENT_NOT_AVAILABLE')
    add('INTERNET_GATEWAY', target[1])
    if not via_nat:
        out['translation'] = dict(kind='IGW_PUBLIC_IPV4_MAPPING', state='NOT_EVALUATED',
                                  original_source_ip=source_ip, translated_private_ip=None, translated_public_ip=None)
    if doc['format'] == FORMAT_V2:
        out['translation'] = mapping_evidence(inv, endpoint, nat if via_nat else None)
    return finish('EGRESS_ROUTE_CANDIDATE', 'OBSERVED_PUBLIC_NAT_IGW_ROUTE' if via_nat else 'OBSERVED_DIRECT_IGW_ROUTE')
