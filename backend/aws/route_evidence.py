"""Phase 6-2 initial unit: observed cross-subnet IPv4 route lookup only.

Not a session verdict, not live evidence, and never used for IaC inputs.
No implicit local route, inferred main table, or external calls.
"""
from ipaddress import IPv4Address, IPv4Network

from backend.aws.snapshot import load_aws_snapshot, sanitize_inventory
from backend.iac.plan_adapter import _read


def lookup_observed_route(raw: bytes, source_subnet_id: str, destination_ip: str) -> dict:
    """Evaluate a single source-subnet route lookup in an uploaded snapshot.

    Invalid snapshot -> ValueError (same contract as the inventory loader).
    Uncertain/unsupported lookup -> UNKNOWN. LOCAL_CANDIDATE does not imply
    endpoint ownership, policy permission, return path, or live reachability.
    """
    _, identity, metadata = load_aws_snapshot(raw)
    inventory = sanitize_inventory(_read(raw)['inventory'])
    result = {
        'analysis_type': 'STATIC_AWS_INVENTORY_ROUTE_LOOKUP',
        'input_identity': identity,
        'collected_at': metadata['collected_at'],
        'source_subnet_id': source_subnet_id,
        'destination_ip': destination_ip,
        'route_table_id': None,
        'association_type': None,
        'selected_route': None,
        'live_observation': False,
        'limitations': [
            'Uploaded snapshot is unauthenticated and sequential, not atomic.',
            'Freshness, completeness and current live state are not established.',
            'No endpoint, SG, NACL, reverse path or session verdict.',
        ],
    }

    def finish(status, reason):
        return dict(result, status=status, reason=reason)

    def unknown(reason):
        return finish('UNKNOWN', reason)

    try:
        if not isinstance(destination_ip, str):
            raise ValueError()
        dst = IPv4Address(destination_ip)
    except ValueError:
        return unknown('INVALID_IPV4_DESTINATION')
    vpc = inventory['Vpcs'][0]
    if vpc.get('State') != 'available':
        return unknown('VPC_STATE_NOT_AVAILABLE')
    primary = IPv4Network(vpc['CidrBlock'])
    if dst not in primary:
        return unknown('DESTINATION_OUTSIDE_PRIMARY_VPC_CIDR')
    subnets = inventory['Subnets']
    sources = [s for s in subnets if s['SubnetId'] == source_subnet_id]
    destinations = [s for s in subnets if dst in IPv4Network(s['CidrBlock'])]
    if len(sources) != 1 or len(destinations) != 1:
        return unknown('SUBNET_MISSING_OR_AMBIGUOUS')
    source, destination = sources[0], destinations[0]
    if any(s.get('State') != 'available' for s in (source, destination)):
        return unknown('SUBNET_STATE_NOT_AVAILABLE')
    source_net, dest_net = (IPv4Network(s['CidrBlock']) for s in (source, destination))
    if not source_net.subnet_of(primary) or not dest_net.subnet_of(primary):
        return unknown('SUBNET_OUTSIDE_PRIMARY_VPC_CIDR')
    if source['SubnetId'] == destination['SubnetId']:
        return unknown('SAME_SUBNET_LOOKUP_NOT_IN_SCOPE')
    if source_net.overlaps(dest_net):
        return unknown('OVERLAPPING_SUBNETS')

    selection = select_subnet_ipv4_route(inventory, source_subnet_id, dst)
    result.update({key: selection[key] for key in ('route_table_id', 'association_type', 'selected_route')})
    if selection['status'] != 'ACTIVE_ROUTE_CANDIDATE':
        return finish(selection['status'], selection['reason'])
    route = selection['selected_route']
    targets = [k for k in ('GatewayId', 'NatGatewayId', 'TransitGatewayId',
        'VpcPeeringConnectionId', 'NetworkInterfaceId', 'InstanceId',
        'EgressOnlyInternetGatewayId', 'LocalGatewayId', 'CarrierGatewayId',
        'CoreNetworkArn', 'VpcEndpointId') if k in route]
    if targets != ['GatewayId'] or route['GatewayId'] != 'local':
        return unknown('SELECTED_ROUTE_TARGET_OUT_OF_SCOPE')
    if IPv4Network(route['DestinationCidrBlock']) != primary:
        return unknown('LOCAL_ROUTE_CIDR_NOT_PRIMARY_VPC')
    return finish('LOCAL_CANDIDATE', 'OBSERVED_ACTIVE_LOCAL_ROUTE')


def select_subnet_ipv4_route(inventory, source_subnet_id, dst):
    """Shared selection only; caller verifies scope, endpoint and target semantics."""
    result = dict(route_table_id=None, association_type=None, selected_route=None)

    def finish(status, reason):
        return dict(result, status=status, reason=reason)

    def unknown(reason):
        return finish('UNKNOWN', reason)

    # Preserve non-associated records as uncertainty rather than dropping them
    # and silently falling back to a main table.
    explicit, main = [], []
    for table in inventory['RouteTables']:
        for assoc in table['Associations']:
            is_main = assoc.get('Main') is True
            subnet = assoc.get('SubnetId')
            if is_main and (subnet or assoc.get('GatewayId')):
                return unknown('INCONSISTENT_ROUTE_ASSOCIATION')
            if not is_main and not subnet and not assoc.get('GatewayId'):
                return unknown('UNRESOLVED_ROUTE_ASSOCIATION')
            if subnet == source_subnet_id:
                if assoc.get('GatewayId'):
                    return unknown('INCONSISTENT_ROUTE_ASSOCIATION')
                explicit.append((table, assoc))
            elif is_main:
                main.append((table, assoc))
    candidates = explicit if explicit else main
    if len(candidates) != 1:
        return unknown('ROUTE_TABLE_MISSING_OR_AMBIGUOUS')
    table, association = candidates[0]
    if association.get('AssociationState', {}).get('State') != 'associated':
        return unknown('ROUTE_ASSOCIATION_NOT_CONFIRMED')
    result['route_table_id'] = table['RouteTableId']
    result['association_type'] = 'EXPLICIT' if explicit else 'MAIN'

    matches = []
    for route in table['Routes']:
        # Prefix-list contents are absent from v1 inventory; they may overlap.
        destinations = [k for k in ('DestinationCidrBlock', 'DestinationIpv6CidrBlock',
                                    'DestinationPrefixListId') if k in route]
        if len(destinations) != 1:
            return unknown('ROUTE_DESTINATION_UNRESOLVED')
        if 'DestinationPrefixListId' in route:
            return unknown('PREFIX_LIST_CONTENTS_NOT_COLLECTED')
        if 'DestinationCidrBlock' in route:
            net = IPv4Network(route['DestinationCidrBlock'])
            if dst in net:
                matches.append((net.prefixlen, route))
    if not matches:
        return unknown('NO_EXPLICIT_MATCHING_ROUTE')
    longest = max(prefix for prefix, _ in matches)
    selected = [route for prefix, route in matches if prefix == longest]
    if len(selected) != 1:
        return unknown('EQUAL_PREFIX_ROUTE_PRIORITY_UNSUPPORTED')
    route = selected[0]
    result['selected_route'] = route
    if route.get('State') == 'blackhole':
        return finish('BLOCKED', 'SELECTED_ROUTE_BLACKHOLE')
    if route.get('State') != 'active':
        return unknown('SELECTED_ROUTE_STATE_UNCONFIRMED')
    return finish('ACTIVE_ROUTE_CANDIDATE', 'OBSERVED_ACTIVE_ROUTE')
