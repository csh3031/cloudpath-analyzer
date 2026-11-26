"""Snapshot-only, independent directional forwarding evidence for AWS Inventory.

No IaC fallback, implicit local route, packet transmission or session verdict.
"""
from ipaddress import IPv4Address, IPv4Network

from backend.aws.endpoint_evidence import lookup_observed_endpoint
from backend.aws.route_evidence import lookup_observed_route
from backend.aws.snapshot import load_aws_snapshot, sanitize_inventory
from backend.iac.plan_adapter import _read


def trace_observed_forwarding(raw: bytes, source_ip: str, destination_ip: str) -> dict:
    """Compose endpoint and route evidence for distinct cross-subnet IPv4 EC2s.

    Reverse lookup is independent and hypothetical, even if request is blocked.
    Invalid inventory raises ValueError; unsupported evidence stays UNKNOWN.
    """
    if not isinstance(raw, bytes):
        raise ValueError('Expected immutable AWS inventory bytes')
    _, identity, meta = load_aws_snapshot(raw)
    inv = sanitize_inventory(_read(raw)['inventory'])
    endpoints = {
        'source': lookup_observed_endpoint(raw, source_ip),
        'destination': lookup_observed_endpoint(raw, destination_ip),
    }
    subnets = {s['SubnetId']: s for s in inv['Subnets']}
    tables = {t['RouteTableId']: t for t in inv['RouteTables']}

    def endpoint_issue(e):
        if e['status'] != 'ENDPOINT_CANDIDATE':
            return e['reason']
        ip = IPv4Address(e['private_ip'])
        net = IPv4Network(subnets[e['subnet_id']]['CidrBlock'])
        if int(ip) - int(net.network_address) < 4 or ip == net.broadcast_address:
            return 'AWS_RESERVED_SUBNET_ADDRESS'
        return None

    def direction(start, end, conditional):
        hops = []
        result = dict(status='UNKNOWN', reason=None, conditional=conditional,
                      route_lookup=None, hops=hops, path_complete=False,
                      packet_stopped=None, policy_status='NOT_EVALUATED')

        def finish(status, reason):
            return dict(result, status=status, reason=reason,
                        path_complete=status == 'FORWARDING_CANDIDATE')

        def add(stage, resource_id, **details):
            hops.append(dict(sequence=len(hops)+1, stage=stage,
                             resource_id=resource_id, **details))

        issue = endpoint_issue(start)
        if issue:
            return finish('UNKNOWN', 'SOURCE_'+issue)
        add('SOURCE_ENDPOINT', start['eni_id'], ip=start['private_ip'],
            subnet_id=start['subnet_id'], instance_id=start['instance_id'])
        issue = endpoint_issue(end)
        if issue:
            return finish('UNKNOWN', 'DESTINATION_'+issue)
        if start['eni_id'] == end['eni_id'] or start['private_ip'] == end['private_ip']:
            return finish('UNKNOWN', 'SAME_ENDPOINT_NOT_IN_SCOPE')
        if start['subnet_id'] == end['subnet_id']:
            return finish('UNKNOWN', 'SAME_SUBNET_FORWARDING_NOT_IN_SCOPE')
        route = lookup_observed_route(raw, start['subnet_id'], end['private_ip'])
        result['route_lookup'] = route
        table_id = route['route_table_id']
        if table_id is not None:
            # Lookup result remains evidence even if the integration cannot use it.
            table = tables[table_id]
            if table.get('PropagatingVgws'):
                return finish('UNKNOWN', 'ROUTE_PROPAGATION_NOT_IN_SCOPE')
            add('ROUTE_LOOKUP', table_id, status=route['status'],
                subnet_id=start['subnet_id'], selected_route=route['selected_route'])
        if route['status'] == 'BLOCKED':
            result['packet_stopped'] = dict(stage='ROUTE_LOOKUP', resource_id=table_id,
                                            reason=route['reason'])
            return finish('BLOCKED', route['reason'])
        if route['status'] != 'LOCAL_CANDIDATE':
            return finish('UNKNOWN', route['reason'])
        add('VPC_LOCAL', meta['vpc_id'], source_subnet_id=start['subnet_id'],
            destination_subnet_id=end['subnet_id'])
        add('DESTINATION_ENDPOINT', end['eni_id'], ip=end['private_ip'],
            subnet_id=end['subnet_id'], instance_id=end['instance_id'])
        return finish('FORWARDING_CANDIDATE', 'OBSERVED_CROSS_SUBNET_LOCAL_PATH')

    request = direction(endpoints['source'], endpoints['destination'], False)
    response = direction(endpoints['destination'], endpoints['source'], True)
    # Never collapse these directions into an overall session verdict.
    return dict(analysis_type='STATIC_AWS_INVENTORY_FORWARDING',
                input_identity=identity, collected_at=meta['collected_at'],
                vpc_id=meta['vpc_id'], region=meta['region'],
                endpoints=endpoints, request=request, response=response,
                session_status='NOT_EVALUATED', live_observation=False,
                limitations=[
                    'Candidate paths are not observed packets or session success.',
                    'Response is a hypothetical independent reverse-path lookup, not a transmitted reply.',
                    'SG, NACL, protocol/ports and host firewall/application state are not evaluated.',
                    'Cross-subnet primary private IPv4 EC2 only; same-subnet and propagated routing are out of scope.',
                    'Uploaded sequential inventory is unauthenticated; freshness, completeness and atomicity are not established.',
                ])
