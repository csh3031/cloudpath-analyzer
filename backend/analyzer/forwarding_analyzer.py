"""Static IPv4 forwarding candidates. No packet sending or policy verdicts."""
from ipaddress import ip_address, ip_network
from backend.analyzer.routing_analyzer import analyze_route
from backend.analyzer.network_acl_analyzer import ref, dynamic, kind


def _ip(value):
    try:
        a = ip_address(value) if isinstance(value, str) else None
        return a if a is not None and a.version == 4 else None
    except ValueError:
        return None


def _net(value):
    try:
        n = ip_network(value, strict=True) if isinstance(value, str) else None
        return n if n is not None and n.version == 4 else None
    except ValueError:
        return None


def _subnet(index, rid):
    s = index.get(rid)
    if not s or kind(s) != 'aws_subnet' or dynamic(s.attributes):
        return None
    v = index.get(ref(s.attributes.get('vpc_id')))
    n = _net(s.attributes.get('cidr_block'))
    vn = _net(v.attributes.get('cidr_block')) if v else None
    if not v or kind(v) != 'aws_vpc' or dynamic(v.attributes) or not n or not vn or not n.subnet_of(vn):
        return None
    return s, v, n


def _endpoint(index, rid, ip):
    r = index.get(rid)
    if not r or kind(r) not in {'aws_instance', 'aws_network_interface'} or dynamic(r.attributes):
        return None
    a = r.attributes
    if any(k in a for k in ('network_interface', 'primary_network_interface', 'network_interface_id')):
        return None
    context = _subnet(index, ref(a.get('subnet_id')))
    if not context or ip is None:
        return None
    s, v, n = context
    # An IP in the CIDR is not proof of ownership. Require explicit assignment.
    values = a.get('private_ips', [])
    if not isinstance(values, list) or any(_ip(x) is None for x in values):
        return None
    if 'private_ip' in a:
        if _ip(a['private_ip']) is None:
            return None
        values = [*values, a['private_ip']]
    if ip not in [_ip(x) for x in values] or ip not in n:
        return None
    if int(ip)-int(n.network_address) < 4 or ip == n.broadcast_address:
        return None
    return r, s, v, n


def _route_uncertainty(resources):
    # Conservative global guard: unresolved relationships may affect selected VPC.
    for r in resources:
        t, a = kind(r), r.attributes
        if t in {'aws_vpc_ipv4_cidr_block_association', 'aws_vpn_gateway_route_propagation'}:
            return 'Secondary CIDR or propagated routes not modeled.'
        if t in {'aws_route', 'aws_route_table', 'aws_default_route_table', 'aws_main_route_table_association', 'aws_route_table_association'}:
            if dynamic(a):
                return 'Dynamic routing configuration: '+r.id
            key = {'aws_route':'route_table_id','aws_route_table':'vpc_id','aws_default_route_table':'default_route_table_id','aws_main_route_table_association':'vpc_id','aws_route_table_association':'subnet_id'}[t]
            attr = 'default_route_table_id' if t=='aws_default_route_table' else 'id'
            if not ref(a.get(key), attr):
                return 'Unresolved routing association: '+r.id
            if t in {'aws_main_route_table_association','aws_route_table_association'} and not ref(a.get('route_table_id')):
                return 'Unresolved route table: '+r.id
            if a.get('propagating_vgws') or a.get('gateway_id') and t=='aws_route_table_association':
                return 'Propagation or gateway association not modeled.'
            if t=='aws_route' and any(a.get(k) is not None for k in ('instance_id','egress_only_gateway_id','local_gateway_id','carrier_gateway_id','core_network_arn','vpc_endpoint_id','destination_ipv6_cidr_block')):
                return 'Unsupported standalone route attributes: '+r.id
    return None


def trace_forwarding(resources, scenario, *, complete_routing_config=False):
    """Return a candidate request path, independent of SG/NACL and response.

    REACHED_DESTINATION only means the supported static forwarding model reaches
    the named endpoint, under explicit completeness/directness assumptions.
    """
    hops, lookups = [], []
    def add(stage, resource, **details):
        hops.append(dict(sequence=len(hops)+1, stage=stage, resource=resource, **details))
    def result(status, reason):
        return dict(status=status, path_complete=status=='REACHED_DESTINATION',
                    hops=hops, route_lookups=lookups, reason=reason,
                    packet_stopped=None, path_kind='STATIC_FORWARDING_CANDIDATE',
                    assumptions=['No live packet transmission or policy evaluation.',
                                 'Complete routing configuration asserted: '+str(complete_routing_config),
                                 'Direct private communication asserted: '+str(scenario.assume_direct_private)])
    index = {r.id:r for r in resources}
    if len(index)!=len(resources): return result('UNKNOWN','Duplicate resource IDs.')
    src, dst = _ip(scenario.source_ip), _ip(scenario.destination_ip)
    source = _endpoint(index, scenario.source_resource, src)
    if not source or dst is None or src==dst:
        return result('UNKNOWN','Source ownership or IPv4 destination not resolved, or same IP.')
    r, s, v, n = source
    if s.id != scenario.source_subnet: return result('UNKNOWN','Source subnet mismatch.')
    add('SOURCE_ENDPOINT',r.id,ip=str(src),subnet=s.id,vpc=v.id)
    dest = _endpoint(index, scenario.destination_resource, dst) if scenario.destination_resource else None
    if scenario.destination_resource and not dest:
        return result('UNKNOWN','Destination address ownership not resolved.')
    if dest and dest[2].id==v.id and s.id==dest[1].id:
        if not scenario.assume_direct_private: return result('UNKNOWN','Direct private communication not asserted.')
        add('SAME_SUBNET',s.id,route_table_applicable=False,nacl_applicable=False)
        add('DESTINATION_ENDPOINT',dest[0].id,ip=str(dst),subnet=s.id,vpc=v.id)
        return result('REACHED_DESTINATION','Same-subnet forwarding candidate; no subnet route-table traversal.')
    if not complete_routing_config:
        return result('UNKNOWN','Complete routing configuration not asserted.')
    issue = _route_uncertainty(resources)
    if issue: return result('UNKNOWN',issue)
    seen = set()
    current = s
    for _ in range(16):
        if current.id in seen: return result('LOOP_DETECTED','Repeated subnet routing context; candidate loop.')
        seen.add(current.id)
        route = analyze_route(resources,current.id,str(dst))
        lookups.append(route)
        add('ROUTE_LOOKUP',route.get('route_table') or current.id,subnet=current.id,
            status=route.get('status'),matched_cidr=route.get('matched_cidr'),next_hop=route.get('next_hop'))
        if route.get('status')=='NO_ROUTE': return result('NO_ROUTE','No matching route in modeled routing context.')
        if route.get('status')!='ROUTE_FOUND': return result('UNKNOWN','Route selection or target unresolved.')
        target = route.get('next_hop')
        if target=='local':
            if current.id != s.id or not dest or dest[2].id!=v.id or not scenario.assume_direct_private:
                return result('UNKNOWN','Local route alone does not establish destination or direct forwarding.')
            add('VPC_LOCAL',v.id,source_subnet=s.id,destination_subnet=dest[1].id)
            add('DESTINATION_ENDPOINT',dest[0].id,ip=str(dst),subnet=dest[1].id,vpc=v.id)
            return result('REACHED_DESTINATION','Same-VPC local forwarding candidate; policies and response excluded.')
        gateway = index.get(target)
        if not gateway or dynamic(gateway.attributes): return result('UNKNOWN','Gateway unresolved.')
        a=gateway.attributes
        if kind(gateway)=='aws_internet_gateway':
            if ref(a.get('vpc_id'))!=v.id: return result('UNKNOWN','IGW attachment to source VPC not verified.')
            add('INTERNET_GATEWAY',gateway.id,vpc=v.id,translation_verified=False)
            return result('PARTIAL','IGW route candidate only; public IP mapping, gateway policies and external destination not verified.')
        if kind(gateway)=='aws_nat_gateway':
            if dest: return result('UNKNOWN','NAT route for named endpoint outside direct model.')
            if a.get('connectivity_type','public')!='public': return result('UNKNOWN','Private NAT or unresolved connectivity type not modeled.')
            context=_subnet(index,ref(a.get('subnet_id')))
            if not context or context[1].id!=v.id: return result('UNKNOWN','NAT subnet or VPC unresolved.')
            add('NAT_GATEWAY',gateway.id,subnet=context[0].id,translation_verified=False)
            current=context[0]
            continue
        return result('UNKNOWN','Unsupported route target.')
    return result('UNKNOWN','Route traversal limit exceeded.')
