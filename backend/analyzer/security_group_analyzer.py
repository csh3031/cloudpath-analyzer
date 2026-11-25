"""Static AWS SG policy evaluation; not packet forwarding or live AWS state."""
import re
from ipaddress import ip_address, ip_network

from backend.models.diagnostics import PolicyCheck, PolicyObservation

REF = re.compile(r'(aws_[\w-]+\.[\w-]+)\.id\Z')
MODERN = {'aws_vpc_security_group_ingress_rule': 'ingress',
          'aws_vpc_security_group_egress_rule': 'egress'}
FIELDS = {'aws_instance': 'vpc_security_group_ids', 'aws_network_interface': 'security_groups',
          'aws_lb': 'security_groups', 'aws_alb': 'security_groups',
          'aws_db_instance': 'vpc_security_group_ids', 'aws_rds_cluster': 'vpc_security_group_ids',
          'aws_efs_mount_target': 'security_groups'}


def ref(value):
    if isinstance(value, str) and value.startswith("${") and value.endswith("}"):
        value = value[2:-1].strip()
    m = REF.fullmatch(value) if isinstance(value, str) else None
    return m.group(1) if m else None


def kind(r):
    return r.id.split('.')[0]


def dynamic(attrs):
    return any(k in attrs for k in ('count', 'for_each', 'dynamic'))


def ip(value):
    try:
        return ip_address(value) if isinstance(value, str) else None
    except ValueError:
        return None


def proto(value):
    if isinstance(value, bool):
        return None
    return {'tcp': 'tcp', '6': 'tcp', 'udp': 'udp', '17': 'udp', '-1': 'all'}.get(str(value).lower())


def port(value):
    return value if type(value) is int and 0 <= value <= 65535 else None


def members(resource):
    if resource is None:
        return set(), True
    attrs = resource.attributes
    key = FIELDS.get(kind(resource))
    # Instances using independently managed ENIs are not resolved in this phase.
    if not key or dynamic(attrs) or (kind(resource) == 'aws_instance' and
            any(k in attrs for k in ('network_interface', 'primary_network_interface', 'security_groups'))):
        return set(), True
    values = attrs.get(key)
    if not isinstance(values, list) or not values:
        return set(), True
    ids = {ref(v) for v in values}
    return ids - {None}, None in ids


def endpoint_vpc(resource, index):
    if resource is None:
        return None
    attrs = resource.attributes
    subnet = index.get(ref(attrs.get('subnet_id')))
    if subnet and not dynamic(subnet.attributes):
        return ref(subnet.attributes.get('vpc_id'))
    return None


def peer_matches(rule, peer_ip, peer_ids, peer_unknown, group_id, direct, known_groups):
    outcomes = []
    for key in ('cidr_blocks', 'ipv6_cidr_blocks', 'cidr_ipv4', 'cidr_ipv6'):
        if key not in rule:
            continue
        raw = rule[key]
        vals = [raw] if key in ('cidr_ipv4', 'cidr_ipv6') else raw
        if not isinstance(vals, list):
            outcomes.append(None); continue
        for value in vals:
            try:
                network = ip_network(value, strict=False) if isinstance(value, str) else None
            except ValueError:
                network = None
            outcomes.append(peer_ip in network if network is not None and peer_ip is not None else None)
    for key in ('security_groups', 'source_security_group_id', 'referenced_security_group_id'):
        if key not in rule:
            continue
        vals = rule[key] if key == 'security_groups' else [rule[key]]
        if not isinstance(vals, list):
            outcomes.append(None); continue
        for value in vals:
            target = ref(value)
            outcomes.append(None if not direct or target not in known_groups else
                            True if target in peer_ids else None if peer_unknown else False)
    if rule.get('self') is True:
        outcomes.append(None if not direct else True if group_id in peer_ids else None if peer_unknown else False)
    elif 'self' in rule and rule['self'] is not False:
        outcomes.append(None)
    for key in ('prefix_list_ids', 'prefix_list_id'):
        if key in rule and rule[key] != []:
            outcomes.append(None)
    return True if True in outcomes else None if not outcomes or None in outcomes else False


def match(rule, scenario, peer_ip, peer_ids, peer_unknown, group_id, direct, known_groups):
    p = proto(rule.get('ip_protocol', rule.get('protocol')))
    wanted = proto(scenario.protocol)
    if p is None or wanted not in ('tcp', 'udp'):
        return None
    if p not in ('all', wanted):
        return False
    if p != 'all':
        lo, hi, dst = (port(rule.get('from_port')), port(rule.get('to_port')), port(scenario.destination_port))
        if None in (lo, hi, dst) or lo > hi:
            return None
        if not lo <= dst <= hi:
            return False
    return peer_matches(rule, peer_ip, peer_ids, peer_unknown, group_id, direct, known_groups)


def rules_for(group, direction, resources):
    a = group.attributes
    inline = a.get(direction, [])
    uncertain = dynamic(a) or not isinstance(inline, list)
    rows = [(f'{group.id}.{direction}[{i}]', r) for i, r in enumerate(inline)] if isinstance(inline, list) else []
    modes = set()
    if 'ingress' in a or 'egress' in a:
        modes.add('inline')
    for r in resources:
        t, attrs = kind(r), r.attributes
        if t not in MODERN and t != 'aws_security_group_rule':
            continue
        d = MODERN.get(t, attrs.get('type'))
        target = ref(attrs.get('security_group_id'))
        if target is None:
            uncertain = True
            continue
        if target != group.id:
            continue
        modes.add('modern' if t in MODERN else 'legacy')
        if d in ('ingress', 'egress') and d != direction:
            continue
        if d != direction or dynamic(attrs):
            uncertain = True
        else:
            rows.append((r.id, attrs))
    conflict = len(modes) > 1
    return rows, uncertain, conflict


def evaluate_security_groups(resources, scenario):
    """Evaluate initial TCP/UDP flow, separately for egress and ingress.

    PASS is an allow-rule match only; BLOCKED assumes complete static configuration.
    UNKNOWN preserves unresolved inputs. All endpoint checks are conditional.
    """
    index = {r.id: r for r in resources}
    src = index.get(scenario.source_resource)
    dst = index.get(scenario.destination_resource)
    src_ip, dst_ip = ip(scenario.source_ip), ip(scenario.destination_ip)
    src_ids, src_unknown = members(src)
    dst_ids, dst_unknown = members(dst)
    # External SG attachments may change effective membership. Do not prove absence.
    extra_attachments = any(kind(r) in ('aws_network_interface_sg_attachment', 'aws_network_interface_attachment') for r in resources)
    src_unknown |= extra_attachments
    dst_unknown |= extra_attachments
    sv, dv = endpoint_vpc(src, index), endpoint_vpc(dst, index)
    known_groups = {g for g, r in index.items() if kind(r) in ('aws_security_group', 'aws_default_security_group') and not dynamic(r.attributes) and ref(r.attributes.get('vpc_id')) == sv}
    all_groups_resolved = all(g in index and kind(index[g]) in ('aws_security_group', 'aws_default_security_group')
                              and not dynamic(index[g].attributes) and ref(index[g].attributes.get('vpc_id')) == sv
                              for g in src_ids | dst_ids)
    direct = bool(all_groups_resolved and scenario.assume_direct_private and sv and sv == dv and src_ip and dst_ip
                  and src_ip.version == dst_ip.version and not src_unknown and not dst_unknown)
    invalid = (len(index) != len(resources) or proto(scenario.protocol) not in ('tcp', 'udp')
               or port(scenario.destination_port) is None or dst_ip is None
               or (scenario.source_ip is not None and src_ip is None)
               or (src_ip is not None and src_ip.version != dst_ip.version))
    # Known address / subnet contradictions must not produce a confident match.
    for r, addr in ((src, src_ip), (dst, dst_ip)):
        if r is None:
            continue
        a = r.attributes
        known = ip(a.get('private_ip'))
        if known and addr and known != addr:
            invalid = True
        if r is src and ref(a.get('subnet_id')) and ref(a.get('subnet_id')) != scenario.source_subnet:
            invalid = True
    assumptions = ('입력된 주소는 해당 검사 지점에서 보이는 패킷 주소라고 가정합니다.',
                   '초기 TCP/UDP 연결의 정적 SG 검사이며 실제 전달 및 응답은 미검증입니다.')
    if scenario.complete_config:
        assumptions += ('사용자가 SG 및 연결 정보가 완전한 구성이라고 지정했습니다.',)
    if direct:
        assumptions += ('같은 VPC의 직접 사설 주소 통신이며 중간 장비가 주소를 바꾸지 않는다고 가정합니다.',)
    results = []
    for direction, endpoint, ids, unknown, peer_ip, peer_ids, peer_unknown in (
        ('egress', src, src_ids, src_unknown, dst_ip, dst_ids, dst_unknown),
        ('ingress', dst, dst_ids, dst_unknown, src_ip, src_ids, src_unknown),
    ):
        evidence = []
        matched = False
        uncertain = unknown or invalid
        for group_id in sorted(ids):
            group = index.get(group_id)
            if not group or kind(group) not in ('aws_security_group', 'aws_default_security_group') or dynamic(group.attributes):
                uncertain = True
                evidence.append({'direction': direction, 'group': group_id, 'match': 'UNKNOWN', 'reason': 'group missing or unsupported'})
                continue
            rows, incomplete, conflict = rules_for(group, direction, resources)
            uncertain |= incomplete or conflict
            if conflict:
                evidence.append({'direction': direction, 'group': group_id, 'match': 'UNKNOWN', 'reason': 'mixed rule management'})
                continue
            if not rows:
                evidence.append({'direction': direction, 'group': group_id, 'match': 'UNKNOWN' if incomplete else 'NO_RULE'})
            for rule_id, rule in rows:
                m = match(rule, scenario, peer_ip, peer_ids, peer_unknown, group_id, direct, known_groups) if isinstance(rule, dict) else None
                # Dynamic group definitions or unresolved same-group rule management are conservative.
                if incomplete and m is True:
                    m = None
                matched |= m is True
                uncertain |= m is None
                evidence.append({'direction': direction, 'group': group_id, 'rule': rule_id,
                                 'match': 'MATCH' if m is True else 'NO_MATCH' if m is False else 'UNKNOWN'})
        if invalid or endpoint is None:
            status, reason = 'UNKNOWN', '통신 입력 또는 리소스 식별 정보가 불충분하거나 모순됩니다.'
        elif matched:
            status, reason = 'PASS', '하나 이상의 연결된 SG 허용 규칙이 일치합니다.'
        elif uncertain or not scenario.complete_config:
            status, reason = 'UNKNOWN', '허용 규칙을 확인하지 못했으나 미해결 정보 또는 구성 완전성 때문에 차단을 확정할 수 없습니다.'
        else:
            status, reason = 'BLOCKED', '지정된 전체 구성에서 일치하는 SG 허용 규칙이 없습니다.'
        results.append(PolicyObservation(status, f'{direction.upper()}: {reason}',
                       endpoint.id if endpoint else None,
                       tuple(evidence), assumptions))
    return results


SECURITY_GROUP_CHECK = PolicyCheck('security_group', evaluate_security_groups,
                                    evaluation_mode='CONDITIONAL_CHECK')
