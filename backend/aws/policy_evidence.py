"""Independent static AWS policy checks for a proposed cross-subnet TCP flow.

No live reachability, connection tracking observation or session verdict.
"""
from ipaddress import IPv4Address, IPv4Network
from backend.aws.forwarding_evidence import trace_observed_forwarding
from backend.aws.snapshot import sanitize_inventory
from backend.iac.plan_adapter import _read


def _port(n):
    return type(n) is int and 1 <= n <= 65535


def _range(lo, hi, port):
    if type(lo) is not int or type(hi) is not int or not 0 <= lo <= hi <= 65535:
        return None
    return lo <= port <= hi


def _protocol(value):
    if isinstance(value, str) and value.lower() == 'tcp':
        return True
    if type(value) not in (str, int):
        return None
    try:
        n = int(value)
    except ValueError:
        return False if value in ('udp', 'icmp', 'icmpv6') else None
    return n in (-1, 6) if -1 <= n <= 255 else None


def _cidr(value, ip):
    try:
        return ip in IPv4Network(value)
    except (ValueError, TypeError):
        return None


def _result(status, reason, **details):
    return dict(status=status, reason=reason, **details)


def _sg(groups, endpoint, peer, egress, port):
    ids = endpoint['security_group_ids']
    uncertain = False
    for gid in ids:
        for i, rule in enumerate(groups[gid]['IpPermissionsEgress' if egress else 'IpPermissions']):
            protocol = _protocol(rule['IpProtocol'])
            if protocol is False:
                continue
            ports = True if str(rule['IpProtocol']) == '-1' else _range(rule.get('FromPort'), rule.get('ToPort'), port)
            if ports is False:
                continue
            cidrs = [_cidr(r['CidrIp'], IPv4Address(peer['private_ip'])) for r in rule.get('IpRanges', [])]
            # v1 omits SG reference account/peering metadata and prefix-list contents.
            unresolved = bool(rule.get('UserIdGroupPairs') or rule.get('PrefixListIds')) or None in cidrs
            if protocol is True and ports is True and True in cidrs:
                return _result('ALLOW_CANDIDATE', 'MATCHING_IPV4_SG_RULE', group_id=gid, rule_index=i, rule=rule)
            if unresolved or ((protocol is None or ports is None) and True in cidrs):
                uncertain = True
    return _result('UNKNOWN' if uncertain else 'BLOCKED',
                   'SG_RULE_UNRESOLVED' if uncertain else 'NO_MATCHING_SG_ALLOW', group_ids=ids)


def _acl(acls, endpoint, peer, egress, port):
    matches = [(a, x) for a in acls for x in a['Associations'] if x.get('SubnetId') == endpoint['subnet_id']]
    if len(matches) != 1:
        return _result('UNKNOWN', 'ACL_ASSOCIATION_MISSING_OR_AMBIGUOUS')
    acl, assoc = matches[0]
    aid = acl['NetworkAclId']
    if not isinstance(assoc.get('NetworkAclAssociationId'), str):
        return _result('UNKNOWN', 'ACL_ASSOCIATION_UNCONFIRMED', acl_id=aid)
    # IPv6 rules are irrelevant to this IPv4 tuple. A rule without either family is ambiguous.
    rules = [r for r in acl['Entries'] if r['Egress'] is egress and ('CidrBlock' in r or 'Ipv6CidrBlock' not in r)]
    numbers = [r['RuleNumber'] for r in rules]
    if any(type(n) is not int or not 1 <= n <= 32767 for n in numbers) or len(numbers) != len(set(numbers)):
        return _result('UNKNOWN', 'ACL_RULE_ORDER_UNCONFIRMED', acl_id=aid)
    for rule in sorted(rules, key=lambda r:r['RuleNumber']):
        match = _cidr(rule.get('CidrBlock'), IPv4Address(peer['private_ip']))
        proto = _protocol(rule['Protocol'])
        ports = True if str(rule['Protocol']) == '-1' else _range(rule.get('PortRange', {}).get('From'), rule.get('PortRange', {}).get('To'), port)
        if False in (match, proto, ports):
            continue
        detail = dict(acl_id=aid, rule_number=rule['RuleNumber'], rule=rule)
        if None in (match, proto, ports) or rule['RuleAction'] not in ('allow','deny') or (rule['RuleNumber']==32767 and rule['RuleAction']!='deny'):
            return _result('UNKNOWN', 'ACL_FIRST_POSSIBLE_RULE_UNRESOLVED', **detail)
        return _result('ALLOW_CANDIDATE' if rule['RuleAction']=='allow' else 'BLOCKED', 'MATCHING_ACL_RULE', **detail)
    return _result('UNKNOWN', 'ACL_NO_EXPLICIT_MATCH_OR_DEFAULT', acl_id=aid)


def evaluate_observed_policy(raw: bytes, source_ip: str, destination_ip: str, source_port: int, destination_port: int) -> dict:
    """Evaluate independent request/conditional reply policies; TCP ports explicit.

    Static matches rely on uploaded rule lists; no completeness/freshness guarantee.
    """
    if not _port(source_port) or not _port(destination_port):
        raise ValueError('Expected explicit TCP source and destination ports in 1..65535')
    forward = trace_observed_forwarding(raw, source_ip, destination_ip)
    inv = sanitize_inventory(_read(raw)['inventory'])
    groups = {g['GroupId']:g for g in inv['SecurityGroups']}
    src, dst = (forward['endpoints'][k] for k in ('source','destination'))
    def checks(a,b,port,reply):
        stages = ('SOURCE_SG_EGRESS','SOURCE_NACL_EGRESS','DESTINATION_NACL_INGRESS','DESTINATION_SG_INGRESS')
        supported = all(e['status']=='ENDPOINT_CANDIDATE' for e in (a,b)) and a['subnet_id'] != b['subnet_id'] and all(not forward[d]['reason'].endswith('AWS_RESERVED_SUBNET_ADDRESS') for d in ('request','response'))
        if not supported:
            rows = [_result('NOT_EVALUATED','ENDPOINT_OR_SCOPE_UNCONFIRMED') for _ in stages]
        else:
            # No tracked-state assertion; F must establish request and connection conditions.
            conditional = _result('CONDITIONAL','REQUIRES_ESTABLISHED_TRACKED_REQUEST')
            rows = [conditional if reply else _sg(groups,a,b,True,port),
                    _acl(inv['NetworkAcls'],a,b,True,port),
                    _acl(inv['NetworkAcls'],b,a,False,port),
                    conditional if reply else _sg(groups,b,a,False,port)]
        return dict(conditional=reply, destination_port=port,
                    checks=[dict(r,stage=s,independent=True) for s,r in zip(stages,rows)])
    return dict(analysis_type='STATIC_AWS_INVENTORY_POLICY', input_identity=forward['input_identity'],
                collected_at=forward['collected_at'], protocol='tcp', source_port=source_port,
                destination_port=destination_port, forwarding=forward,
                request=checks(src,dst,destination_port,False), response=checks(dst,src,source_port,True),
                session_status='NOT_EVALUATED', live_observation=False,
                limitations=['Independent policy checks are not traversed packet hops.',
                             'SG reply requires tracked connection evidence/assumption; untracked and runtime tracking behavior not established.',
                             'SG references and prefix-list contents are unresolved; IPv4 CIDR TCP only.',
                             'Snapshot freshness, completeness and authenticity not established; host firewall and application not evaluated.'])
