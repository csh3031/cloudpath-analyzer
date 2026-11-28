"""Independent static AWS policy checks for a proposed cross-subnet TCP flow.

No live reachability, connection tracking observation or session verdict.
"""
from ipaddress import IPv4Address, IPv4Network
from backend.aws.local_delivery_evidence import subnet_policy
from backend.aws.forwarding_evidence import trace_observed_forwarding
from backend.aws.snapshot import sanitize_inventory
from backend.iac.plan_adapter import _read
from backend.aws.prefix_list_evidence import load_prefix_lists, match_prefix_list


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


def _local_reference(groups, endpoint, peer, pair, direct_same_vpc):
    """Match only verified direct private ENI peer membership in a single VPC.

    Callers must establish endpoint correlation and a direct local route first.
    No inference from a CIDR, a group name, a translated IP, or a rule's own SG.
    Unknown references remain unresolved (including absent group metadata).
    """
    if not direct_same_vpc or not isinstance(pair, dict):
        return None
    ref = pair.get('GroupId')
    if not isinstance(ref, str) or ref not in groups:
        return None
    # The v1/v2 normalized snapshot retains GroupId, not account/peering
    # metadata. Only groups positively present in this selected VPC qualify.
    if set(pair) != {'GroupId'}:
        return None
    a, b = endpoint.get('security_group_ids'), peer.get('security_group_ids')
    if not all(isinstance(ids, list) and ids and all(isinstance(g,str) and g in groups for g in ids) and len(ids)==len(set(ids)) for ids in (a,b)):
        return None
    vpcs = {groups[g].get('VpcId') for g in a+b+[ref]}
    if len(vpcs)!=1 or not next(iter(vpcs)):
        return None
    if not endpoint.get('eni_id') or not peer.get('eni_id') or endpoint['eni_id']==peer['eni_id']:
        return None
    return ref in b


def _sg(groups, endpoint, peer, egress, port, *, direct_same_vpc=False, prefix_lists=None):
    ids = endpoint['security_group_ids']
    uncertain = False
    unresolved_prefixes = []
    for gid in ids:
        for i, rule in enumerate(groups[gid]['IpPermissionsEgress' if egress else 'IpPermissions']):
            protocol = _protocol(rule['IpProtocol'])
            if protocol is False:
                continue
            ports = True if str(rule['IpProtocol']) == '-1' else _range(rule.get('FromPort'), rule.get('ToPort'), port)
            if ports is False:
                continue
            cidrs = [_cidr(r['CidrIp'], IPv4Address(peer['private_ip'])) for r in rule.get('IpRanges', [])]
            refs = [(pair, _local_reference(groups, endpoint, peer, pair, direct_same_vpc))
                    for pair in rule.get('UserIdGroupPairs', [])]
            prefixes = [match_prefix_list(pair, prefix_lists or {}, peer['private_ip'])
                        for pair in rule.get('PrefixListIds', [])]
            unresolved_prefixes.extend(detail for match,detail in prefixes if match is None)
            unresolved = any(match is None for match,_ in prefixes) or None in cidrs or any(match is None for _,match in refs)
            if protocol is True and ports is True and True in cidrs:
                return _result('ALLOW_CANDIDATE', 'MATCHING_IPV4_SG_RULE', group_id=gid, rule_index=i, rule=rule)
            for pair, match in refs:
                if match is True and protocol is True and ports is True:
                    return _result('ALLOW_CANDIDATE', 'MATCHING_DIRECT_PEER_SG_REFERENCE', group_id=gid,
                                   rule_index=i, rule=rule, referenced_group_id=pair['GroupId'],
                                   peer_eni_id=peer['eni_id'], peer_private_ip=peer['private_ip'],
                                   reference_scope='DIRECT_SAME_VPC_PRIVATE_ENI')
            for match, detail in prefixes:
                if match is True and protocol is True and ports is True:
                    return _result('ALLOW_CANDIDATE', 'MATCHING_IPV4_PREFIX_LIST_RULE', group_id=gid, rule_index=i, rule=rule, **detail)
            if unresolved or ((protocol is None or ports is None) and (True in cidrs or any(match is True for _,match in refs) or any(match is True for match,_ in prefixes))):
                uncertain = True
    return _result('UNKNOWN' if uncertain else 'BLOCKED',
                   'SG_RULE_UNRESOLVED' if uncertain else 'NO_MATCHING_SG_ALLOW', group_ids=ids,
                   **({'unresolved_prefix_lists':unresolved_prefixes} if unresolved_prefixes else {}))


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


def evaluate_observed_policy(raw: bytes, source_ip: str, destination_ip: str, source_port: int, destination_port: int, *, prefix_list_raw=None) -> dict:
    """Evaluate independent request/conditional reply policies; TCP ports explicit.

    Static matches rely on uploaded rule lists; no completeness/freshness guarantee.
    """
    if not _port(source_port) or not _port(destination_port):
        raise ValueError('Expected explicit TCP source and destination ports in 1..65535')
    forward = trace_observed_forwarding(raw, source_ip, destination_ip)
    inv = sanitize_inventory(_read(raw)['inventory'])
    prefix_lists, prefix_summary = load_prefix_lists(prefix_list_raw, forward['input_identity'], forward['region'], forward['collected_at'])
    groups = {g['GroupId']:g for g in inv['SecurityGroups']}
    src, dst = (forward['endpoints'][k] for k in ('source','destination'))
    def checks(a,b,port,reply):
        stages = ('SOURCE_SG_EGRESS','SOURCE_NACL_EGRESS','DESTINATION_NACL_INGRESS','DESTINATION_SG_INGRESS')
        supported = all(e['status']=='ENDPOINT_CANDIDATE' for e in (a,b)) and a['eni_id']!=b['eni_id'] and a['private_ip']!=b['private_ip'] and all(not forward[d]['reason'].endswith('AWS_RESERVED_SUBNET_ADDRESS') for d in ('request','response')) and (a['subnet_id']!=b['subnet_id'] or forward['request']['status']==forward['response']['status']=='FORWARDING_CANDIDATE')
        if not supported:
            rows = [_result('NOT_EVALUATED','ENDPOINT_OR_SCOPE_UNCONFIRMED') for _ in stages]
        else:
            # No tracked-state assertion; F must establish request and connection conditions.
            conditional = _result('CONDITIONAL','REQUIRES_ESTABLISHED_TRACKED_REQUEST')
            direct = forward['request']['status']=='FORWARDING_CANDIDATE' and not reply
            local=forward['response' if reply else 'request'].get('local_delivery',{})
            rows = [conditional if reply else _sg(groups,a,b,True,port,direct_same_vpc=direct,prefix_lists=prefix_lists),
                    subnet_policy(_acl,inv,a,b,True,port,local),
                    subnet_policy(_acl,inv,b,a,False,port,local),
                    conditional if reply else _sg(groups,b,a,False,port,direct_same_vpc=direct,prefix_lists=prefix_lists)]
        return dict(conditional=reply, destination_port=port,
                    checks=[dict(r,stage=s,independent=True) for s,r in zip(stages,rows)])
    return dict(analysis_type='STATIC_AWS_INVENTORY_POLICY', input_identity=forward['input_identity'],
                collected_at=forward['collected_at'], protocol='tcp', source_port=source_port,
                destination_port=destination_port, forwarding=forward,
                request=checks(src,dst,destination_port,False), response=checks(dst,src,source_port,True),
                **({'prefix_list_evidence':prefix_summary} if prefix_summary is not None else {}),
                session_status='NOT_EVALUATED', live_observation=False,
                limitations=['Independent policy checks are not traversed packet hops.',
                             'SG reply requires tracked connection evidence/assumption; untracked and runtime tracking behavior not established.',
                             'Direct same-VPC verified private ENI SG references are supported; other references unresolved; optional version-bound customer-managed IPv4 prefix list evidence only; no prefix-list routes.',
                             'Snapshot freshness, completeness and authenticity not established; host firewall and application not evaluated.'])
