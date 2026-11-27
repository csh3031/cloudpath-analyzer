"""Offline correlation of uploaded default-format VPC Flow Logs, never live probing."""
from collections import Counter
from ipaddress import IPv4Address, ip_address
import re
from backend.aws.session_evidence import analyze_observed_session
from backend.aws.reachability_evidence import MAX_BYTES, MAX_SKEW_SECONDS, _timestamp

FIELDS = 'version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status'.split()
MAX_LINES = 50000


def _integer(s, lo, hi):
    if not re.fullmatch(r'[0-9]{1,19}', s):
        raise ValueError('Invalid numeric Flow Logs field')
    n = int(s)
    if not lo <= n <= hi:
        raise ValueError('Out-of-range Flow Logs field')
    return n


def parse_flow_logs(raw):
    """Default v2 whitespace-delimited text only; optional exact header.

    Fail closed on malformed or unsupported records, including custom formats.
    NODATA/SKIPDATA rows have no usable tuple and remain coverage warnings.
    """
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError('Invalid Flow Logs size or type')
    try:
        lines = raw.decode('utf-8-sig').splitlines()
    except UnicodeError as exc:
        raise ValueError('Flow Logs must be UTF-8 text') from exc
    if len(lines) > MAX_LINES:
        raise ValueError('Too many Flow Logs lines')
    seen = set()
    rows = []
    duplicates = 0
    for lineno, line in enumerate(lines, 1):
        parts = line.split()
        if not parts:
            continue
        if not rows and not seen and parts == FIELDS:
            continue
        try:
            if len(parts) != len(FIELDS) or parts[0] != '2':
                raise ValueError('Expected default 14-field version 2 format')
            _, account, eni, src, dst, sp, dp, proto, packets, octets, start, end, action, status = parts
            if not re.fullmatch(r'eni-[0-9a-f]{8,32}', eni):
                raise ValueError('Invalid interface ID')
            if not re.fullmatch(r'[0-9]{12}', account) and account != '-':
                raise ValueError('Invalid account ID')
            start, end = (_integer(x, 0, 253402300799) for x in (start, end))
            if end < start:
                raise ValueError('Reversed time range')
            if status not in ('OK', 'NODATA', 'SKIPDATA'):
                raise ValueError('Unknown log status')
            row = dict(account=account, eni=eni, start=start, end=end, status=status)
            if status == 'OK':
                if action not in ('ACCEPT', 'REJECT'):
                    raise ValueError('Unknown action')
                # Non-TCP or IPv6 rows are parsed but excluded from correlation.
                src, dst = str(ip_address(src)), str(ip_address(dst))
                proto = _integer(proto, 0, 255)
                sp = None if sp == '-' and proto not in (6, 17) else _integer(sp, 0, 65535)
                dp = None if dp == '-' and proto not in (6, 17) else _integer(dp, 0, 65535)
                packets, octets = (_integer(x, 1, 2**63-1) for x in (packets, octets))
                row.update(src=src, dst=dst, sp=sp, dp=dp, proto=proto, packets=packets, octets=octets, action=action)
            else:
                if any(x != '-' for x in (src,dst,sp,dp,proto,packets,octets,action)):
                    raise ValueError('Unsupported non-OK record fields')
            key = tuple(sorted(row.items()))
            if key in seen:
                duplicates += 1
                continue
            seen.add(key)
            rows.append(row)
        except ValueError as exc:
            raise ValueError(f'Flow Logs line {lineno}: {exc}') from exc
    return rows, duplicates


def correlate_flow_logs(inventory_raw, logs_raw, source_ip, destination_ip, source_port, destination_port):
    """Exact tuple + snapshot ENI + fully contained +/-300s window.

    Counts are distinct log records, not unique packets or connections. Evidence
    is uploaded and unauthenticated. No causal attribution or verdict overwrite.
    """
    if not isinstance(inventory_raw, bytes) or len(inventory_raw) > MAX_BYTES:
        raise ValueError('Invalid inventory size or type')
    for ip in (source_ip, destination_ip):
        if not isinstance(ip, str) or str(IPv4Address(ip)) != ip:
            raise ValueError('Expected canonical IPv4 address')
    if source_ip == destination_ip or any(type(p) is not int or not 1 <= p <= 65535 for p in (source_port, destination_port)):
        raise ValueError('Distinct endpoints and integer TCP ports required')
    rows, duplicates = parse_flow_logs(logs_raw)
    session = analyze_observed_session(inventory_raw, source_ip, destination_ip, source_port, destination_port)
    endpoints = session['evidence']['forwarding']['endpoints']
    src, dst = endpoints['source'], endpoints['destination']
    scope = (all(e['status'] == 'ENDPOINT_CANDIDATE' for e in (src,dst)) and
             src['subnet_id'] != dst['subnet_id'] and
             session['findings'][0]['status'] == 'PASS')
    center = _timestamp(session['collected_at']).timestamp()
    lower, upper = center-MAX_SKEW_SECONDS, center+MAX_SKEW_SECONDS
    enis = {e['eni_id'] for e in (src,dst)} if scope else set()
    request = (source_ip,destination_ip,source_port,destination_port)
    reply = (destination_ip,source_ip,destination_port,source_port)
    counts = Counter()
    ignored = Counter()
    warnings = Counter()
    accounts = set()
    for row in rows:
        if row['eni'] not in enis:
            ignored['OUTSIDE_ENDPOINT_ENI'] += 1
            continue
        if row['end'] < lower or row['start'] > upper:
            ignored['OUTSIDE_TIME_WINDOW'] += 1
            continue
        if row['status'] != 'OK':
            warnings[row['status']] += 1
            continue
        if row['start'] < lower or row['end'] > upper:
            ignored['PARTIAL_TIME_WINDOW'] += 1
            continue
        tup = tuple(row[k] for k in ('src','dst','sp','dp'))
        if row['proto'] != 6 or tup not in (request,reply):
            ignored['TUPLE_OR_PROTOCOL_MISMATCH'] += 1
            continue
        accounts.add(row['account'])
        counts[('request' if tup == request else 'response',row['eni'],row['action'])] += 1
    reasons = []
    if not scope:
        reasons.append('ENDPOINT_SCOPE_UNCONFIRMED')
    if '-' in accounts or len(accounts) > 1:
        reasons.append('LOG_ACCOUNT_UNCONFIRMED_OR_MIXED')
    accepted = sum(n for (_,_,a),n in counts.items() if a=='ACCEPT')
    rejected = sum(n for (_,_,a),n in counts.items() if a=='REJECT')
    observation = ('NOT_COMPARABLE' if reasons else 'MIXED_RECORDS' if accepted and rejected else
                   'ACCEPT_RECORDS' if accepted else 'REJECT_RECORDS' if rejected else 'NO_MATCHING_RECORDS')
    return dict(analysis_type='AWS_FLOW_LOG_OBSERVATION_CORRELATION', input_identity=session['input_identity'],
                region=session['region'], collected_at=session['collected_at'], scenario=session['scenario'],
                window=dict(start_epoch=lower,end_epoch=upper,heuristic_seconds=MAX_SKEW_SECONDS),
                cloudpath_predicted=session['predicted_connectivity'], cloudpath_conditional=session['conditional_connectivity'],
                observation=observation, reasons=reasons, matched_records=accepted+rejected,
                per_interface=[dict(direction=d,eni_id=e,action=a,record_count=n) for (d,e,a),n in sorted(counts.items())],
                coverage_warnings=dict(warnings), ignored_records=dict(ignored), duplicate_records=duplicates,
                live_observation=False, evidence_kind='UPLOADED_OBSERVED_LOG_RECORDS',
                limitations=['Uploaded records are not authenticated; inventory account and region linkage are unverified.',
                             'Time window is a heuristic; configuration equivalence is not established.',
                             'ACCEPT/REJECT are interface-level aggregated records, not an application or session verdict.',
                             'No matching record, NODATA or SKIPDATA is not proof of blocking or absence of traffic.',
                             'Counts are distinct records, not unique packets; reverse tuple is not proof of a tracked reply.',
                             'No causal attribution to SG/NACL, no AWS API calls, no prediction overwrite.'])
