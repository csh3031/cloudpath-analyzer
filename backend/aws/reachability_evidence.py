"""Compare uploaded AWS Reachability Analyzer results with a fresh local static prediction.
No API calls, live packets, or changes to either model. A comparison is not authentication.
"""
from datetime import datetime
from ipaddress import IPv4Address
import re

from backend.iac.plan_adapter import _read
from backend.aws.session_evidence import analyze_observed_session

MAX_BYTES = 5 * 1024 * 1024
MAX_SKEW_SECONDS = 300


def _single(raw, key):
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError('Evidence exceeds size limit or is not bytes')
    try:
        doc = _read(raw)
    except ValueError as exc:
        raise ValueError('Invalid evidence JSON') from exc
    rows = doc.get(key)
    if (not isinstance(rows, list) or len(rows) != 1 or
            not isinstance(rows[0], dict) or doc.get('NextToken')):
        raise ValueError('Expected one complete record in ' + key)
    return rows[0]


def _id(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(prefix + r'-[0-9a-f]{8,32}', value):
        raise ValueError('Invalid ' + prefix + ' ID')
    return value


def _timestamp(value):
    if not isinstance(value, str):
        raise ValueError('Missing timestamp')
    try:
        t = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError('Invalid timestamp') from exc
    if t.tzinfo is None:
        raise ValueError('Timestamp must include timezone')
    return t


def _arn_scope(value, kind, resource_id):
    if not isinstance(value, str):
        return None
    m = re.fullmatch(r'arn:aws(?:-us-gov|-cn)?:ec2:([a-z0-9-]+):([0-9]{12}):' + kind + '/' + resource_id, value)
    return m.groups() if m else None


def _exact_address(value, ip):
    return isinstance(value, str) and value in (ip, ip + '/32')


def _exact_port(value, port):
    return (isinstance(value, dict) and set(value) == {'FromPort', 'ToPort'}
            and all(type(v) is int and v == port for v in value.values()))


def compare_reachability(inventory_raw, paths_raw, analyses_raw, source_ip, destination_ip,
                         source_port, destination_port):
    """One path and one analysis from DescribeNetworkInsights* CLI output.

    Only exact TCP tuple and endpoint matches qualify for tentative comparison.
    A broad filter is not evidence about an individual TCP tuple. Snapshot and
    analysis timestamps are checked but shared configuration/account is not proven.
    """
    if not isinstance(inventory_raw, bytes) or len(inventory_raw) > MAX_BYTES:
        raise ValueError('Invalid inventory size')
    for ip in (source_ip, destination_ip):
        if not isinstance(ip, str) or str(IPv4Address(ip)) != ip:
            raise ValueError('Expected canonical IPv4 address')
    if source_ip == destination_ip or any(type(p) is not int or not 1 <= p <= 65535 for p in (source_port, destination_port)):
        raise ValueError('Distinct endpoints and integer TCP ports required')
    p = _single(paths_raw, 'NetworkInsightsPaths')
    a = _single(analyses_raw, 'NetworkInsightsAnalyses')
    pid = _id(p.get('NetworkInsightsPathId'), 'nip')
    aid = _id(a.get('NetworkInsightsAnalysisId'), 'nia')
    if a.get('NetworkInsightsPathId') != pid:
        raise ValueError('Analysis and path IDs differ')
    started = _timestamp(a.get('StartDate'))
    status = a.get('Status')
    if status not in ('running', 'failed', 'succeeded'):
        raise ValueError('Invalid analysis status')
    found = a.get('NetworkPathFound')
    if status == 'succeeded' and type(found) is not bool:
        raise ValueError('Successful analysis requires boolean NetworkPathFound')
    if status != 'succeeded':
        found = None
    session = analyze_observed_session(inventory_raw, source_ip, destination_ip, source_port, destination_port)
    endpoints = session['evidence']['forwarding']['endpoints']
    reasons = []
    if any(endpoints[k]['status'] != 'ENDPOINT_CANDIDATE' for k in ('source','destination')):
        reasons.append('ENDPOINT_SCOPE_UNCONFIRMED')
    for k, field in [('source','Source'), ('destination','Destination')]:
        ep = endpoints[k]
        if not isinstance(p.get(field), str) or p[field] not in (ep.get('instance_id'), ep.get('eni_id')):
            reasons.append(field.upper() + '_RESOURCE_MISMATCH')
    if p.get('Protocol') != 'tcp':
        reasons.append('PROTOCOL_MISMATCH')
    f = p.get('FilterAtSource') or {}
    if not isinstance(f, dict):
        raise ValueError('Invalid source filter')
    if set(f) - {'SourceAddress','DestinationAddress','SourcePortRange','DestinationPortRange'} or p.get('FilterAtDestination'):
        reasons.append('UNSUPPORTED_PATH_FILTER')
    for field, filter_field, ip in [('SourceIp','SourceAddress',source_ip),('DestinationIp','DestinationAddress',destination_ip)]:
        values = [v for v in (p.get(field),f.get(filter_field)) if v is not None]
        if not values or not all(_exact_address(v, ip) for v in values):
            reasons.append(field.upper() + '_NOT_EXACT')
    if not _exact_port(f.get('SourcePortRange'), source_port):
        reasons.append('SOURCE_PORT_NOT_EXACT')
    dp = p.get('DestinationPort')
    df = f.get('DestinationPortRange')
    if ((dp is None and df is None) or (dp is not None and (type(dp) is not int or dp != destination_port))
            or (df is not None and not _exact_port(df, destination_port))):
        reasons.append('DESTINATION_PORT_NOT_EXACT')
    if any(a.get(k) for k in ('FilterInArns','FilterOutArns','AdditionalAccounts','WarningMessage','SuggestedAccounts')):
        reasons.append('ANALYSIS_SCOPE_OR_WARNING_UNSUPPORTED')
    ps = _arn_scope(p.get('NetworkInsightsPathArn'), 'network-insights-path', pid)
    ans = _arn_scope(a.get('NetworkInsightsAnalysisArn'), 'network-insights-analysis', aid)
    if not ps or ps != ans or ps[0] != session['region']:
        reasons.append('ARN_SCOPE_UNCONFIRMED_OR_MISMATCH')
    # Inventory v1 does not carry a verified AWS account ID.
    skew = abs((started - _timestamp(session['collected_at'])).total_seconds())
    if skew > MAX_SKEW_SECONDS:
        reasons.append('COLLECTION_TIME_GAP')
    if status != 'succeeded':
        reasons.append('ANALYSIS_NOT_SUCCEEDED')
    candidate = session['predicted_connectivity']
    if candidate != 'BLOCKED':
        candidate = session['conditional_connectivity']
    if candidate not in ('BLOCKED','REACHABLE'):
        reasons.append('CLOUDPATH_SCOPE_UNRESOLVED')
    comparison = 'NOT_COMPARABLE' if reasons else ('CONSISTENT_CANDIDATE' if found == (candidate == 'REACHABLE') else 'DISCREPANCY_CANDIDATE')
    return dict(analysis_type='AWS_REACHABILITY_STATIC_COMPARISON', input_identity=session['input_identity'],
                region=session['region'], collected_at=session['collected_at'], analysis_started_at=started.isoformat(),
                time_gap_seconds=skew, path_id=pid, analysis_id=aid, analysis_status=status,
                scenario=session['scenario'], cloudpath_predicted=session['predicted_connectivity'],
                cloudpath_conditional=session['conditional_connectivity'], aws_network_path_found=found,
                comparison=comparison, reasons=reasons, live_observation=False,
                limitations=['Both results are static, not packet observations.',
                             'Inventory account, authenticity and identical configuration are unverified.',
                             'Time proximity is a heuristic, not configuration equivalence.',
                             'CloudPath reply tracking is conditional; AWS path scope may differ.',
                             'No AWS API calls; no changes to the original prediction.'])
