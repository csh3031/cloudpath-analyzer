"""Integrate static, uploaded AWS evidence without asserting live reachability."""
from backend.aws.policy_evidence import evaluate_observed_policy


_TRACKED = 'TCP_REPLY_CONNECTION_TRACKED'
_REQUEST = 'REQUEST_DELIVERY_PREDICTED'
_SNAPSHOT = 'UPLOADED_SNAPSHOT_ACCURATE_COMPLETE_AND_STABLE'


def analyze_observed_session(raw: bytes, source_ip: str, destination_ip: str,
                             source_port: int, destination_port: int, *, prefix_list_raw=None) -> dict:
    """Cross-subnet IPv4 TCP only. Reply is hypothetical and tracking unverified.

    Stop the predicted path on the first blocked or uncertain check. Preserve
    independent evidence without treating it as a traversed hop. No live calls.
    """
    policy = evaluate_observed_policy(raw, source_ip, destination_ip,
                                      source_port, destination_port, prefix_list_raw=prefix_list_raw)
    forward = policy['forwarding']
    findings = []

    def direction(name, start, end, enabled, dependency=None):
        f = forward[name]
        checks = {c['stage']: c for c in policy[name]['checks']}
        reply = name == 'response'
        assumptions = [_SNAPSHOT] + ([_REQUEST, _TRACKED] if reply else [])
        # Scope validation is a preflight check, not an assertion of packet delivery.
        source_ok = start['status'] == 'ENDPOINT_CANDIDATE'
        dest_ok = end['status'] == 'ENDPOINT_CANDIDATE'
        preflight_ok = (source_ok and dest_ok and
                        checks['SOURCE_SG_EGRESS']['status'] != 'NOT_EVALUATED')
        stages = [('ENDPOINT_SCOPE', 'PASS' if preflight_ok else 'UNKNOWN',
                   'ENDPOINT_SCOPE_SUPPORTED' if preflight_ok else f['reason'],
                   {'source': start, 'destination': end})]
        for stage in ('SOURCE_SG_EGRESS', 'SOURCE_NACL_EGRESS', 'ROUTE_LOOKUP',
                      'DESTINATION_NACL_INGRESS', 'DESTINATION_SG_INGRESS'):
            if stage == 'ROUTE_LOOKUP':
                status = {'FORWARDING_CANDIDATE':'PASS', 'BLOCKED':'BLOCKED',
                          'UNKNOWN':'UNKNOWN'}[f['status']]
                if not preflight_ok:
                    status = 'NOT_EVALUATED'
                stages.append((stage, status, f['reason'], f))
            else:
                c = checks[stage]
                status = 'PASS' if c['status'] == 'ALLOW_CANDIDATE' else c['status']
                stages.append((stage, status, c['reason'], c))
        trace = []
        first_blocker = None
        stopped_at = None
        active = enabled
        stop_status = None
        for stage, status, reason, evidence in stages:
            fid = name + ':' + stage
            mode = ('CONDITIONAL_CHECK' if reply else 'PREDICTED_PATH') if active else 'INDEPENDENT_CHECK'
            # Conditional SG checks count toward only the hypothetical tracked branch.
            passes = status in ('PASS','NOT_APPLICABLE') or (reply and status == 'CONDITIONAL')
            deps = ([dependency] if dependency else []) + ([stopped_at] if stopped_at else [])
            item = dict(id=fid, direction=name, stage=stage, status=status,
                        reason=reason, evidence=evidence, evaluation_mode=mode,
                        assumptions=list(assumptions) if active else [_SNAPSHOT],
                        dependencies=deps)
            if reply and status == 'CONDITIONAL' and _TRACKED not in item['assumptions']:
                item['assumptions'].append(_TRACKED)
            findings.append(item)
            if not active:
                continue
            trace.append(fid)
            if not passes:
                stopped_at = fid
                stop_status = status
                if status == 'BLOCKED':
                    first_blocker = fid
                active = False
        result = ('NOT_EVALUATED' if not enabled else 'BLOCKED' if stop_status == 'BLOCKED'
                  else 'UNKNOWN' if stopped_at else 'REACHABLE')
        return dict(status=result, evaluation_mode='CONDITIONAL_CHECK' if reply else 'PREDICTED_PATH',
                    trace=trace, first_blocker=first_blocker, stopped_at=stopped_at,
                    path_complete=result == 'REACHABLE', conditional=reply,
                    assumptions=assumptions, dependency=dependency)

    src, dst = (forward['endpoints'][key] for key in ('source','destination'))
    request = direction('request', src, dst, True)
    request_ok = request['status'] == 'REACHABLE'
    response = direction('response', dst, src, request_ok,
                         request['trace'][-1])
    # A reply that needs connection tracking remains conditional, not a live or
    # unconditional REACHABLE/BLOCKED verdict. Independent reply failures after
    # an unresolved request do not become first blockers.
    predicted = 'BLOCKED' if request['status'] == 'BLOCKED' else 'UNKNOWN'
    conditional = response['status'] if request_ok else 'NOT_EVALUATED'
    return dict(analysis_type='STATIC_AWS_INVENTORY_PREDICTION',
                input_identity=policy['input_identity'], collected_at=policy['collected_at'],
                vpc_id=forward['vpc_id'], region=forward['region'],
                scenario=dict(source_ip=source_ip, destination_ip=destination_ip,
                              protocol='tcp', source_port=source_port,
                              destination_port=destination_port, request_type='TCP_SESSION'),
                predicted_connectivity=predicted, conditional_connectivity=conditional,
                first_blocker=request['first_blocker'],
                conditional_first_blocker=response['first_blocker'],
                request=request, response=response, findings=findings,
                evidence=policy, live_observation=False,
                assumptions=[_SNAPSHOT, _TRACKED],
                dependencies={'response': response['dependency']},
                coverage=dict(supported=['single VPC primary IPv4', 'distinct ENIs; conditional same-subnet direct path',
                                         'single ENI EC2', 'explicit local route',
                                         'TCP IPv4 CIDR SG and NACL rules; direct private ENI SG references'],
                              unverified=['snapshot authenticity, completeness, freshness and atomicity',
                                          'attachment status', 'actual connection tracking',
                                          'host firewall, TCP listener and application',
                                          'live packet delivery', 'host on-link behavior and complex routes',
                                          'non-direct SG references, missing/unsupported prefix-list evidence and prefix-list routes']),
                limitations=forward['limitations'] + policy['limitations'] + [
                    'REACHABLE on a direction means only a static candidate under its assumptions.',
                    'Response is conditional on request delivery and tracked TCP reply.',
                    'Only a request-path blocker before any unknown is a first_blocker; reply blockers are conditional.',
                    'Legacy IaC analysis remains restricted for AWS Inventory.'])
