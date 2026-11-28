"""Correlate offline S3 network and policy candidates; never execute requests.
A binding is a user assertion about one hypothetical request, not authentication.
"""
import hashlib
import json
from backend.aws.gateway_endpoint_session_evidence import analyze_gateway_endpoint_session
from backend.aws.interface_endpoint_session_evidence import analyze_interface_endpoint_session
from backend.aws.s3_authorization_evidence import analyze_s3_authorization
from backend.aws.peering_evidence import _timestamp
from backend.iac.plan_adapter import _read


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def network_result_identity(result):
    """Stable identity of a locally recomputed result, not a signature."""
    return 'sha256-s3-network-result-v1:' + hashlib.sha256(_canonical(result).encode()).hexdigest()


def analyze_s3_access(inventory_raw, endpoint_raw, observation_raw, authorization_raw, binding_raw,
                      endpoint_id, endpoint_type, source_kind, source_port, **source_options):
    if endpoint_type not in ('Gateway', 'Interface'):
        raise ValueError('Expected Gateway or Interface')
    engine = analyze_gateway_endpoint_session if endpoint_type == 'Gateway' else analyze_interface_endpoint_session
    network = engine(inventory_raw, endpoint_raw, observation_raw, endpoint_id, source_kind, source_port, **source_options)
    auth = analyze_s3_authorization(authorization_raw)
    cfg, scenario = network['endpoint_configuration'], auth['scenario']
    network_id = network_result_identity(network)
    request, response = network['request_status'], network['response_status']
    network_status = ('BLOCKED' if request == 'BLOCKED' else
                      'CONDITIONAL_RESPONSE_BLOCKED' if request == 'CONDITIONAL_CANDIDATE' and response == 'BLOCKED' else
                      'CONDITIONAL_CANDIDATE' if request == response == 'CONDITIONAL_CANDIDATE' else 'UNKNOWN')
    result = dict(analysis_type='STATIC_AWS_S3_ACCESS_CONSTRAINTS', network=network, authorization=auth,
                  network_result_identity=network_id, network_status=network_status,
                  authorization_status=auth['authorization_status'], correlated_authorization_status='UNKNOWN',
                  binding_status='UNKNOWN', binding_reason=None, authorization_evaluation_mode='INDEPENDENT_CHECK',
                  access_status='UNKNOWN', reason=None, first_stop=None, independent_denial_layers=[],
                  authentication_status='NOT_EVALUATED', tls_status='NOT_EVALUATED', api_status='UNKNOWN', live_observation=False,
                  limitations=['Offline assertions about a hypothetical source principal and request; not proof of role attachment, credentials, policy completeness or actual context.',
                               'S3 same-account GetObject/ListBucket, submitted endpoint-specific or regional DNS profile, no alternate route composition.',
                               'Endpoint policy content must match the submitted endpoint snapshot; identity/bucket policies are asserted only.',
                               'No actual DNS, TLS, service authentication, object existence, API success, AWS calls or packet transmission.'])

    def correlate():
        if binding_raw is None:
            return 'S3_REQUEST_BINDING_MISSING'
        if not isinstance(binding_raw, bytes) or len(binding_raw) > 16384:
            raise ValueError('Binding must be bytes, at most 16 KiB')
        binding = _read(binding_raw)
        if set(binding) != {'schema','network_result_identity','authorization_input_identity','collected_at','same_hypothetical_request'} or binding['schema'] != 'cloudpath-s3-access-binding-v1':
            raise ValueError('Invalid S3 request binding wrapper')
        if binding['same_hypothetical_request'] is not True:
            return 'S3_REQUEST_BINDING_UNCONFIRMED'
        if binding['network_result_identity'] != network_id or binding['authorization_input_identity'] != auth['input_identity']:
            return 'S3_REQUEST_BINDING_IDENTITY_MISMATCH'
        if cfg['status'] != 'VPC_ENDPOINT_CONFIGURATION_CANDIDATE' or cfg['endpoint_type'] != endpoint_type or cfg['service_name'] != 'com.amazonaws.'+cfg['region']+'.s3':
            return 'S3_ENDPOINT_SCOPE_UNCONFIRMED'
        if (scenario['endpoint_id'], scenario['endpoint_type'], scenario['vpc_id']) != (endpoint_id, endpoint_type, cfg['vpc_id']):
            return 'S3_REQUEST_ENDPOINT_CONTEXT_MISMATCH'
        if scenario['secure_transport'] is not True:
            return 'S3_HTTPS_CONTEXT_UNCONFIRMED'
        dns = network.get('dns_evidence') or {}
        if not network.get('destination_endpoint') or dns.get('status') not in ('GATEWAY_DNS_PREFIX_CORRELATION_CANDIDATE','ENDPOINT_DNS_ENI_CORRELATION_CANDIDATE'):
            return 'S3_NETWORK_DESTINATION_UNCONFIRMED'
        if endpoint_type == 'Gateway' and network.get('path_kind') != 'GATEWAY_ENDPOINT':
            return 'S3_GATEWAY_ROUTE_NOT_CONFIRMED'
        if endpoint_type == 'Interface' and network.get('path_kind') not in ('SAME_SUBNET_DIRECT','CROSS_SUBNET_DIRECT'):
            return 'S3_INTERFACE_ROUTE_NOT_CONFIRMED'
        # A failed/unknown Interface route does not establish the endpoint context.
        if endpoint_type == 'Interface' and not any(s['stage'] == 'LOCAL_ROUTE' and s['status'] == 'ALLOW_CANDIDATE' for s in network['request']):
            return 'S3_INTERFACE_ROUTE_NOT_CONFIRMED'
        collected = _timestamp(binding['collected_at'])
        resolved = _timestamp(dns['resolved_at'])
        times = [_timestamp(_read(raw)['collected_at']) for raw in (inventory_raw, endpoint_raw, observation_raw, *[source_options.get(k) for k in ('ecs_raw','eks_raw','policy_raw','prefix_list_raw')]) if raw is not None]
        if collected < max(times+[resolved]) or (collected-min(times+[resolved])).total_seconds()>300 or (collected-resolved).total_seconds()>=dns['ttl_seconds']:
            return 'S3_REQUEST_BINDING_TIME_SCOPE_UNCONFIRMED'
        # Endpoint Policy is single document. No default or missing-policy inference.
        rows = [r for r in _read(endpoint_raw)['VpcEndpoints'] if r['VpcEndpointId'] == endpoint_id]
        policy = rows[0].get('PolicyDocument') if len(rows)==1 else None
        if isinstance(policy,str):
            try: policy = _read(policy.encode())
            except ValueError: return 'S3_ENDPOINT_POLICY_SNAPSHOT_UNCONFIRMED'
        if not isinstance(policy,dict) or not policy:
            return 'S3_ENDPOINT_POLICY_SNAPSHOT_UNCONFIRMED'
        docs = _read(authorization_raw)['policies']['endpoint']
        if len(docs)!=1 or _canonical(docs[0])!=_canonical(policy):
            return 'S3_ENDPOINT_POLICY_SNAPSHOT_MISMATCH'
        return 'MATCHED_ASSERTED_S3_REQUEST_CONTEXT'

    reason = correlate()
    result['binding_reason'] = reason
    bound = reason == 'MATCHED_ASSERTED_S3_REQUEST_CONTEXT'
    if bound:
        result['binding_status'] = 'CORRELATED_CANDIDATE'
        result['correlated_authorization_status'] = auth['authorization_status']
    denial = bound and auth['authorization_status'] in ('EXPLICIT_DENY','IMPLICIT_DENY_CANDIDATE')
    if network_status in ('BLOCKED','CONDITIONAL_RESPONSE_BLOCKED'):
        result.update(access_status='NETWORK_BLOCKED' if network_status=='BLOCKED' else 'CONDITIONAL_RESPONSE_BLOCKED',
                      reason='NETWORK_REQUEST_BLOCKED' if network_status=='BLOCKED' else 'NETWORK_CONDITIONAL_RESPONSE_BLOCKED',
                      first_stop=network['first_request_stop'] if network_status=='BLOCKED' else network['conditional_first_response_stop'])
        if denial: result['independent_denial_layers'] = auth.get('explicit_deny_layers',[]) or ['authorization_implicit_candidate']
    elif network_status!='CONDITIONAL_CANDIDATE':
        result.update(reason='NETWORK_PATH_UNCONFIRMED',first_stop=network['first_request_stop'] or network['conditional_first_response_stop'])
    elif not bound:
        result.update(reason=reason,first_stop='REQUEST_BINDING')
    else:
        result['authorization_evaluation_mode']='CONDITIONAL_CHECK'
        status=auth['authorization_status']
        if status=='ALLOW_CANDIDATE': result.update(access_status='CONDITIONAL_ACCESS_CANDIDATE',reason='NETWORK_AND_POLICY_CANDIDATES')
        elif denial: result.update(access_status='AUTHORIZATION_DENY' if status=='EXPLICIT_DENY' else 'AUTHORIZATION_DENY_CANDIDATE',reason=auth['reason'],first_stop='AUTHORIZATION')
        else: result.update(reason='AUTHORIZATION_UNCONFIRMED',first_stop='AUTHORIZATION')
    return result
