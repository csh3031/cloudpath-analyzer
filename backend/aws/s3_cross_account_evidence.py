"""Bounded, asserted cross-account S3 policy path, not effective authorization."""
import json
from .s3_authorization_evidence import analyze_s3_authorization, _pairs, _layer, PRINCIPAL, LAYERS


def analyze_s3_cross_account(raw):
    # Reuse the original validator, including all size, schema and request constraints.
    original = analyze_s3_authorization(raw)
    evidence = json.loads(raw, object_pairs_hook=_pairs)
    request = evidence['request']
    account = PRINCIPAL.fullmatch(request['principal_arn'])[1]
    owner = request['bucket_account']
    result = {'analysis_type': 'STATIC_S3_CROSS_ACCOUNT_POLICY_PATH',
              'input_identity': original['input_identity'], 'scenario': request,
              'principal_account': account, 'resource_account': owner,
              'layers': {}, 'explicit_deny_layers': [], 'unconfirmed_assertions': [],
              'policy_path_status': 'UNKNOWN', 'authorization_status': 'UNKNOWN',
              'api_status': 'UNKNOWN', 'live_observation': False,
              'limitations': ['Hypothetical submitted documents only; no authenticated attachments, owner or runtime principal.',
                              'Direct cross-account IAM user/role requests via asserted S3 endpoint only; no AssumeRole, account delegation, STS session principal or ACL grants.',
                              'SCP/RCP across accounts, public access restrictions, boundary/session, KMS and network applicability require separate evidence.']}
    if account == owner:
        return result | {'reason': 'SAME_ACCOUNT_USE_EXISTING_ANALYZER'}
    policies, complete, assertions = (evidence[k] for k in ('policies', 'complete', 'assertions'))
    context = {'aws:sourcevpce': request['endpoint_id'], 'aws:sourcevpc': request['vpc_id'],
               'aws:principalarn': request['principal_arn'], 'aws:principalaccount': account,
               'aws:securetransport': None if request['secure_transport'] is None else str(request['secure_transport']).lower()}
    layers = {k: _layer(policies[k], complete[k] and (k != 'endpoint' or bool(policies[k])), request, context, k) for k in LAYERS}
    result['layers'] = layers
    result['explicit_deny_layers'] = [k for k in LAYERS if layers[k]['status'] == 'EXPLICIT_DENY']
    # Only assess the policy-only path; ACL/object-owner exceptions cannot be decided here.
    # Scope conditions are assertions, not authenticated evidence.
    required = ['bucket_owner_enforced', 'no_additional_service_restrictions']
    if request['action'] == 's3:GetObject':
        required.append('object_owned_by_bucket_account')
    result['unconfirmed_assertions'] = [k for k in required if not assertions[k]]
    if result['explicit_deny_layers']:
        status, reason = 'EXPLICIT_DENY_CANDIDATE', 'MATCHING_SUBMITTED_DENY'
    elif result['unconfirmed_assertions']:
        status, reason = 'UNKNOWN', 'RESOURCE_SCOPE_UNCONFIRMED'
    elif any(layers[k]['status'] == 'UNKNOWN' for k in LAYERS):
        status, reason = 'UNKNOWN', 'POLICY_EVIDENCE_INCOMPLETE_OR_UNSUPPORTED'
    elif any(layers[k]['status'] == 'NO_MATCHING_ALLOW' for k in LAYERS):
        status, reason = 'POLICY_PATH_BLOCKED_CANDIDATE', 'CROSS_ACCOUNT_REQUIRES_ALL_THREE_ALLOWS'
    elif all(layers[k]['status'] == 'ALLOW_CANDIDATE' for k in LAYERS):
        status, reason = 'POLICY_PATH_ALLOW_CANDIDATE', 'CROSS_ACCOUNT_POLICY_ALLOWS_MATCH'
    else:
        status, reason = 'UNKNOWN', 'POLICY_EVIDENCE_INCOMPLETE_OR_UNSUPPORTED'
    return result | {'policy_path_status': status, 'reason': reason}
