"""Offline, asserted identity-grant constraints, not effective AWS authorization."""
import hashlib
import json
import re
from .s3_authorization_evidence import _layer, _pairs, PRINCIPAL
from .s3_identity_evidence import analyze_s3_identity, POLICY, VERSION

MAX_LIMIT_BYTES = 2 * 1024 * 1024
SCHEMA = 'cloudpath-iam-permission-limits-v1'


def _fields(obj, names):
    if not isinstance(obj, dict) or set(obj) != set(names.split()):
        raise ValueError('Invalid permission limit fields')


def _load(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_LIMIT_BYTES:
        raise ValueError('Limit evidence must be bytes, at most 2 MiB')
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON constant')))
    except (UnicodeError, RecursionError) as exc:
        raise ValueError('Invalid limit JSON') from exc


def _managed(row, account):
    _fields(row, 'arn policy_id_before policy_id_after default_version_before default_version_after document_version is_default_version document')
    arn = POLICY.fullmatch(row['arn']) if isinstance(row['arn'], str) else None
    if not arn or any(not isinstance(row[k], str) or not re.fullmatch(r'ANPA[A-Z0-9]{8,64}', row[k]) for k in ('policy_id_before','policy_id_after')) or any(not isinstance(row[k], str) or not VERSION.fullmatch(row[k]) for k in ('default_version_before','default_version_after','document_version')) or type(row['is_default_version']) is not bool or not isinstance(row['document'], dict):
        raise ValueError('Invalid managed limit policy')
    return arn[1] in ('aws', account) and row['policy_id_before'] == row['policy_id_after'] and row['default_version_before'] == row['default_version_after'] == row['document_version'] and row['is_default_version']


def _state(row, fields):
    _fields(row, 'state complete ' + fields)
    if row['state'] not in ('ABSENT','PRESENT','UNKNOWN') or type(row['complete']) is not bool:
        raise ValueError('Invalid limit state')


def _unknown(reason):
    return {'status':'UNKNOWN','reason':reason}


def _eval(docs, request, context):
    r = _layer(docs, True, request, context, 'identity')
    return {'status':r['status'], 'reason':'ASSERTED_POLICY_EVALUATED', 'evaluation':r}


def analyze_iam_permission_limits(authorization_raw, identity_raw=None, limits_raw=None, *, cross_account=False):
    """Assess direct identity grant path for the same hypothetical S3 request.

    A blocked identity grant path is not a final denial: resource grants may differ.
    The sidecar is asserted, not authenticated, and no real session is identified.
    """
    identity = analyze_s3_identity(authorization_raw, identity_raw, cross_account=cross_account)
    auth = identity['authorization']
    result = {'analysis_type':'STATIC_IAM_IDENTITY_GRANT_LIMITS', 'identity':identity,
              'limits_input_identity':None, 'boundary':_unknown('NOT_EVALUATED'),
              'session':_unknown('NOT_EVALUATED'), 'identity_grant_status':'UNKNOWN',
              'reason':'LIMIT_EVIDENCE_MISSING', 'authorization_status':'UNKNOWN',
              'runtime_identity_status':'UNKNOWN','api_status':'UNKNOWN','live_observation':False,
              'limitations':['Direct identity grant only; bucket grants and resource-policy exceptions not composed.', 'Asserted boundary and hypothetical session documents only; no STS binding or actual policy retrieval.', 'Organizations, cross-account, KMS/ACL and network authorization integration pending.']}
    if limits_raw is None:
        return result
    e = _load(limits_raw)
    _fields(e,'schema authorization_input_identity identity_input_identity boundary session')
    if e['schema'] != SCHEMA:
        raise ValueError('Invalid limit schema')
    result['limits_input_identity'] = 'sha256-iam-permission-limits-v1:' + hashlib.sha256(limits_raw).hexdigest()
    b,s = e['boundary'],e['session']
    _state(b,'policy')
    _state(s,'session_kind inline_document managed_policies')
    if b['state'] == 'PRESENT' and not isinstance(b['policy'],dict) or b['state'] != 'PRESENT' and b['policy'] is not None:
        raise ValueError('Boundary state/document conflict')
    if s['session_kind'] not in ('ASSUMED_ROLE','IAM_USER','UNKNOWN') or not isinstance(s['managed_policies'],list) or len(s['managed_policies']) > 10 or s['inline_document'] is not None and not isinstance(s['inline_document'],dict):
        raise ValueError('Invalid session policy set')
    if s['state'] != 'PRESENT' and (s['inline_document'] is not None or s['managed_policies']):
        raise ValueError('Session state/document conflict')
    if s['state'] == 'PRESENT' and s['inline_document'] is None and not s['managed_policies']:
        raise ValueError('Present session policy requires documents')
    if e['authorization_input_identity'] != auth['input_identity'] or e['identity_input_identity'] != identity['identity_input_identity']:
        return result | {'reason':'LIMIT_INPUT_IDENTITY_MISMATCH'}
    if identity['identity_status'] != 'CORRELATED_CANDIDATE':
        return result | {'reason':'IAM_ATTACHMENT_UNCORRELATED'}
    a = json.loads(authorization_raw)
    p = json.loads(identity_raw)['principal_before']
    request = auth['scenario']
    account,kind = PRINCIPAL.fullmatch(request['principal_arn']).groups()
    context = {'aws:sourcevpce':request['endpoint_id'], 'aws:sourcevpc':request['vpc_id'], 'aws:principalarn':request['principal_arn'], 'aws:principalaccount':account, 'aws:securetransport':None if request['secure_transport'] is None else str(request['secure_transport']).lower()}
    if not b['complete'] or b['state'] == 'UNKNOWN':
        br = _unknown('BOUNDARY_EVIDENCE_INCOMPLETE')
    elif b['state'] == 'ABSENT':
        br = {'status':'NOT_APPLICABLE','reason':'ASSERTED_ABSENT'} if p['permissions_boundary_arn'] is None and a['assertions']['no_permissions_boundary'] else _unknown('BOUNDARY_PRESENCE_CONFLICT')
    elif not _managed(b['policy'],account) or b['policy']['arn'] != p['permissions_boundary_arn'] or a['assertions']['no_permissions_boundary']:
        br = _unknown('BOUNDARY_ATTACHMENT_OR_VERSION_UNCONFIRMED')
    else:
        br = _eval([b['policy']['document']],request,context)
    if not s['complete'] or s['state'] == 'UNKNOWN' or s['session_kind'] == 'UNKNOWN':
        sr = _unknown('SESSION_EVIDENCE_INCOMPLETE')
    elif (kind == 'role') != (s['session_kind'] == 'ASSUMED_ROLE'):
        sr = _unknown('SESSION_KIND_CONFLICT')
    elif s['state'] == 'ABSENT':
        sr = {'status':'NOT_APPLICABLE','reason':'ASSERTED_ABSENT'} if a['assertions']['no_session_policy'] else _unknown('SESSION_PRESENCE_CONFLICT')
    elif kind != 'role' or a['assertions']['no_session_policy']:
        sr = _unknown('SESSION_SCOPE_UNSUPPORTED_OR_CONFLICT')
    else:
        # A session policy set is a union, then intersects the identity grant.
        # Managed session policy must be from the role account (AWS-managed
        # session policy provenance is not established in this profile).
        valid = [_managed(row,account) for row in s['managed_policies']]
        arns = [row['arn'] for row in s['managed_policies']]
        if not all(valid) or len(arns) != len(set(arns)) or any(POLICY.fullmatch(arn)[1] != account for arn in arns):
            sr = _unknown('SESSION_MANAGED_SET_UNCONFIRMED')
        else:
            docs = ([s['inline_document']] if s['inline_document'] is not None else []) + [row['document'] for row in s['managed_policies']]
            sr = _eval(docs,request,context)
    result.update(boundary=br,session=sr)
    # G1 intentionally has no evaluated layers for cross-account requests.
    base = (_layer(a['policies']['identity'], a['complete']['identity'], request, context, 'identity')['status']
            if cross_account and account != request['bucket_account'] else auth['layers']['identity']['status'])
    statuses = [base,br['status'],sr['status']]
    if 'EXPLICIT_DENY' in statuses:
        status,reason = 'EXPLICIT_DENY_CANDIDATE','MATCHING_ASSERTED_DENY'
    elif 'UNKNOWN' in statuses:
        status,reason = 'UNKNOWN','IDENTITY_OR_LIMIT_EVIDENCE_INCOMPLETE'
    elif 'NO_MATCHING_ALLOW' in statuses:
        status,reason = 'IDENTITY_GRANT_BLOCKED_CANDIDATE','REQUIRED_IDENTITY_GRANT_LAYER_NO_ALLOW'
    elif base == 'ALLOW_CANDIDATE' and all(x in ('ALLOW_CANDIDATE','NOT_APPLICABLE') for x in statuses[1:]):
        status,reason = 'IDENTITY_GRANT_CANDIDATE','IDENTITY_AND_ASSERTED_LIMITS_ALLOW'
    else:
        status,reason = 'UNKNOWN','UNRESOLVED_LIMITS'
    return result | {'identity_grant_status':status,'reason':reason}
