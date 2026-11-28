"""Offline, bounded S3 policy constraints for an asserted same-account request.
No credential, policy retrieval, network or AWS API execution. Not IAM Simulator.
"""
import hashlib
import json
import re

MAX_BYTES = 1024 * 1024
LAYERS = ('identity', 'bucket', 'endpoint')
ASSERTIONS = ('no_permissions_boundary', 'no_session_policy', 'no_scp_rcp',
              'bucket_owner_enforced', 'no_additional_service_restrictions',
              'object_owned_by_bucket_account', 'no_kms_requirement')
PRINCIPAL = re.compile(r'arn:aws:iam::([0-9]{12}):(user|role)/[A-Za-z0-9_+=,.@/-]{1,512}')
BUCKET = re.compile(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]')
CONDITION_KEYS = {'aws:sourcevpce', 'aws:sourcevpc', 'aws:principalarn',
                  'aws:securetransport', 'aws:principalaccount'}


def _pairs(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError('Duplicate JSON key')
        result[k] = v
    return result


def _strings(value):
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not 1 <= len(value) <= 64 or any(
        not isinstance(x, str) or not 1 <= len(x) <= 1024 for x in value
    ):
        return None
    return value


def _glob(pattern, value):
    # IAM * and ? only; brackets are literal. Bounded iterative matching.
    i = j = 0
    star = -1
    mark = 0
    while i < len(value):
        if j < len(pattern) and (pattern[j] == '?' or pattern[j] == value[i]) and pattern[j] != '*':
            i += 1; j += 1
        elif j < len(pattern) and pattern[j] == '*':
            star = j; j += 1; mark = i
        elif star >= 0:
            mark += 1; i = mark; j = star + 1
        else:
            return False
    return all(c == '*' for c in pattern[j:])


def _all(values):
    return False if False in values else None if None in values else True


def _match_patterns(value, patterns, *, ignore_case=False, wildcard=True):
    patterns = _strings(patterns)
    if patterns is None:
        return None
    matches = []
    for p in patterns:
        if '${' in p:
            matches.append(None); continue
        left, right = (p.lower(), value.lower()) if ignore_case else (p, value)
        matches.append(_glob(left, right) if wildcard else left == right)
    return True if True in matches else None if None in matches else False


def _principal(value, request, layer):
    if value == '*':
        return True
    if value == {'AWS': '*'}:
        return None if layer == 'endpoint' and request['endpoint_type'] == 'Gateway' else True
    if layer == 'endpoint' and request['endpoint_type'] == 'Gateway':
        return None  # Gateway principal must be wildcard, use condition for restriction.
    if not isinstance(value, dict) or set(value) != {'AWS'}:
        return None
    values = _strings(value['AWS'])
    if values is None:
        return None
    matches = []
    for p in values:
        # Exact IAM ARN only. Account delegation, service, STS session and wildcard ARN not inferred.
        matches.append(p == request['principal_arn'] if PRINCIPAL.fullmatch(p) else None)
    return True if True in matches else None if None in matches else False


def _conditions(conditions, context):
    if not isinstance(conditions, dict) or not conditions:
        return None
    results = []
    for op, entries in conditions.items():
        if op not in ('StringEquals', 'StringNotEquals', 'StringLike', 'StringNotLike',
                      'ArnEquals', 'ArnLike', 'ArnNotEquals', 'ArnNotLike', 'Bool') or not isinstance(entries, dict) or not entries:
            results.append(None); continue
        seen = set()
        for key, vals in entries.items():
            key = key.lower()
            if key in seen or key not in CONDITION_KEYS or context.get(key) is None:
                results.append(None); continue
            seen.add(key)
            if op == 'Bool':
                values = _strings(vals)
                if key != 'aws:securetransport' or values is None or any(v not in ('true','false') for v in values):
                    results.append(None); continue
                results.append(context[key] in values); continue
            if key == 'aws:securetransport':
                results.append(None); continue
            if op.startswith('Arn') and key != 'aws:principalarn':
                results.append(None); continue
            if op.startswith('Arn'):
                patterns = _strings(vals)
                matches = []
                for pattern in patterns or []:
                    parts = pattern.split(':',5)
                    actual = context[key].split(':',5)
                    matches.append(None if len(parts)!=6 or '${' in pattern else all(_glob(p,v) for p,v in zip(parts,actual)))
                matched = True if True in matches else None if not matches or None in matches else False
            else:
                matched = _match_patterns(context[key], vals, wildcard='Like' in op)
            results.append(not matched if matched is not None and 'Not' in op else matched)
    return _all(results)


def _statement(s, request, context, layer):
    if not isinstance(s, dict) or s.get('Effect') not in ('Allow','Deny'):
        return None, None
    # Unsupported elements (including NotAction/NotResource/NotPrincipal) cannot silently become a match.
    allowed = {'Sid','Effect','Action','Resource','Condition'} | ({'Principal'} if layer != 'identity' else set())
    if not set(s) <= allowed or not {'Action','Resource'} <= set(s) or (layer != 'identity' and 'Principal' not in s):
        return s['Effect'], None
    # S3 object ARNs are case-sensitive; action names are not.
    checks = [_match_patterns(request['action'], s['Action'], ignore_case=True),
              _match_patterns(request['resource'], s['Resource'])]
    if layer != 'identity':
        checks.append(_principal(s['Principal'], request, layer))
    if 'Condition' in s:
        checks.append(_conditions(s['Condition'], context))
    return s['Effect'], _all(checks)


def _layer(documents, complete, request, context, layer):
    result = {'layer': layer, 'complete_asserted': complete, 'matching_allows': [],
              'matching_denies': [], 'unresolved_statements': [], 'unresolved_allow': False, 'unresolved_deny': False}
    for di, doc in enumerate(documents):
        if not isinstance(doc, dict) or not set(doc) <= {'Version','Id','Statement'} or doc.get('Version') != '2012-10-17':
            result['unresolved_statements'].append({'document_index': di, 'statement_index': None})
            result['unresolved_allow'] = result['unresolved_deny'] = True
            continue
        statements = doc.get('Statement')
        if isinstance(statements, dict): statements = [statements]
        if not isinstance(statements, list) or not 1 <= len(statements) <= 128:
            result['unresolved_statements'].append({'document_index': di, 'statement_index': None})
            result['unresolved_allow'] = result['unresolved_deny'] = True
            continue
        for si, statement in enumerate(statements):
            effect, matched = _statement(statement, request, context, layer)
            ref = {'document_index': di, 'statement_index': si}
            if matched is True:
                result['matching_denies' if effect == 'Deny' else 'matching_allows'].append(ref)
            elif matched is None:
                result['unresolved_statements'].append(ref)
                if effect != 'Deny': result['unresolved_allow'] = True
                if effect != 'Allow': result['unresolved_deny'] = True
    if result['matching_denies']:
        status = 'EXPLICIT_DENY'
    elif not complete or result['unresolved_deny']:
        status = 'UNKNOWN'
    elif result['matching_allows']:
        status = 'ALLOW_CANDIDATE'
    elif result['unresolved_allow']:
        status = 'UNKNOWN'
    else:
        status = 'NO_MATCHING_ALLOW'
    result['status'] = status
    return result


def analyze_s3_authorization(raw):
    """Evaluate submitted policies for one hypothetical same-account S3 read request."""
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        raise ValueError('Authorization evidence must be bytes, at most 1 MiB')
    try:
        evidence = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON constant')))
    except (UnicodeError, RecursionError) as exc:
        raise ValueError('Invalid authorization JSON') from exc
    if not isinstance(evidence, dict) or set(evidence) != {'schema','request','policies','complete','assertions'} or evidence['schema'] != 'cloudpath-s3-authz-v1':
        raise ValueError('Invalid authorization evidence wrapper')
    request = evidence['request']
    fields = {'principal_arn','bucket_account','action','resource','endpoint_id','endpoint_type','vpc_id','secure_transport'}
    if not isinstance(request, dict) or set(request) != fields:
        raise ValueError('Invalid authorization request fields')
    if any(not isinstance(request[k],str) or not 1 <= len(request[k]) <= 1024 for k in fields - {'secure_transport'}):
        raise ValueError('Invalid authorization request value')
    principal = PRINCIPAL.fullmatch(request['principal_arn'])
    if not principal or not re.fullmatch(r'[0-9]{12}', request['bucket_account']) or not re.fullmatch(r'vpce-[0-9a-f]{8,17}', request['endpoint_id']) or not re.fullmatch(r'vpc-[0-9a-f]{8,17}', request['vpc_id']) or request['endpoint_type'] not in ('Interface','Gateway') or (request['secure_transport'] is not None and type(request['secure_transport']) is not bool):
        raise ValueError('Invalid authorization scenario identity')
    if request['action'] not in ('s3:GetObject','s3:ListBucket') or not request['resource'].startswith('arn:aws:s3:::'):
        raise ValueError('Unsupported S3 action/resource profile')
    resource = request['resource'][len('arn:aws:s3:::'):]
    bucket, sep, key = resource.partition('/')
    if not BUCKET.fullmatch(bucket) or ('..' in bucket) or (request['action']=='s3:ListBucket' and sep) or (request['action']=='s3:GetObject' and (not sep or not key or any(c in key for c in '*?${') or any(ord(c)<32 for c in key))):
        raise ValueError('Invalid bucket or object resource for action')
    policies, complete, assertions = (evidence[k] for k in ('policies','complete','assertions'))
    if not isinstance(policies, dict) or set(policies) != set(LAYERS) or any(not isinstance(policies[k],list) or len(policies[k])>16 for k in LAYERS):
        raise ValueError('Invalid policy sets')
    if not isinstance(complete,dict) or set(complete)!=set(LAYERS) or any(type(v) is not bool for v in complete.values()):
        raise ValueError('Explicit completeness flags required')
    if not isinstance(assertions,dict) or set(assertions)!=set(ASSERTIONS) or any(type(v) is not bool for v in assertions.values()):
        raise ValueError('Explicit scope assertion flags required')
    context = {'aws:sourcevpce':request['endpoint_id'], 'aws:sourcevpc':request['vpc_id'], 'aws:principalarn':request['principal_arn'], 'aws:principalaccount':principal[1], 'aws:securetransport':None if request['secure_transport'] is None else str(request['secure_transport']).lower()}
    result = {'analysis_type':'STATIC_AWS_S3_AUTHORIZATION_CONSTRAINTS', 'input_identity':'sha256-s3-authz-v1:'+hashlib.sha256(raw).hexdigest(), 'scenario':request, 'network_status':'NOT_EVALUATED', 'authentication_status':'NOT_EVALUATED', 'api_status':'UNKNOWN','live_observation':False, 'layers':{}, 'limitations':['Submitted hypothetical request and policies only; no authenticated policy attachment, effective principal or live context.', 'Same-account S3 GetObject/ListBucket only; limited policy language and principal forms. No cross-account, ACL, KMS, access point, organizations or session/boundary evaluation.', 'Policy candidates are not proof of network reachability, credentials, TLS, object existence or API success. No AWS calls.']}
    if principal[1]!=request['bucket_account']:
        return result | {'authorization_status':'UNKNOWN','reason':'CROSS_ACCOUNT_SCOPE_UNSUPPORTED'}
    # Absence of endpoint policy document is not proof of a default full-access policy.
    if not policies['endpoint']:
        complete = complete | {'endpoint':False}
    layers = {k:_layer(policies[k],complete[k],request,context,k) for k in LAYERS}
    result['layers']=layers
    result['unconfirmed_assertions']=[k for k in ASSERTIONS if not assertions[k]]
    denies=[k for k in LAYERS if layers[k]['matching_denies']]
    result['explicit_deny_layers']=denies
    if denies:
        status, reason='EXPLICIT_DENY','MATCHING_EXPLICIT_DENY'
    elif result['unconfirmed_assertions'] or any(not complete[k] or layers[k]['unresolved_deny'] for k in LAYERS):
        status, reason='UNKNOWN','AUTHORIZATION_EVIDENCE_OR_SCOPE_INCOMPLETE'
    elif layers['endpoint']['status']=='NO_MATCHING_ALLOW':
        status, reason='IMPLICIT_DENY_CANDIDATE','ENDPOINT_NO_MATCHING_ALLOW'
    elif layers['identity']['status']=='NO_MATCHING_ALLOW' and layers['bucket']['status']=='NO_MATCHING_ALLOW':
        status, reason='IMPLICIT_DENY_CANDIDATE','IDENTITY_AND_BUCKET_NO_MATCHING_ALLOW'
    elif layers['endpoint']['status']=='ALLOW_CANDIDATE' and any(layers[k]['status']=='ALLOW_CANDIDATE' for k in ('identity','bucket')):
        status, reason='ALLOW_CANDIDATE','MATCHING_GRANT_AND_ENDPOINT_ALLOW'
    else:
        status, reason='UNKNOWN','POLICY_STATEMENT_UNRESOLVED'
    return result | {'authorization_status':status,'reason':reason}
