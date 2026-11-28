"""Bounded same-account direct bucket grants. Called on locally evaluated evidence.
Not a standalone authorization verdict. No AWS calls or runtime identity inference.
"""
import json
from .s3_authorization_evidence import PRINCIPAL

PASS = ('ALLOW_CANDIDATE', 'NOT_APPLICABLE')


def evaluate_resource_grant(authorization, auth, limits, organization):
    """Classify exact direct IAM ARN grants; never infer STS or delegated grants."""
    result = dict(status='UNKNOWN', reason='RESOURCE_GRANT_SCOPE_UNCONFIRMED',
                  principal_kind=None, direct_matches=[], ignored_implicit_limits=[])
    req = auth['scenario']
    account, kind = PRINCIPAL.fullmatch(req['principal_arn']).groups()
    if account != req['bucket_account']:
        return result
    result['principal_kind'] = 'IAM_USER' if kind == 'user' else 'IAM_ROLE'
    if kind == 'role' and req['principal_arn'].split(':role/',1)[1].startswith('aws-service-role/'):
        return result | {'reason':'SERVICE_LINKED_ROLE_SCOPE_UNSUPPORTED'}
    a = json.loads(authorization)
    layers = auth['layers']
    bucket = layers['bucket']
    for ref in bucket['matching_allows']:
        doc = a['policies']['bucket'][ref['document_index']]
        statements = doc['Statement']
        if isinstance(statements, dict): statements = [statements]
        p = statements[ref['statement_index']].get('Principal')
        if isinstance(p, dict) and set(p) == {'AWS'}:
            arns = p['AWS'] if isinstance(p['AWS'], list) else [p['AWS']]
            if req['principal_arn'] in arns and all(isinstance(x,str) and PRINCIPAL.fullmatch(x) for x in arns):
                result['direct_matches'].append(ref)
    if not result['direct_matches']:
        return result | {'status':'NO_DIRECT_GRANT_CANDIDATE' if bucket['status']=='NO_MATCHING_ALLOW' else 'UNKNOWN',
                         'reason':'NO_SUPPORTED_EXACT_PRINCIPAL_GRANT'}
    # A matching deny is independently meaningful, but no aggregate grant may
    # use incomplete identity attachments or an unbound limit/organization set.
    if limits['identity']['identity_status'] != 'CORRELATED_CANDIDATE' or not all(a['complete'].values()):
        return result | {'reason':'DIRECT_GRANT_ATTACHMENT_OR_POLICY_INCOMPLETE'}
    b, s = limits['boundary']['status'], limits['session']['status']
    layer_statuses = [layers[x]['status'] for x in ('identity','bucket','endpoint')] + [b,s,organization['scp']['status'],organization['rcp']['status']]
    if 'EXPLICIT_DENY' in layer_statuses:
        return result | {'status':'EXPLICIT_DENY_CANDIDATE','reason':'MATCHING_ASSERTED_DENY'}
    if 'UNKNOWN' in layer_statuses or any(layers[x]['unresolved_deny'] for x in ('identity','bucket','endpoint')):
        return result | {'reason':'DIRECT_GRANT_POLICY_OR_LIMIT_UNCONFIRMED'}
    if layers['endpoint']['status'] != 'ALLOW_CANDIDATE' or organization['organization_status'] != 'ORGANIZATION_PASS_CANDIDATE':
        return result | {'status':'RESOURCE_GRANT_BLOCKED_CANDIDATE','reason':'ENDPOINT_OR_ORGANIZATION_LIMIT'}
    if kind == 'user':
        if s != 'NOT_APPLICABLE':
            return result | {'reason':'IAM_USER_SESSION_SCOPE_UNCONFIRMED'}
        if b == 'NO_MATCHING_ALLOW':
            result['ignored_implicit_limits'].append('boundary')
        elif b not in PASS:
            return result | {'reason':'IAM_USER_BOUNDARY_SCOPE_UNCONFIRMED'}
    elif b not in PASS or s not in PASS:
        return result | {'status':'RESOURCE_GRANT_BLOCKED_CANDIDATE','reason':'ROLE_BOUNDARY_OR_SESSION_LIMIT'}
    if layers['identity']['status'] == 'NO_MATCHING_ALLOW':
        result['ignored_implicit_limits'].append('identity')
    return result | {'status':'RESOURCE_GRANT_ALLOW_CANDIDATE','reason':'EXACT_SAME_ACCOUNT_PRINCIPAL_GRANT'}
