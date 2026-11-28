"""Separate asserted SCP subject and RCP resource hierarchies for cross-account S3.
No AWS calls, no modification of the original authorization request or digest.
"""
import json
from .s3_authorization_evidence import analyze_s3_authorization, PRINCIPAL
from .iam_organization_limits import _load, _validate, _evaluate, _result, _path_valid

PASS = ('ALLOW_CANDIDATE', 'NOT_APPLICABLE')


def analyze_cross_account_organization(authorization, principal_organization=None, resource_organization=None):
    auth = analyze_s3_authorization(authorization)
    req = auth['scenario']
    account, kind = PRINCIPAL.fullmatch(req['principal_arn']).groups()
    owner = req['bucket_account']
    result = dict(scp=_result(), rcp=_result(), organization_status='UNKNOWN', reason='ORGANIZATION_EVIDENCE_MISSING',
                  principal_account=account, resource_account=owner, authorization_status='UNKNOWN', api_status='UNKNOWN', live_observation=False)
    if account == owner or req['principal_arn'].split(':role/',1)[-1].startswith('aws-service-role/'):
        return result | {'reason':'CROSS_ACCOUNT_PRINCIPAL_SCOPE_UNSUPPORTED'}
    expected = 'IAM_USER' if kind == 'user' else 'IAM_ROLE'
    context = {'aws:sourcevpce':req['endpoint_id'], 'aws:sourcevpc':req['vpc_id'], 'aws:principalarn':req['principal_arn'], 'aws:principalaccount':account, 'aws:securetransport':None if req['secure_transport'] is None else str(req['secure_transport']).lower()}
    no_controls = json.loads(authorization)['assertions']['no_scp_rcp']

    def evaluate(raw, target, control):
        if raw is None: return _result(reason='ORGANIZATION_EVIDENCE_MISSING'), None
        e = _load(raw); _validate(e)
        if e['authorization_input_identity'] != auth['input_identity']:
            return _result(reason='ORGANIZATION_INPUT_IDENTITY_MISMATCH'), None
        if e['account_id'] != target:
            return _result(reason='ORGANIZATION_ACCOUNT_SCOPE_MISMATCH'), None
        if not e['scope_complete'] or e['membership']=='UNKNOWN' or e['principal_kind']!=expected:
            return _result(reason='ORGANIZATION_SCOPE_INCOMPLETE_OR_CONFLICT'), None
        if e['membership']=='STANDALONE':
            valid=e['organization_id'] is None and e['management_account_id'] is None and not e['levels'] and e['scp_state']==e['rcp_state']=='DISABLED'
        else:
            valid=e['organization_id'] is not None and e['management_account_id'] is not None and (target==e['management_account_id'])==(e['membership']=='MANAGEMENT')
        if not valid: return _result(reason='ORGANIZATION_MEMBERSHIP_CONFLICT'), None
        if e['levels'] and not _path_valid(e):
            return _result(reason='HIERARCHY_UNCONFIRMED'), None
        if any(e[k+'_state']=='DISABLED' and any(n[k+'s'] for n in e['levels']) for k in ('scp','rcp')):
            return _result(reason='DISABLED_WITH_ATTACHMENTS'), None
        # no_scp_rcp asserts absence of applicable controls, not absence of all policies in both orgs.
        return _evaluate(e, control, req, context, no_controls), e

    scp, p = evaluate(principal_organization, account, 'SCP')
    rcp, o = evaluate(resource_organization, owner, 'RCP')
    if p and o and p['organization_id'] is not None and p['organization_id']==o['organization_id']:
        # Same organization has a common root and management account. Shared
        # complete node snapshots cannot describe conflicting policy attachments.
        conflict = any(p[k]!=o[k] for k in ('management_account_id','scp_state','rcp_state'))
        if p['levels'] and o['levels']:
            conflict |= p['levels'][0]['id'] != o['levels'][0]['id']
            other={x['id']:x for x in o['levels']}
            for n in p['levels']:
                m=other.get(n['id'])
                if m:
                    conflict |= n['kind']!=m['kind'] or n['parent_id']!=m['parent_id']
                    for field in ('scp','rcp'):
                        if n[field+'_complete'] and m[field+'_complete']:
                            conflict |= {v['id']:v for v in n[field+'s']} != {v['id']:v for v in m[field+'s']}
        def records(e):
            return {row['id']:(kind,row) for n in e['levels'] for kind in ('scps','rcps') for row in n[kind]}
        pr, rr = records(p), records(o)
        conflict |= any(pr[k]!=rr[k] for k in pr.keys() & rr.keys())
        if conflict:
            return result | {'scp':_result(reason='SHARED_ORGANIZATION_CONFLICT'),'rcp':_result(reason='SHARED_ORGANIZATION_CONFLICT'),'reason':'SHARED_ORGANIZATION_CONFLICT'}
    # Management account IDs cannot describe two different organizations in one snapshot.
    if p and o and p['organization_id']!=o['organization_id'] and (p['management_account_id'] is not None and p['management_account_id']==o['management_account_id'] or p['management_account_id']==owner and o['membership']!='MANAGEMENT' or o['management_account_id']==account and p['membership']!='MANAGEMENT'):
        return result | {'reason':'ORGANIZATION_MEMBERSHIP_CONFLICT'}
    statuses=(scp['status'],rcp['status'])
    if 'EXPLICIT_DENY' in statuses: status,reason='EXPLICIT_DENY_CANDIDATE','MATCHING_ASSERTED_ORGANIZATION_DENY'
    elif 'UNKNOWN' in statuses: status,reason='UNKNOWN','ORGANIZATION_CONTROL_UNCONFIRMED'
    elif 'NO_MATCHING_ALLOW' in statuses: status,reason='ORGANIZATION_BLOCKED_CANDIDATE','REQUIRED_ORGANIZATION_LEVEL_NO_ALLOW'
    elif all(s in PASS for s in statuses): status,reason='ORGANIZATION_PASS_CANDIDATE','NO_ASSERTED_ORGANIZATION_BLOCK'
    else: status,reason='UNKNOWN','UNRESOLVED_ORGANIZATION_CONTROLS'
    return result | dict(scp=scp,rcp=rcp,organization_status=status,reason=reason)
