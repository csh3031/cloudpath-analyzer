"""Bounded offline S3 object encryption and KMS policy-path candidates."""
import json
import re
from .s3_authorization_evidence import (analyze_s3_authorization, MAX_BYTES, PRINCIPAL,
    _pairs, _strings, _match_patterns, _all)

KEY = re.compile(r'arn:aws:kms:([a-z]{2}(?:-[a-z]+)+-[0-9]+):([0-9]{12}):key/(?:[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}|mrk-[a-f0-9]{32})')


def _condition(value, context):
    if not isinstance(value, dict) or not value:
        return None
    checks = []
    for op, entries in value.items():
        if op not in ('StringEquals', 'StringLike', 'StringNotEquals', 'StringNotLike') or not isinstance(entries, dict) or not entries:
            checks.append(None); continue
        for name, patterns in entries.items():
            # Encryption context keys are case-sensitive. No inference of other keys.
            if name not in context:
                checks.append(None); continue
            m = _match_patterns(context[name], patterns, wildcard='Like' in op)
            checks.append(not m if m is not None and 'Not' in op else m)
    return _all(checks)


def _principal(value, principal):
    """Only exact user/role and account-root delegation. No wildcard grant inference."""
    if not isinstance(value, dict) or set(value) != {'AWS'}:
        return None, None
    vals = _strings(value['AWS'])
    if vals is None:
        return None, None
    account = PRINCIPAL.fullmatch(principal)[1]
    direct, delegated, unknown = False, False, False
    for v in vals:
        if PRINCIPAL.fullmatch(v):
            direct |= v == principal
        elif re.fullmatch(r'arn:aws:iam::[0-9]{12}:root', v):
            delegated |= v == f'arn:aws:iam::{account}:root'
        else:
            unknown = True
    return (True if direct else None if unknown else False,
            True if delegated else None if unknown else False)


def _layer(docs, complete, principal, key, context, key_policy):
    allows, delegates, denies, unresolved = [], [], [], []
    for di, doc in enumerate(docs):
        if not isinstance(doc, dict) or not set(doc) <= {'Version','Id','Statement'} or doc.get('Version') != '2012-10-17':
            unresolved.append([di, None]); continue
        statements = doc.get('Statement')
        if isinstance(statements, dict): statements = [statements]
        if not isinstance(statements, list) or not 1 <= len(statements) <= 128:
            unresolved.append([di, None]); continue
        for si, s in enumerate(statements):
            ref = [di, si]
            fields = {'Sid','Effect','Action','Resource','Condition'} | ({'Principal'} if key_policy else set())
            required = {'Effect','Action','Resource'} | ({'Principal'} if key_policy else set())
            if not isinstance(s, dict) or not required <= set(s) <= fields or s['Effect'] not in ('Allow','Deny'):
                unresolved.append(ref); continue
            action = _match_patterns('kms:Decrypt', s['Action'], ignore_case=True)
            if action is False: continue
            # Key policy Resource '*' means this particular key; other forms unsupported.
            resource = (True if s['Resource'] in ('*', ['*']) else None) if key_policy else _match_patterns(key, s['Resource'])
            cond = _condition(s['Condition'], context) if 'Condition' in s else True
            direct, delegation = _principal(s['Principal'], principal) if key_policy else (True, False)
            if key_policy and s['Effect']=='Deny' and s['Principal'] in ('*', {'AWS':'*'}):
                direct = True; delegation = False
            base = _all([action,resource,cond])
            d, g = _all([base,direct]), _all([base,delegation])
            if s['Effect']=='Deny' and (d is True or g is True): denies.append(ref)
            elif s['Effect']=='Allow':
                if d is True: allows.append(ref)
                if g is True: delegates.append(ref)
            if d is None or g is None: unresolved.append(ref)
    status = 'EXPLICIT_DENY' if denies else 'UNKNOWN' if not complete or unresolved else 'ALLOW_CANDIDATE' if allows or delegates else 'NO_MATCHING_ALLOW'
    return dict(status=status, direct_allows=allows, delegation_allows=delegates, matching_denies=denies, unresolved_statements=unresolved, complete_asserted=complete)


def analyze_s3_kms(authorization, encryption=None):
    original = analyze_s3_authorization(authorization)
    auth = json.loads(authorization, object_pairs_hook=_pairs)
    req = original['scenario']
    result = dict(analysis_type='STATIC_S3_KMS_POLICY_PATH', input_identity=original['input_identity'],
                  scenario=req, kms_status='UNKNOWN', authorization_status='UNKNOWN', api_status='UNKNOWN',
                  live_observation=False, layers={}, encryption_context=None, key_arn=None, encryption_mode=None,
                  limitations=['Asserted object metadata and submitted policy documents only; no live evidence.',
                               'No KMS grants, runtime identity, key material availability, boundary/session/SCP/RCP or S3 authorization integration.',
                               'Only ordinary GetObject, commercial AWS, symmetric customer-managed key, supported conditions and principals.'])
    def out(status, reason): return result | dict(kms_status=status, reason=reason)
    if req['action']=='s3:ListBucket': return out('NOT_APPLICABLE','LIST_BUCKET_NO_OBJECT_DECRYPT')
    if encryption is None: return out('UNKNOWN','ENCRYPTION_EVIDENCE_MISSING')
    if not isinstance(encryption, bytes) or len(encryption)>MAX_BYTES: raise ValueError('Encryption evidence must be bytes <= 1 MiB')
    try:
        e=json.loads(encryption, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON constant')))
    except (UnicodeError, RecursionError) as exc: raise ValueError('Invalid encryption JSON') from exc
    if not isinstance(e,dict) or set(e)!={'schema','authorization_input_identity','object','key'} or e['schema']!='cloudpath-s3-kms-v1': raise ValueError('Invalid encryption evidence wrapper')
    if e['authorization_input_identity']!=original['input_identity']: return out('UNKNOWN','AUTHORIZATION_BINDING_MISMATCH')
    o=e['object']
    if not isinstance(o,dict) or set(o)!={'resource','metadata_complete','encryption_mode','region','bucket_key_enabled','key_arn'} or type(o['metadata_complete']) is not bool: raise ValueError('Invalid object metadata')
    if o['resource']!=req['resource'] or not o['metadata_complete']: return out('UNKNOWN','OBJECT_METADATA_UNCONFIRMED')
    mode=o['encryption_mode']; result['encryption_mode']=mode
    if mode in ('SSE_S3','UNENCRYPTED'):
        if o['key_arn'] is not None or o['bucket_key_enabled'] not in (None,False) or e['key'] is not None: return out('UNKNOWN','CONTRADICTORY_ENCRYPTION_METADATA')
        return out('NOT_REQUIRED_CANDIDATE','NO_KMS_OBJECT_ENCRYPTION')
    if mode!='SSE_KMS': return out('UNKNOWN','ENCRYPTION_MODE_UNSUPPORTED_OR_UNKNOWN')
    if auth['assertions']['no_kms_requirement']: return out('UNKNOWN','CONTRADICTORY_AUTHORIZATION_ASSERTION')
    key=o['key_arn']; match=KEY.fullmatch(key) if isinstance(key,str) else None
    if not match or o['region']!=match[1] or type(o['bucket_key_enabled']) is not bool: return out('UNKNOWN','KMS_KEY_OR_CONTEXT_UNCONFIRMED')
    result['key_arn']=key
    context_arn=req['resource'].split('/',1)[0] if o['bucket_key_enabled'] else req['resource']
    result['encryption_context']=context_arn
    k=e['key']
    if k is None: return out('UNKNOWN','KMS_KEY_EVIDENCE_MISSING')
    if not isinstance(k,dict) or set(k)!={'arn','state','manager','spec','usage','policy_complete','policy','no_grants_asserted'} or any(type(k[x]) is not bool for x in ('policy_complete','no_grants_asserted')) or not isinstance(k['policy'],list) or len(k['policy'])>16: raise ValueError('Invalid key evidence')
    if k['arn']!=key: return out('UNKNOWN','KMS_KEY_BINDING_MISMATCH')
    if k['spec']!='SYMMETRIC_DEFAULT' or k['usage']!='ENCRYPT_DECRYPT': return out('UNKNOWN','KEY_TYPE_UNSUPPORTED')
    if k['state'] in ('Disabled','PendingDeletion','PendingReplicaDeletion'): return out('KEY_UNAVAILABLE_CANDIDATE','KEY_STATE_NOT_ENABLED')
    if k['state']!='Enabled': return out('UNKNOWN','KEY_STATE_UNCONFIRMED')
    principal=req['principal_arn']; account=PRINCIPAL.fullmatch(principal)[1]; cross=account!=match[2]
    if k['manager']=='AWS' and cross: return out('POLICY_PATH_BLOCKED_CANDIDATE','AWS_MANAGED_KEY_CROSS_ACCOUNT_UNSUPPORTED')
    if k['manager']!='CUSTOMER': return out('UNKNOWN','KEY_MANAGER_UNSUPPORTED')
    context={'kms:ViaService':f's3.{match[1]}.amazonaws.com','kms:CallerAccount':account,'kms:EncryptionContext:aws:s3:arn':context_arn}
    identity=_layer(auth['policies']['identity'],auth['complete']['identity'],principal,key,context,False)
    kp=_layer(k['policy'],k['policy_complete'] and bool(k['policy']),principal,key,context,True)
    result['layers']={'identity':identity,'key_policy':kp}
    if any(x['status']=='EXPLICIT_DENY' for x in (identity,kp)): return out('EXPLICIT_DENY_CANDIDATE','MATCHING_KMS_DENY')
    if any(x['status']=='UNKNOWN' for x in (identity,kp)) or not k['no_grants_asserted']: return out('UNKNOWN','POLICY_OR_GRANT_EVIDENCE_INCOMPLETE')
    direct=bool(kp['direct_allows']); delegated=bool(kp['delegation_allows']); iam=bool(identity['direct_allows'])
    if (direct and not cross) or (iam and (direct or delegated)):
        return out('POLICY_PATH_ALLOW_CANDIDATE','KMS_POLICY_PATH_MATCH')
    return out('POLICY_PATH_BLOCKED_CANDIDATE','KMS_POLICY_PATH_NO_MATCHING_ALLOW')
