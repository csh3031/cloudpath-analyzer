"""Bounded offline IAM attachment correlation for the existing S3 hypothesis.
Normalized assertions, not an authenticated AWS export or runtime identity.
"""
import hashlib
import json
import re
from collections import Counter
from backend.aws.s3_authorization_evidence import analyze_s3_authorization, PRINCIPAL, _pairs
from backend.aws.peering_evidence import _timestamp

MAX_IDENTITY_BYTES = 2 * 1024 * 1024
NAME = re.compile(r'[A-Za-z0-9_+=,.@-]{1,128}')
POLICY = re.compile(r'arn:aws:iam::(aws|[0-9]{12}):policy/[A-Za-z0-9_+=,.@/-]{1,512}')
GROUP = re.compile(r'arn:aws:iam::([0-9]{12}):group/[A-Za-z0-9_+=,.@/-]{1,512}')
VERSION = re.compile(r'v[1-9][0-9]{0,9}')
FLAGS = {'principal','inline_list','managed_list','group_list','documents'}
FIELDS = {'schema','authorization_input_identity','request_at','started_at','collected_at','complete','principal_before','principal_after','inline_names_before','inline_names_after','managed_arns_before','managed_arns_after','groups_before','groups_after','inline_policies','managed_policies'}


def _canonical(doc):
    return json.dumps(doc, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def _load(raw):
    if not isinstance(raw, bytes) or len(raw)>MAX_IDENTITY_BYTES:
        raise ValueError('Identity evidence must be bytes, at most 2 MiB')
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON constant')))
    except (UnicodeError, RecursionError) as exc:
        raise ValueError('Invalid identity JSON') from exc


def _fields(obj, fields):
    if not isinstance(obj, dict) or set(obj)!=fields:
        raise ValueError('Invalid identity evidence fields')


def _list(values, pattern, cap=32):
    if not isinstance(values,list) or len(values)>cap or any(not isinstance(v,str) or not pattern.fullmatch(v) for v in values):
        raise ValueError('Invalid IAM attachment list')
    return values


def _principal(p):
    _fields(p, {'arn','unique_id','permissions_boundary_arn'})
    arn=p['arn']
    m=PRINCIPAL.fullmatch(arn) if isinstance(arn,str) else None
    uid=p['unique_id']
    boundary=p['permissions_boundary_arn']
    if not m or not isinstance(uid,str) or not re.fullmatch(('AROA' if m[2]=='role' else 'AIDA')+r'[A-Z0-9]{8,64}',uid):
        raise ValueError('Invalid IAM principal record')
    if boundary is not None and (not isinstance(boundary,str) or not POLICY.fullmatch(boundary)):
        raise ValueError('Invalid IAM boundary ARN')
    return m


def _rows(rows, fields):
    if not isinstance(rows,list) or len(rows)>16:
        raise ValueError('Invalid IAM document list')
    for row in rows:
        _fields(row,fields)
    return rows


def analyze_s3_identity(authorization_raw, identity_raw=None, *, cross_account=False):
    """Correlate a hypothetical IAM ARN and identity document set; never infer effective session."""
    auth=analyze_s3_authorization(authorization_raw)
    result={'analysis_type':'STATIC_AWS_S3_IDENTITY_ATTACHMENT_CONSTRAINTS',
            'authorization':auth,'identity_input_identity':None,'identity_status':'UNKNOWN',
            'correlated_authorization_status':'UNKNOWN','reason':None,'attachments':[],
            'authentication_status':'NOT_EVALUATED','source_identity_status':'UNKNOWN',
            'network_status':'NOT_EVALUATED','api_status':'UNKNOWN','live_observation':False,
            'limitations':['Submitted normalized assertions only, not authenticated IAM data or proof of actual credentials/source role.',
                           'Direct role/user policies only; user group grants, boundary/session/SCP/RCP, bucket policy provenance, cross-account and runtime remain unresolved.',
                           'Repeated snapshot assertions and hashes are not proof of atomicity, freshness or actual policy attachment. No AWS calls.']}
    def stop(reason):
        return result | {'reason':reason}
    if identity_raw is None:
        return stop('IAM_IDENTITY_EVIDENCE_MISSING')
    e=_load(identity_raw)
    _fields(e,FIELDS)
    if e['schema']!='cloudpath-s3-identity-v1':
        raise ValueError('Invalid identity evidence schema')
    result['identity_input_identity']='sha256-s3-identity-v1:'+hashlib.sha256(identity_raw).hexdigest()
    _fields(e['complete'],FLAGS)
    if any(type(v) is not bool for v in e['complete'].values()):
        raise ValueError('Explicit IAM completeness flags required')
    p,q=e['principal_before'],e['principal_after']
    principal=_principal(p); _principal(q)
    account,kind=principal.groups()
    for prefix,pattern in [('inline_names',NAME),('managed_arns',POLICY),('groups',GROUP)]:
        for suffix in ('before','after'):
            _list(e[prefix+'_'+suffix],pattern)
    inline=_rows(e['inline_policies'],{'name','principal_id','document_before','document_after'})
    managed=_rows(e['managed_policies'],{'arn','policy_id_before','policy_id_after','default_version_before','default_version_after','document_version','is_default_version','document'})
    for row in inline:
        if not isinstance(row['name'],str) or not NAME.fullmatch(row['name']) or not isinstance(row['principal_id'],str) or any(not isinstance(row[k],dict) for k in ('document_before','document_after')):
            raise ValueError('Invalid IAM inline policy record')
    for row in managed:
        if not isinstance(row['arn'],str) or not POLICY.fullmatch(row['arn']) or any(not isinstance(row[k],str) or not re.fullmatch(r'ANPA[A-Z0-9]{8,64}',row[k]) for k in ('policy_id_before','policy_id_after')) or any(not isinstance(row[k],str) or not VERSION.fullmatch(row[k]) for k in ('default_version_before','default_version_after','document_version')) or type(row['is_default_version']) is not bool or not isinstance(row['document'],dict):
            raise ValueError('Invalid IAM managed policy record')
    start,end,request_at=(_timestamp(e[k]) for k in ('started_at','collected_at','request_at'))
    if e['authorization_input_identity']!=auth['input_identity']:
        return stop('IAM_AUTHORIZATION_IDENTITY_MISMATCH')
    if not start<=end<=request_at or (request_at-start).total_seconds()>300:
        return stop('IAM_EVIDENCE_TIME_SCOPE_UNCONFIRMED')
    if p['arn']!=auth['scenario']['principal_arn'] or (not cross_account and account!=auth['scenario']['bucket_account']):
        return stop('IAM_PRINCIPAL_SCOPE_MISMATCH')
    if p!=q:
        return stop('IAM_PRINCIPAL_CHANGED')
    if not all(e['complete'].values()):
        return stop('IAM_COLLECTION_INCOMPLETE')
    for prefix in ('inline_names','managed_arns','groups'):
        a,b=(e[prefix+'_'+k] for k in ('before','after'))
        if len(set(a))!=len(a) or len(set(b))!=len(b):
            return stop('IAM_DUPLICATE_ATTACHMENT')
        if set(a)!=set(b):
            return stop('IAM_ATTACHMENT_LIST_CHANGED')
    if e['groups_before']:
        return stop('IAM_GROUP_POLICY_SCOPE_UNSUPPORTED' if kind=='user' else 'IAM_ROLE_GROUP_CONFLICT')
    if any(POLICY.fullmatch(a)[1] not in ('aws',account) for a in e['managed_arns_before']):
        return stop('IAM_MANAGED_POLICY_ACCOUNT_MISMATCH')
    if Counter(r['name'] for r in inline)!=Counter(e['inline_names_before']) or Counter(r['arn'] for r in managed)!=Counter(e['managed_arns_before']):
        return stop('IAM_ATTACHMENT_DOCUMENT_SET_MISMATCH')
    docs=[]; refs=[]
    for row in inline:
        if row['principal_id']!=p['unique_id']:
            return stop('IAM_INLINE_PRINCIPAL_MISMATCH')
        if _canonical(row['document_before'])!=_canonical(row['document_after']):
            return stop('IAM_INLINE_DOCUMENT_CHANGED')
        docs.append(row['document_before']); refs.append({'kind':'INLINE','name':row['name']})
    for row in managed:
        if row['policy_id_before']!=row['policy_id_after']:
            return stop('IAM_MANAGED_POLICY_ID_CHANGED')
        if not row['is_default_version'] or not row['default_version_before']==row['default_version_after']==row['document_version']:
            return stop('IAM_MANAGED_DEFAULT_VERSION_UNCONFIRMED')
        docs.append(row['document']); refs.append({'kind':'MANAGED','arn':row['arn'],'version':row['document_version']})
    submitted=json.loads(authorization_raw)['policies']['identity']
    if Counter(map(_canonical,docs))!=Counter(map(_canonical,submitted)):
        return stop('IAM_IDENTITY_POLICY_CONTENT_MISMATCH')
    # Map references to existing G1 statement document indices, preserving multiplicity.
    pending=list(zip(map(_canonical,docs),refs))
    for i,doc in enumerate(submitted):
        pos=next(j for j,(text,_) in enumerate(pending) if text==_canonical(doc))
        _,ref=pending.pop(pos)
        result['attachments'].append(ref | {'document_index':i})
    result['identity_status']='CORRELATED_CANDIDATE'
    if p['permissions_boundary_arn'] is not None:
        return stop('IAM_PERMISSIONS_BOUNDARY_PENDING')
    if not json.loads(authorization_raw)['complete']['identity']:
        return stop('IAM_AUTHORIZATION_IDENTITY_INCOMPLETE')
    # Attachment correlation does not itself authorize cross-account access.
    result['correlated_authorization_status']=auth['authorization_status']
    return stop('IAM_ASSERTED_ATTACHMENT_CORRELATED')
