"""Bounded, asserted S3 ownership, ACL and public access controls for read requests."""
import json
import re
from .s3_authorization_evidence import analyze_s3_authorization, MAX_BYTES, PRINCIPAL, _pairs

FLAGS = ('BlockPublicAcls','IgnorePublicAcls','BlockPublicPolicy','RestrictPublicBuckets')
MODES = ('BucketOwnerEnforced','BucketOwnerPreferred','ObjectWriter')
GROUPS = ('AllUsers','AuthenticatedUsers','LogDelivery')
PERMISSIONS = ('READ','WRITE','READ_ACP','WRITE_ACP','FULL_CONTROL')


def _shape(v, fields, name):
    if not isinstance(v,dict) or set(v)!=set(fields):
        raise ValueError('Invalid '+name)
    return v


def _account(v):
    return isinstance(v,str) and re.fullmatch(r'[0-9]{12}',v) is not None


def _canonical(v):
    return isinstance(v,str) and re.fullmatch(r'[a-f0-9]{64}',v) is not None


def _flags(v):
    if v is None: return dict.fromkeys(FLAGS)
    _shape(v,FLAGS,'public access block flags')
    if any(x is not None and type(x) is not bool for x in v.values()): raise ValueError('Invalid public access block flag')
    return v


def analyze_s3_acl(authorization, access=None):
    base=analyze_s3_authorization(authorization)
    req=base['scenario']
    raw=json.loads(authorization,object_pairs_hook=_pairs)
    principal_account=PRINCIPAL.fullmatch(req['principal_arn'])[1]
    bucket_account=req['bucket_account']
    result=dict(analysis_type='STATIC_S3_ACL_PUBLIC_ACCESS', input_identity=base['input_identity'],
                scenario=req, ownership_status='UNKNOWN', acl_status='UNKNOWN', public_access_status='UNKNOWN',
                effective_public_access_block=dict.fromkeys(FLAGS), acl_read_candidate_refs=[], ignored_public_refs=[],
                public_read_refs=[], authorization_status='UNKNOWN', api_status='UNKNOWN', live_observation=False,
                limitations=['Asserted normalized evidence; no actual ownership, canonical ID or policy-status provenance.',
                             'Ordinary IAM user/role GetObject/ListBucket only; no access points, anonymous or service principal requests.',
                             'ACL candidates are not IAM grants or final access; public ACL grants and non-bucket-owned object policy integration unresolved.',
                             'Account controls must include applicable organization-level controls; no inference from missing flags.'])
    def out(reason): return result | {'reason':reason}
    if access is None: return out('ACL_EVIDENCE_MISSING')
    if not isinstance(access,bytes) or len(access)>MAX_BYTES: raise ValueError('ACL evidence must be bytes <= 1 MiB')
    e=json.loads(access,object_pairs_hook=_pairs,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON constant')))
    _shape(e,('schema','authorization_input_identity','ownership','public_access','acl'),'ACL wrapper')
    if e['schema']!='cloudpath-s3-acl-v1': raise ValueError('Invalid ACL schema')
    if e['authorization_input_identity']!=base['input_identity']: return out('AUTHORIZATION_BINDING_MISMATCH')
    o=_shape(e['ownership'],('resource','complete','mode','bucket_account','resource_owner_account'),'ownership')
    if type(o['complete']) is not bool or o['mode'] not in (*MODES,None) or not _account(o['bucket_account']) or (o['resource_owner_account'] is not None and not _account(o['resource_owner_account'])): raise ValueError('Invalid ownership metadata')
    if o['resource']!=req['resource'] or o['bucket_account']!=bucket_account: return out('RESOURCE_BINDING_MISMATCH')
    p=_shape(e['public_access'],('bucket_flags','account_flags','account_includes_org_controls','bucket_policy_public'),'public access')
    if type(p['account_includes_org_controls']) is not bool or (p['bucket_policy_public'] is not None and type(p['bucket_policy_public']) is not bool): raise ValueError('Invalid public access metadata')
    bf,af=_flags(p['bucket_flags']),_flags(p['account_flags'])
    effective={k: True if bf[k] is True or af[k] is True else False if bf[k] is False and af[k] is False and p['account_includes_org_controls'] else None for k in FLAGS}
    result['effective_public_access_block']=effective
    # A public policy classification must be explicitly asserted for the submitted complete bucket policy.
    public=p['bucket_policy_public'] if raw['complete']['bucket'] else None
    if not raw['policies']['bucket'] and raw['complete']['bucket']:
        public=False if public is not True else None
    restrict=effective['RestrictPublicBuckets']
    if principal_account==bucket_account or restrict is False or public is False:
        result['public_access_status']='NO_RESTRICT_PUBLIC_BUCKETS_BLOCK_CANDIDATE'
    elif restrict is True and public is True:
        result['public_access_status']='CROSS_ACCOUNT_BLOCK_CANDIDATE'
    # Ownership is independent of public access controls.
    if not o['complete'] or o['mode'] is None or o['resource_owner_account'] is None: return out('OWNERSHIP_EVIDENCE_INCOMPLETE')
    owner=o['resource_owner_account']
    if (o['mode']=='BucketOwnerEnforced' or req['action']=='s3:ListBucket') and owner!=bucket_account: return out('OWNERSHIP_CONFLICT')
    if raw['assertions']['bucket_owner_enforced'] and o['mode']!='BucketOwnerEnforced': return out('OWNERSHIP_CONFLICT')
    if req['action']=='s3:GetObject' and raw['assertions']['object_owned_by_bucket_account'] and owner!=bucket_account: return out('OWNERSHIP_CONFLICT')
    result['ownership_status']='BUCKET_ACCOUNT_OWNER_CANDIDATE' if owner==bucket_account else 'OTHER_ACCOUNT_OWNER_CANDIDATE'
    if o['mode']=='BucketOwnerEnforced':
        result['acl_status']='ACL_DISABLED_CANDIDATE'
        return out('BUCKET_OWNER_ENFORCED')
    if e['acl'] is None: return out('ACL_METADATA_MISSING')
    a=_shape(e['acl'],('resource','complete','owner_canonical_id','canonical_accounts','grants'),'ACL metadata')
    if type(a['complete']) is not bool or not _canonical(a['owner_canonical_id']): raise ValueError('Invalid ACL owner or completeness')
    if a['resource']!=req['resource']: return out('ACL_RESOURCE_MISMATCH')
    mapping=a['canonical_accounts']
    if not isinstance(mapping,dict) or len(mapping)>128 or any(not _canonical(k) or not _account(v) for k,v in mapping.items()) or len(set(mapping.values()))!=len(mapping): raise ValueError('Invalid canonical account mapping')
    if mapping.get(a['owner_canonical_id'])!=owner: return out('ACL_OWNER_BINDING_UNCONFIRMED')
    grants=a['grants']
    if not isinstance(grants,list) or len(grants)>100: raise ValueError('Invalid ACL grant list')
    unknown=False
    for i,g in enumerate(grants):
        _shape(g,('type','id','permission'),'ACL grant')
        if g['permission'] not in PERMISSIONS: raise ValueError('Invalid ACL permission')
        kind,id_=g['type'],g['id']
        if kind=='CanonicalUser':
            if not _canonical(id_): raise ValueError('Invalid canonical grantee')
            if g['permission'] not in ('READ','FULL_CONTROL'): continue
            acct=mapping.get(id_)
            if acct is None: unknown=True
            elif acct==principal_account: result['acl_read_candidate_refs'].append(i)
        elif kind=='Group':
            if id_ not in GROUPS: raise ValueError('Invalid ACL group')
            if id_ not in ('AllUsers','AuthenticatedUsers'): continue
            if effective['IgnorePublicAcls'] is True:
                result['ignored_public_refs'].append(i)
            elif g['permission'] in ('READ','FULL_CONTROL'):
                result['public_read_refs'].append(i)
                unknown=True  # Do not infer public-grant applicability to a runtime session.
        else:
            unknown=True
    if not a['complete'] or unknown: return out('ACL_EVIDENCE_INCOMPLETE_OR_UNSUPPORTED')
    if result['acl_read_candidate_refs']:
        result['acl_status']='ACCOUNT_READ_GRANT_CANDIDATE'
    else:
        result['acl_status']='NO_MATCHING_ACCOUNT_READ_GRANT_CANDIDATE'
    return out('ACL_ACCOUNT_GRANTS_EVALUATED')
