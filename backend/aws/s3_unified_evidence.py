"""G3e.1: correlate locally recomputed S3 evidence, not actual AWS authorization.
The manifest is an assertion, not a signature or an authenticated capture.
"""
import hashlib
import json
from .s3_authorization_evidence import analyze_s3_authorization, _pairs, PRINCIPAL
from .s3_access_evidence import analyze_s3_access
from .iam_permission_limits import analyze_iam_permission_limits
from .iam_organization_limits import analyze_iam_organization_limits
from .s3_cross_account_evidence import analyze_s3_cross_account
from .s3_kms_evidence import analyze_s3_kms
from .s3_acl_evidence import analyze_s3_acl
from .peering_evidence import _timestamp
from .s3_resource_grant_evidence import evaluate_resource_grant
from .iam_cross_account_organization import analyze_cross_account_organization

NAMES = ('authorization','identity','limits','organization','encryption','acl','network_binding')
CROSS_NAMES = NAMES + ('resource_organization',)


def digest(raw):
    return None if raw is None else hashlib.sha256(raw).hexdigest()


def _load(raw):
    if not isinstance(raw,bytes) or len(raw)>65536:
        raise ValueError('Unified manifest must be bytes <= 64 KiB')
    return json.loads(raw,object_pairs_hook=_pairs,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON constant')))


def analyze_s3_unified(authorization, *, identity=None, limits=None, organization=None,
                       encryption=None, acl=None, manifest=None, network=None, resource_organization=None):
    """Recompute each sidecar against one authorization byte sequence.

    network is raw G2 arguments except authorization_raw; never a result object.
    Same-account grants or narrow exact cross-account direct policy paths,
    ACL-disabled and no-KMS, may produce aggregate candidates.
    """
    auth=analyze_s3_authorization(authorization)
    req=auth['scenario']; same=PRINCIPAL.fullmatch(req['principal_arn'])[1]==req['bucket_account']
    lim=analyze_iam_permission_limits(authorization,identity,limits,cross_account=not same)
    org=(analyze_iam_organization_limits(authorization,organization) if same else
         analyze_cross_account_organization(authorization,organization,resource_organization))
    kms=analyze_s3_kms(authorization,encryption)
    owner=analyze_s3_acl(authorization,acl)
    cross=None if same else analyze_s3_cross_account(authorization)
    net=None if network is None else analyze_s3_access(authorization_raw=authorization,**network)
    raw={'authorization':authorization,'identity':identity,'limits':limits,'organization':organization,'encryption':encryption,'acl':acl,'network_binding':None if network is None else network.get('binding_raw')}
    r=dict(analysis_type='STATIC_S3_UNIFIED_EVIDENCE_V1',scenario=req,input_identity=auth['input_identity'],
           account_scope='SAME_ACCOUNT' if same else 'CROSS_ACCOUNT',
           evidence_status='UNKNOWN', evidence_reason='UNIFIED_MANIFEST_MISSING',
           network_status='NOT_EVALUATED' if net is None else net['network_status'],
           integrated_status='UNKNOWN',grant_path=None,authorization_status='UNKNOWN',api_status='UNKNOWN',
           runtime_identity_status='UNKNOWN',live_observation=False,first_stop=None,
           independent_findings=[],unresolved=[],
           components=dict(resource_grant=None,authorization=auth,identity=lim['identity'],limits=lim,organization=org,kms=kms,acl=owner,cross_account=cross,network=net),
           limitations=['Manifest and sidecars are asserted, not authenticated AWS observations.','Only direct IAM user/role grants with bucket-owner-enforced ACL-disabled, no-KMS S3 read profile are composed; cross-account requires both exact policy grants and separate organization evidence.','No runtime credentials, group or workload binding, STS/wildcard/delegated resource grants, KMS guardrails or actual API proof.'])
    findings=r['independent_findings']
    def finding(layer,status,reason): findings.append(dict(layer=layer,status=status,reason=reason))
    base=auth if same else cross
    for name,l in base['layers'].items():
        if l['status'] in ('EXPLICIT_DENY','NO_MATCHING_ALLOW','UNKNOWN'):
            finding(name,l['status'],'SUBMITTED_POLICY_LAYER')
    for name,obj in [('boundary',lim['boundary']),('session',lim['session']),('scp',org['scp']),('rcp',org['rcp'])]:
        if obj['status'] not in ('ALLOW_CANDIDATE','NOT_APPLICABLE'): finding(name,obj['status'],obj['reason'])
    for name,status,reason,passing in [('kms',kms['kms_status'],kms['reason'],('NOT_REQUIRED_CANDIDATE','NOT_APPLICABLE')),('ownership',owner['ownership_status'],owner['reason'],('BUCKET_ACCOUNT_OWNER_CANDIDATE',)),('acl',owner['acl_status'],owner['reason'],('ACL_DISABLED_CANDIDATE',)),('public_access',owner['public_access_status'],owner['reason'],('NO_RESTRICT_PUBLIC_BUCKETS_BLOCK_CANDIDATE',))]:
        if status not in passing: finding(name,status,reason)
    if net and net['network_status']!='CONDITIONAL_CANDIDATE': finding('network',net['network_status'],net['reason'])
    if manifest is None: return r
    m=_load(manifest)
    if not isinstance(m,dict) or set(m)!={'schema','digests','request_at','same_hypothetical_request','observed_at','network_result_identity'} or m['schema'] not in ('cloudpath-s3-unified-v1','cloudpath-s3-unified-v2'): raise ValueError('Invalid unified manifest')
    v2=m['schema']=='cloudpath-s3-unified-v2'
    names=CROSS_NAMES if v2 else NAMES
    if not isinstance(m['digests'],dict) or set(m['digests'])!=set(names) or not isinstance(m['observed_at'],dict) or set(m['observed_at'])!=set(names): raise ValueError('Invalid manifest evidence keys')
    def stop(reason): return r | {'evidence_reason':reason}
    if v2: raw['resource_organization']=resource_organization
    elif resource_organization is not None: return stop('RESOURCE_ORGANIZATION_UNBOUND')
    if same and resource_organization is not None: return stop('RESOURCE_ORGANIZATION_SCOPE_CONFLICT')
    if m['same_hypothetical_request'] is not True: return stop('REQUEST_ASSERTION_MISSING')
    if m['digests']!={k:digest(v) for k,v in raw.items()}: return stop('INPUT_DIGEST_MISMATCH')
    if m['network_result_identity']!=(None if net is None else net['network_result_identity']): return stop('NETWORK_RESULT_IDENTITY_MISMATCH')
    t=_timestamp(m['request_at'])
    for name,value in raw.items():
        observed=m['observed_at'][name]
        if value is None:
            if observed is not None: return stop('ABSENT_EVIDENCE_TIME_CONFLICT')
            continue
        if observed is None: return stop('EVIDENCE_TIME_MISSING')
        dt=_timestamp(observed)
        if not 0<=(t-dt).total_seconds()<=300: return stop('EVIDENCE_TIME_SCOPE_UNCONFIRMED')
    if identity is not None:
        i=json.loads(identity)
        if _timestamp(i['request_at'])!=t or _timestamp(i['collected_at'])!=_timestamp(m['observed_at']['identity']) or not 0<=(t-_timestamp(i['started_at'])).total_seconds()<=300: return stop('IAM_TIME_SCOPE_MISMATCH')
    if raw['network_binding'] is not None:
        b=json.loads(raw['network_binding'])
        if _timestamp(b['collected_at'])!=_timestamp(m['observed_at']['network_binding']) or _timestamp(b['collected_at'])!=t: return stop('NETWORK_TIME_SCOPE_MISMATCH')
        # At the unified request time, the DNS assertion must still be within TTL.
        dns=net['network'].get('dns_evidence') or {}
        if net['binding_status']=='CORRELATED_CANDIDATE' and not 0<=(t-_timestamp(dns['resolved_at'])).total_seconds()<dns['ttl_seconds']: return stop('NETWORK_DNS_TIME_SCOPE_UNCONFIRMED')
    r.update(evidence_status='ASSERTED_REQUEST_CORRELATED',evidence_reason='EXACT_INPUTS_AND_ASSERTED_TIME_WINDOW')
    resource_grant=evaluate_resource_grant(authorization,auth,lim,org)
    r['components']['resource_grant']=resource_grant
    if resource_grant['status'] in ('EXPLICIT_DENY_CANDIDATE','RESOURCE_GRANT_BLOCKED_CANDIDATE'):
        finding('resource_grant',resource_grant['status'],resource_grant['reason'])
    direct_ok=lim['identity_grant_status']=='IDENTITY_GRANT_CANDIDATE'
    resource_ok=resource_grant['status']=='RESOURCE_GRANT_ALLOW_CANDIDATE'
    unresolved=r['unresolved']
    def require(ok,label):
        if not ok: unresolved.append(label)
    require(net is not None and net['binding_status']=='CORRELATED_CANDIDATE','NETWORK_REQUEST_BINDING')
    if not same:
        require(v2 and resource_organization is not None,'CROSS_ACCOUNT_ORGANIZATION_BINDING')
        require(not req['principal_arn'].split(':role/',1)[-1].startswith('aws-service-role/'),'CROSS_ACCOUNT_PRINCIPAL_SCOPE')
        # Direct exact bucket principal only; do not infer delegated or wildcard grants.
        docs=json.loads(authorization)['policies']['bucket']
        exact=False
        for ref in cross['layers']['bucket']['matching_allows']:
            statements=docs[ref['document_index']]['Statement']
            if isinstance(statements,dict): statements=[statements]
            p=statements[ref['statement_index']].get('Principal')
            if isinstance(p,dict) and set(p)=={'AWS'}:
                arns=p['AWS'] if isinstance(p['AWS'],list) else [p['AWS']]
                exact |= req['principal_arn'] in arns and all(isinstance(a,str) and PRINCIPAL.fullmatch(a) for a in arns)
        require(exact,'CROSS_ACCOUNT_EXACT_RESOURCE_GRANT')
        require(cross['policy_path_status']=='POLICY_PATH_ALLOW_CANDIDATE','CROSS_ACCOUNT_POLICY_PATH')
    require(lim['identity']['identity_status']=='CORRELATED_CANDIDATE','DIRECT_IDENTITY_ATTACHMENT')
    require(owner['ownership_status']=='BUCKET_ACCOUNT_OWNER_CANDIDATE' and owner['acl_status']=='ACL_DISABLED_CANDIDATE','OWNERSHIP_OR_ACL_SCOPE')
    require(owner['public_access_status']=='NO_RESTRICT_PUBLIC_BUCKETS_BLOCK_CANDIDATE','PUBLIC_ACCESS_SCOPE')
    require(kms['kms_status'] in ('NOT_REQUIRED_CANDIDATE','NOT_APPLICABLE'),'KMS_COMPOSITION_UNSUPPORTED_OR_UNKNOWN')
    require(json.loads(authorization)['assertions']['no_additional_service_restrictions'],'ADDITIONAL_SERVICE_RESTRICTIONS')
    require(org['organization_status']=='ORGANIZATION_PASS_CANDIDATE','ORGANIZATION_GUARDRAILS')
    require(direct_ok or (same and resource_ok),'DIRECT_IDENTITY_GRANT_OR_LIMITS')
    require(base['layers']['endpoint']['status']=='ALLOW_CANDIDATE','ENDPOINT_POLICY')
    require(base['layers']['bucket']['status'] in (('ALLOW_CANDIDATE','NO_MATCHING_ALLOW') if same else ('ALLOW_CANDIDATE',)),'BUCKET_POLICY')
    # An explicit submitted denial is an independent finding, not proof of live access.
    # Keep network block as a path-specific result, not a global S3 denial.
    if net and net['binding_status']=='CORRELATED_CANDIDATE' and net['network_status'] in ('BLOCKED','CONDITIONAL_RESPONSE_BLOCKED'):
        r.update(integrated_status='NETWORK_PATH_BLOCKED_CANDIDATE',first_stop=net['first_stop'])
    elif (same or v2) and net and net['binding_status']=='CORRELATED_CANDIDATE' and net['network_status']=='CONDITIONAL_CANDIDATE' and base['layers']['endpoint']['status'] in ('EXPLICIT_DENY','NO_MATCHING_ALLOW'):
        r.update(integrated_status='ENDPOINT_POLICY_BLOCK_CANDIDATE',first_stop='ENDPOINT_POLICY')
    elif not unresolved and net['network_status']=='CONDITIONAL_CANDIDATE':
        r.update(integrated_status='CONDITIONAL_ACCESS_CANDIDATE',grant_path=('CROSS_ACCOUNT_IDENTITY_AND_RESOURCE' if not same else 'IDENTITY' if direct_ok else 'RESOURCE_POLICY'))
    # Retain independent explicit-deny candidates without treating an unsupported
    # resource-policy grant or a KMS caching case as a globally applicable denial.
    return r
