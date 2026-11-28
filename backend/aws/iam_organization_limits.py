"""Asserted offline Organizations guardrails for the G1 same-account S3 profile."""
import hashlib
import json
import re
from .s3_authorization_evidence import analyze_s3_authorization, _layer, _pairs, PRINCIPAL

SCHEMA = 'cloudpath-iam-organization-limits-v1'
MAX_ORG_BYTES = 2 * 1024 * 1024
ACCOUNT = re.compile(r'[0-9]{12}')
ORG = re.compile(r'o-[a-z0-9]{10,32}')
ROOT = re.compile(r'r-[a-z0-9]{4,32}')
OU = re.compile(r'ou-([a-z0-9]{4,32})-[a-z0-9]{8,32}')
POLICY_ID = re.compile(r'p-[A-Za-z0-9_]{8,128}')


def _fields(obj, names):
    if not isinstance(obj, dict) or set(obj) != set(names.split()):
        raise ValueError('Invalid Organizations evidence fields')


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _load(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_ORG_BYTES:
        raise ValueError('Organizations evidence must be bytes, at most 2 MiB')
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON constant')))
    except (UnicodeError, RecursionError) as exc:
        raise ValueError('Invalid Organizations JSON') from exc


def _result(status='UNKNOWN', reason='NOT_EVALUATED', levels=None):
    return {'status':status, 'reason':reason, 'levels':levels or []}


def _validate(e):
    _fields(e, 'schema authorization_input_identity account_id organization_id management_account_id membership scope_complete principal_kind scp_state rcp_state path_complete levels')
    if e['schema'] != SCHEMA or not _matches(ACCOUNT,e['account_id']) or e['membership'] not in ('MEMBER','MANAGEMENT','STANDALONE','UNKNOWN') or e['principal_kind'] not in ('IAM_USER','IAM_ROLE','SERVICE_LINKED_ROLE','UNKNOWN') or any(type(e[k]) is not bool for k in ('scope_complete','path_complete')):
        raise ValueError('Invalid Organizations scope')
    for key in ('organization_id','management_account_id'):
        if e[key] is not None and not _matches(ORG if key=='organization_id' else ACCOUNT,e[key]):
            raise ValueError('Invalid organization or management account identifier')
    for key in ('scp_state','rcp_state'):
        if e[key] not in ('ENABLED','DISABLED','UNKNOWN'):
            raise ValueError('Invalid policy type state')
    levels=e['levels']
    if not isinstance(levels,list) or len(levels)>16:
        raise ValueError('Invalid hierarchy size')
    seen={}
    for level in levels:
        _fields(level,'kind id parent_id scp_complete rcp_complete scps rcps')
        kind=level['kind']
        if kind not in ('ROOT','OU','ACCOUNT') or not _matches({'ROOT':ROOT,'OU':OU,'ACCOUNT':ACCOUNT}[kind],level['id']) or level['parent_id'] is not None and not isinstance(level['parent_id'],str):
            raise ValueError('Invalid hierarchy node')
        for flag in ('scp_complete','rcp_complete'):
            if type(level[flag]) is not bool:
                raise ValueError('Invalid completeness flag')
        for field in ('scps','rcps'):
            rows=level[field]
            if not isinstance(rows,list) or len(rows)>16:
                raise ValueError('Invalid attached policy set')
            local=set()
            for row in rows:
                _fields(row,'id name aws_managed document')
                if not _matches(POLICY_ID,row['id']) or not isinstance(row['name'],str) or not 1<=len(row['name'])<=128 or type(row['aws_managed']) is not bool or not isinstance(row['document'],dict):
                    raise ValueError('Invalid organization policy record')
                if row['id'] in local:
                    raise ValueError('Duplicate attachment at same node')
                local.add(row['id'])
                fingerprint=(field,row)
                if row['id'] in seen and seen[row['id']] != fingerprint:
                    raise ValueError('Conflicting organization policy record')
                seen[row['id']]=fingerprint


def _path_valid(e):
    levels=e['levels']
    if not e['path_complete'] or len(levels)<2 or levels[0]['kind']!='ROOT' or levels[0]['parent_id'] is not None or levels[-1]['kind']!='ACCOUNT' or levels[-1]['id']!=e['account_id']:
        return False
    if len({x['id'] for x in levels})!=len(levels):
        return False
    root=levels[0]['id'][2:]
    for i,node in enumerate(levels[1:],1):
        if node['parent_id']!=levels[i-1]['id']:
            return False
        if i<len(levels)-1 and (node['kind']!='OU' or OU.fullmatch(node['id'])[1]!=root):
            return False
    return True


def _full_rcp(row):
    doc=row['document']
    if not row['aws_managed'] or row['name']!='RCPFullAWSAccess' or doc.get('Version')!='2012-10-17' or set(doc)-{'Version','Statement','Id'}:
        return False
    statements=doc.get('Statement')
    if isinstance(statements,dict): statements=[statements]
    if not isinstance(statements,list) or len(statements)!=1 or not isinstance(statements[0],dict):
        return False
    s=statements[0]
    return set(s)-{'Sid'}=={'Effect','Principal','Action','Resource'} and s['Effect']=='Allow' and s['Principal']=='*' and s['Action'] in ('*',['*']) and s['Resource'] in ('*',['*'])


def _custom_rcp(row):
    doc=row['document']
    if row['aws_managed'] or row['name']=='RCPFullAWSAccess' or doc.get('Version')!='2012-10-17' or set(doc)-{'Version','Statement','Id'}:
        return False
    statements=doc.get('Statement')
    if isinstance(statements,dict): statements=[statements]
    return isinstance(statements,list) and bool(statements) and all(isinstance(s,dict) and s.get('Effect')=='Deny' and s.get('Principal')=='*' for s in statements)


def _evaluate(e, kind, request, context, no_controls):
    field=kind.lower()+'s'; flag=kind.lower()+'_complete'; state=e[kind.lower()+'_state']
    # Exempt scope is not assumed from missing policy documents.
    if e['membership'] in ('MANAGEMENT','STANDALONE') or e['principal_kind']=='SERVICE_LINKED_ROLE':
        if e['membership']=='STANDALONE' and (state=='ENABLED' or e['levels']):
            return _result(reason='STANDALONE_SCOPE_CONFLICT')
        return _result('NOT_APPLICABLE','ASSERTED_EXEMPT_SCOPE')
    if state=='UNKNOWN': return _result(reason='POLICY_TYPE_STATE_UNKNOWN')
    if state=='DISABLED':
        if any(level[field] for level in e['levels']): return _result(reason='DISABLED_WITH_ATTACHMENTS')
        return _result('NOT_APPLICABLE','ASSERTED_POLICY_TYPE_DISABLED')
    if no_controls: return _result(reason='G1_NO_CONTROLS_ASSERTION_CONFLICT')
    if not _path_valid(e): return _result(reason='HIERARCHY_UNCONFIRMED')
    evaluated=[]
    for node in e['levels']:
        rows=node[field]
        docs=[r['document'] for r in rows]
        if kind=='RCP':
            full=[r for r in rows if _full_rcp(r)]
            valid=[r for r in rows if _full_rcp(r) or _custom_rcp(r)]
            if len(full)!=1 or len(valid)!=len(rows):
                evaluated.append({'id':node['id'],'kind':node['kind'],'status':'UNKNOWN','reason':'RCP_DEFAULT_OR_SYNTAX_UNCONFIRMED','policy_ids':[r['id'] for r in rows]})
                continue
        result=_layer(docs,node[flag],request,context,'identity' if kind=='SCP' else 'bucket')
        # An enabled SCP should have attachments at each level; missing documents
        # are not evidence of an impossible empty enabled attachment set.
        status=result['status'] if rows else 'UNKNOWN'
        evaluated.append({'id':node['id'],'kind':node['kind'],'status':status,'policy_ids':[r['id'] for r in rows],'evaluation':result})
    statuses=[x['status'] for x in evaluated]
    if 'EXPLICIT_DENY' in statuses: return _result('EXPLICIT_DENY','MATCHING_ASSERTED_ORGANIZATION_DENY',evaluated)
    if 'UNKNOWN' in statuses: return _result(reason='POLICY_LEVEL_UNCONFIRMED',levels=evaluated)
    if 'NO_MATCHING_ALLOW' in statuses: return _result('NO_MATCHING_ALLOW','REQUIRED_LEVEL_NO_ALLOW',evaluated)
    if all(s=='ALLOW_CANDIDATE' for s in statuses): return _result('ALLOW_CANDIDATE','ALL_ASSERTED_LEVELS_ALLOW',evaluated)
    return _result(reason='UNRESOLVED_ORGANIZATION_POLICY',levels=evaluated)


def analyze_iam_organization_limits(authorization_raw, organization_raw=None):
    auth=analyze_s3_authorization(authorization_raw)
    result={'analysis_type':'STATIC_IAM_ORGANIZATION_LIMITS','authorization':auth,'organization_input_identity':None,'scp':_result(),'rcp':_result(),'organization_status':'UNKNOWN','reason':'ORGANIZATION_EVIDENCE_MISSING','authorization_status':'UNKNOWN','runtime_identity_status':'UNKNOWN','api_status':'UNKNOWN','live_observation':False,'limitations':['Asserted organization hierarchy and attachment documents, not authenticated AWS evidence.','Same-account G1 S3 read profile only; SCP subject account and RCP resource account coincide here.','Bounded G1 policy language; unsupported conditions/statements remain unresolved. No runtime identity, cross-account, resource grant composition or AWS calls.']}
    if organization_raw is None: return result
    e=_load(organization_raw); _validate(e)
    result['organization_input_identity']='sha256-iam-organization-limits-v1:'+hashlib.sha256(organization_raw).hexdigest()
    request=auth['scenario']; account,kind=PRINCIPAL.fullmatch(request['principal_arn']).groups()
    if e['authorization_input_identity']!=auth['input_identity']:
        return result | {'reason':'ORGANIZATION_INPUT_IDENTITY_MISMATCH'}
    if account!=request['bucket_account'] or e['account_id']!=account:
        return result | {'reason':'ORGANIZATION_ACCOUNT_SCOPE_UNSUPPORTED_OR_MISMATCH'}
    if not e['scope_complete'] or e['membership']=='UNKNOWN' or e['principal_kind']=='UNKNOWN':
        return result | {'reason':'ORGANIZATION_SCOPE_INCOMPLETE'}
    expected='IAM_USER' if kind=='user' else 'SERVICE_LINKED_ROLE' if request['principal_arn'].split(':role/',1)[-1].startswith('aws-service-role/') else 'IAM_ROLE'
    if e['principal_kind']!=expected:
        return result | {'reason':'PRINCIPAL_KIND_CONFLICT'}
    if e['membership']=='STANDALONE':
        valid=e['organization_id'] is None and e['management_account_id'] is None and not e['levels'] and e['scp_state']==e['rcp_state']=='DISABLED'
    else:
        valid=e['organization_id'] is not None and e['management_account_id'] is not None and (e['account_id']==e['management_account_id'])==(e['membership']=='MANAGEMENT')
    if not valid: return result | {'reason':'ORGANIZATION_MEMBERSHIP_CONFLICT'}
    # Service-linked role exemption must be treated as an asserted profile, not ARN-only proof.
    context={'aws:sourcevpce':request['endpoint_id'],'aws:sourcevpc':request['vpc_id'],'aws:principalarn':request['principal_arn'],'aws:principalaccount':account,'aws:securetransport':None if request['secure_transport'] is None else str(request['secure_transport']).lower()}
    no_controls=json.loads(authorization_raw)['assertions']['no_scp_rcp']
    scp=_evaluate(e,'SCP',request,context,no_controls); rcp=_evaluate(e,'RCP',request,context,no_controls)
    statuses=[scp['status'],rcp['status']]
    if 'EXPLICIT_DENY' in statuses: status,reason='EXPLICIT_DENY_CANDIDATE','MATCHING_ASSERTED_ORGANIZATION_DENY'
    elif 'UNKNOWN' in statuses: status,reason='UNKNOWN','ORGANIZATION_CONTROL_UNCONFIRMED'
    elif 'NO_MATCHING_ALLOW' in statuses: status,reason='ORGANIZATION_BLOCKED_CANDIDATE','REQUIRED_ORGANIZATION_LEVEL_NO_ALLOW'
    elif all(x in ('ALLOW_CANDIDATE','NOT_APPLICABLE') for x in statuses): status,reason='ORGANIZATION_PASS_CANDIDATE','NO_ASSERTED_ORGANIZATION_BLOCK'
    else: status,reason='UNKNOWN','UNRESOLVED_ORGANIZATION_CONTROLS'
    return result | {'scp':scp,'rcp':rcp,'organization_status':status,'reason':reason}
