"""Offline normalized IAM registration and isolated what-if overlay; no permission verdict."""
import copy
import hashlib
import json
import re
from datetime import datetime

MAX_BYTES = 5 * 1024 * 1024
MAX_ROWS = 4096
SCHEMA = 'cloudpath-iam-inventory-v1'
OVERLAY = 'cloudpath-iam-overlay-v1'
COLLECTIONS = ('identities', 'policies', 'attachments')
ACCOUNT = re.compile(r'[0-9]{12}')
IDENTITY = re.compile(r'arn:aws:iam::([0-9]{12}):(user|role|group)/[A-Za-z0-9_+=,.@/-]{1,512}')
POLICY = re.compile(r'arn:aws:iam::(aws|[0-9]{12}):policy/[A-Za-z0-9_+=,.@/-]{1,512}')
NAME = re.compile(r'[A-Za-z0-9_+=,.@-]{1,128}')
VERSION = re.compile(r'v[1-9][0-9]{0,9}')
SOURCE = {'OBSERVED': 'AWS_SNAPSHOT', 'PLANNED': 'TERRAFORM', 'HYPOTHETICAL': 'MANUAL'}


def _require(ok, message):
    if not ok:
        raise ValueError(message)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, 'Duplicate JSON member')
        result[key] = value
    return result


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def _digest(value):
    return 'sha256-iam-inventory-v1:' + hashlib.sha256(_canonical(value).encode()).hexdigest()


def _load(raw):
    _require(isinstance(raw, bytes) and len(raw) <= MAX_BYTES, 'Expected JSON bytes up to 5 MiB')
    try:
        return json.loads(raw, object_pairs_hook=_pairs,
                          parse_constant=lambda _: _require(False, 'Invalid JSON constant'))
    except (UnicodeError, RecursionError) as exc:
        raise ValueError('Invalid or excessively nested JSON') from exc


def _fields(value, names):
    _require(isinstance(value, dict) and set(value) == set(names), 'Invalid IAM registration fields')


def _match(pattern, value):
    return pattern.fullmatch(value) if isinstance(value, str) else None


def _time(value):
    _require(isinstance(value, str) and len(value) <= 40, 'Invalid registration time')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError('Invalid registration time') from exc
    _require(parsed.utcoffset() is not None and 'T' in value, 'Timezone-aware registration time required')


def _identity_arn(value, account):
    m = _match(IDENTITY, value)
    _require(m and m[1] == account, 'Invalid or out-of-account IAM identity ARN')
    return m[2]


def _managed_arn(value, account):
    m = _match(POLICY, value)
    _require(m and m[1] in (account, 'aws'), 'Invalid or out-of-account managed policy ARN')


def _policy_ref(value, account):
    _require(isinstance(value, str) and len(value) <= 900, 'Invalid policy reference')
    if value.startswith('inline:'):
        owner, sep, name = value[7:].rpartition('#')
        _require(sep and _match(NAME, name), 'Invalid inline policy reference')
        _identity_arn(owner, account)
    else:
        _managed_arn(value, account)


def _record(collection, row, account):
    if collection == 'identities':
        _fields(row, ('arn', 'kind', 'unique_id'))
        kind = _identity_arn(row['arn'], account)
        _require(row['kind'] == kind.upper(), 'Identity kind does not match ARN')
        prefix = {'user':'AIDA','role':'AROA','group':'AGPA'}[kind]
        uid = row['unique_id']
        _require(uid is None or _match(re.compile(prefix+r'[A-Z0-9]{8,64}'), uid), 'Invalid identity unique ID')
        return row['arn']
    if collection == 'policies':
        _fields(row, ('ref', 'kind', 'owner_arn', 'policy_id', 'default_version', 'document_version', 'document'))
        ref = row['ref']; _policy_ref(ref, account)
        if row['kind'] == 'INLINE':
            _require(ref.startswith('inline:') and ref[7:].rpartition('#')[0] == row['owner_arn'], 'Inline policy owner mismatch')
            _require(all(row[k] is None for k in ('policy_id','default_version','document_version')), 'Inline policy cannot have managed policy metadata')
        else:
            _require(row['kind'] == 'MANAGED' and not ref.startswith('inline:') and row['owner_arn'] is None, 'Invalid managed policy record')
            _require(row['policy_id'] is None or _match(re.compile(r'ANPA[A-Z0-9]{8,64}'), row['policy_id']), 'Invalid managed policy ID')
            for k in ('default_version','document_version'):
                _require(row[k] is None or _match(VERSION,row[k]), 'Invalid managed policy version')
        doc = row['document']
        _require(doc is None or (isinstance(doc, dict) and len(_canonical(doc)) <= 65536), 'Invalid or oversized policy document')
        return ref
    _fields(row, ('identity_arn','policy_ref','kind'))
    kind = _identity_arn(row['identity_arn'], account)
    ref = row['policy_ref']; _policy_ref(ref, account)
    _require(row['kind'] in ('IDENTITY_POLICY','PERMISSIONS_BOUNDARY'), 'Invalid attachment kind')
    if ref.startswith('inline:'):
        _require(row['kind']=='IDENTITY_POLICY' and ref[7:].rpartition('#')[0]==row['identity_arn'], 'Inline attachment owner mismatch')
    if row['kind']=='PERMISSIONS_BOUNDARY':
        _require(kind!='group', 'Group cannot have a permissions boundary')
    return (row['identity_arn'], row['kind'], ref)


def _check_base(base):
    _fields(base, ('schema','account_id','layer','source','registered_at','complete',*COLLECTIONS))
    _require(base['schema']==SCHEMA, 'Invalid inventory schema')
    account=base['account_id']; _require(_match(ACCOUNT,account),'Invalid account ID')
    _require(isinstance(base['layer'],str) and SOURCE.get(base['layer']) == base['source'] and base['layer'] in SOURCE,'Invalid source/layer combination')
    _time(base['registered_at'])
    _fields(base['complete'], COLLECTIONS)
    _require(all(type(x) is bool for x in base['complete'].values()),'Explicit completeness flags required')
    tables={}
    for c in COLLECTIONS:
        rows=base[c]; _require(isinstance(rows,list) and len(rows)<=MAX_ROWS,'Invalid or oversized registration list')
        table={}
        for row in rows:
            key=_record(c,row,account); _require(key not in table,'Duplicate registration record')
            table[key]=copy.deepcopy(row)
        tables[c]=table
    return tables


def _overlay_key(collection, key, account):
    if collection=='identities':
        _identity_arn(key,account); return key
    if collection=='policies':
        _policy_ref(key,account); return key
    _require(isinstance(key,list) and len(key)==3,'Invalid attachment key')
    return _record(collection,dict(zip(('identity_arn','kind','policy_ref'),key)),account)


def _apply(tables, overlay, base, provenance):
    _fields(overlay, ('schema','account_id','base_identity','registered_at','operations'))
    _require(overlay['schema']==OVERLAY and overlay['account_id']==base['account_id'] and overlay['base_identity']==_digest(base),'Overlay base or account mismatch')
    _time(overlay['registered_at'])
    ops=overlay['operations']; _require(isinstance(ops,list) and len(ops)<=MAX_ROWS,'Invalid or oversized overlay operations')
    seen=set()
    for op in ops:
        _fields(op, ('operation','collection','key','record'))
        c=op['collection']; _require(c in COLLECTIONS,'Invalid overlay collection')
        key=_overlay_key(c,op['key'],base['account_id']); marker=(c,key)
        _require(marker not in seen,'Duplicate overlay target'); seen.add(marker)
        if op['operation']=='UPSERT':
            _require(_record(c,op['record'],base['account_id'])==key,'Overlay record key mismatch')
            tables[c][key]=copy.deepcopy(op['record']); provenance[c][key]='HYPOTHETICAL'
        elif op['operation']=='DELETE':
            _require(op['record'] is None and key in tables[c],'Invalid overlay deletion')
            del tables[c][key]; del provenance[c][key]
        else:
            raise ValueError('Invalid overlay operation')
    _require(all(len(t)<=MAX_ROWS for t in tables.values()), 'Effective inventory too large')


def register_iam_inventory(base_raw, overlay_raw=None):
    """Return an effective copy with explicit origins; never infer absence or authorization."""
    base=_load(base_raw); tables=_check_base(base)
    origins={c:{k:base['layer'] for k in tables[c]} for c in COLLECTIONS}
    overlay=None
    if overlay_raw is not None:
        overlay=_load(overlay_raw); _apply(tables,overlay,base,origins)
    issues=[]
    identities,policies,attachments=(tables[c] for c in COLLECTIONS)
    boundaries={}
    for key,row in attachments.items():
        principal,kind,ref=key
        if principal not in identities: issues.append({'code':'IDENTITY_REFERENCE_UNRESOLVED','key':list(key)})
        if ref not in policies: issues.append({'code':'POLICY_REFERENCE_UNRESOLVED','key':list(key)})
        if kind=='PERMISSIONS_BOUNDARY': boundaries.setdefault(principal,[]).append(ref)
    for principal,refs in boundaries.items():
        if len(refs)>1: issues.append({'code':'MULTIPLE_BOUNDARIES','key':principal})
    for key,row in policies.items():
        if row['kind']=='INLINE' and row['owner_arn'] not in identities: issues.append({'code':'INLINE_OWNER_UNRESOLVED','key':key})
        if row['document'] is None: issues.append({'code':'POLICY_DOCUMENT_UNRESOLVED','key':key})
        if row['kind']=='MANAGED' and row['policy_id'] is None: issues.append({'code':'MANAGED_POLICY_ID_UNRESOLVED','key':key})
        if row['kind']=='MANAGED' and (row['default_version'] is None or row['default_version']!=row['document_version']): issues.append({'code':'MANAGED_DEFAULT_VERSION_UNCONFIRMED','key':key})
    for key,row in identities.items():
        if row['unique_id'] is None: issues.append({'code':'IDENTITY_UNIQUE_ID_UNRESOLVED','key':key})
    for c in COLLECTIONS:
        if not base['complete'][c]: issues.append({'code':'COLLECTION_INCOMPLETE','key':c})
    effective={c:[{'record':tables[c][k],'origin':origins[c][k]} for k in sorted(tables[c])] for c in COLLECTIONS}
    # A bounded combined model matters for future web callers as well as CLI users.
    _require(len(_canonical(effective).encode())<=MAX_BYTES,'Effective model exceeds 5 MiB')
    return {'schema':'cloudpath-iam-registration-result-v1','account_id':base['account_id'],
            'base_layer':base['layer'],'base_source':base['source'],'base_registered_at':base['registered_at'],
            'base_identity':_digest(base),'overlay_identity':None if overlay is None else 'sha256-iam-overlay-v1:'+hashlib.sha256(_canonical(overlay).encode()).hexdigest(),
            'overlay_registered_at':None if overlay is None else overlay['registered_at'],
            'effective_layer':'EFFECTIVE','effective_mode':'BASE_ONLY' if overlay is None else 'WHAT_IF',
            'base_completeness_asserted':copy.deepcopy(base['complete']), 'effective_completeness':'NOT_ATTESTED',
            'counts':{c:len(tables[c]) for c in COLLECTIONS}, 'issues':issues,
            'registration_status':'UNRESOLVED_REFERENCES_OR_EVIDENCE' if issues else 'REGISTERED_CANDIDATE',
            'effective':effective,'authorization_status':'NOT_EVALUATED','api_status':'UNKNOWN',
            'live_observation':False,'limitations':['Normalized submitted assertions only; source labels and completeness are not authenticated.',
            'No group membership, workload binding, session evaluation, raw AWS or Terraform adapter, or live collection in this phase.',
            'Policy documents are stored as structured input, not validated for IAM semantics. No inferred permission or absence.']}
