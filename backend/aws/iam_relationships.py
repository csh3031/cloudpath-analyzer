"""Offline asserted IAM relationships bound to an exact registered scenario.
No trust, credential-chain, or authorization evaluation.
"""
import re
from .iam_inventory import (register_iam_inventory, _load, _fields, _require,
                            _identity_arn, _match, _time, MAX_ROWS)

SCHEMA = 'cloudpath-iam-relationships-v1'
# Application and infrastructure roles are intentionally separate.
KINDS = {'EC2': ('INSTANCE_PROFILE',), 'ECS': ('TASK_ROLE','EXECUTION_ROLE'),
         'EKS': ('IRSA','POD_IDENTITY','NODE_ROLE','POD_EXECUTION_ROLE')}


def _label(s):
    _require(isinstance(s,str) and 0 < len(s) <= 1024 and not any(ord(c)<32 for c in s), 'Invalid workload reference')
    return s


def inspect_iam_relationships(base_raw, relation_raw, *, user_arn=None, workload=None, overlay_raw=None):
    model=register_iam_inventory(base_raw,overlay_raw)
    data=_load(relation_raw)
    _fields(data, ('schema','account_id','base_identity','overlay_identity','registered_at','complete','memberships','bindings'))
    account=model['account_id']
    _require(data['schema']==SCHEMA and data['account_id']==account and data['base_identity']==model['base_identity'] and data['overlay_identity']==model['overlay_identity'], 'Relationship scenario or account mismatch')
    _time(data['registered_at'])
    _fields(data['complete'],('memberships','bindings'))
    _require(all(type(v) is bool for v in data['complete'].values()), 'Explicit relationship completeness required')
    _require((user_arn is None)!=(workload is None),'Select exactly one user or workload')
    for c in ('memberships','bindings'):
        _require(isinstance(data[c],list) and len(data[c])<=MAX_ROWS,'Invalid relationship list')
    members=set(); bindings={}
    for row in data['memberships']:
        _fields(row,('user_arn','group_arn'))
        u,g=row['user_arn'],row['group_arn']
        _require(_identity_arn(u,account)=='user' and _identity_arn(g,account)=='group','Only users may belong to IAM groups')
        _require((u,g) not in members,'Duplicate membership'); members.add((u,g))
    for row in data['bindings']:
        _fields(row,('service','workload_ref','kind','via_ref','role_arn'))
        svc=row['service']; kind=row['kind']; ref=_label(row['workload_ref']); _label(row['via_ref'])
        _require(isinstance(svc,str) and svc in KINDS and kind in KINDS[svc],'Invalid service role kind')
        _require(_identity_arn(row['role_arn'],account)=='role','Workload must refer to a role')
        key=(svc,ref,kind); _require(key not in bindings,'Duplicate or conflicting workload binding'); bindings[key]=row
    effective=model['effective']; identities={x['record']['arn']:x['record'] for x in effective['identities']}
    policies={x['record']['ref']:x['record'] for x in effective['policies']}
    issues=[]; principals=[]; auxiliary=[]; groups=[]; selected=[]
    if model['issues']: issues.append('INVENTORY_UNRESOLVED')
    if user_arn is not None:
        _require(_identity_arn(user_arn,account)=='user','Select IAM user ARN')
        principals=[user_arn]; groups=sorted(g for u,g in members if u==user_arn)
        if not data['complete']['memberships']: issues.append('MEMBERSHIP_INCOMPLETE')
    else:
        _require(isinstance(workload,(tuple,list)) and len(workload)==2 and isinstance(workload[0],str) and workload[0] in KINDS,'Select service and workload reference')
        svc,ref=workload; _label(ref)
        selected=[bindings[k] for k in sorted(bindings) if k[:2]==(svc,ref)]
        app={'EC2':('INSTANCE_PROFILE',),'ECS':('TASK_ROLE',),'EKS':('IRSA','POD_IDENTITY')}[svc]
        candidates=[r for r in selected if r['kind'] in app]
        auxiliary=[r for r in selected if r['kind'] not in app]
        principals=sorted({r['role_arn'] for r in candidates})
        if len(candidates)!=1: issues.append('APPLICATION_ROLE_MISSING_OR_AMBIGUOUS')
        if not data['complete']['bindings']: issues.append('BINDINGS_INCOMPLETE')
    for arn in principals+groups+[r['role_arn'] for r in auxiliary]:
        if arn not in identities: issues.append('IDENTITY_REFERENCE_UNRESOLVED')
    rows=[]; boundaries=[]
    for item in effective['attachments']:
        r=item['record']; arn=r['identity_arn']
        if arn not in principals+groups: continue
        entry={'identity_arn':arn,'policy_ref':r['policy_ref'],'origin':item['origin'],
               'relationship':'GROUP_INHERITED' if arn in groups else 'DIRECT'}
        if r['policy_ref'] not in policies: issues.append('POLICY_REFERENCE_UNRESOLVED')
        if r['kind']=='PERMISSIONS_BOUNDARY': boundaries.append(entry)
        else: rows.append(entry)
    return {'schema':'cloudpath-iam-relationship-result-v1','base_identity':model['base_identity'],
            'overlay_identity':model['overlay_identity'],'effective_mode':model['effective_mode'],
            'relationship_status':'UNKNOWN' if issues else 'CONFIGURATION_CANDIDATE',
            'principal_candidates':principals,'groups':groups,'policy_candidates':rows,
            'boundary_candidates':boundaries,'workload_bindings':selected,'auxiliary_bindings':auxiliary,
            'issues':sorted(set(issues)),'authorization_status':'NOT_EVALUATED',
            'runtime_identity_status':'UNKNOWN','api_status':'UNKNOWN','live_observation':False,
            'limitations':['Normalized assertions, not authenticated AWS evidence. via_ref is asserted, not independently joined to raw service records.',
                           'No trust or runtime credential-chain proof, no group or binding overlay operations, no cross-account resolution.',
                           'Policy candidates are not effective permissions. Auxiliary roles never grant application policy candidates.']}
