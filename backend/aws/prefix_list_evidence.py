"""Offline IPv4 prefix list evidence for SGs and opt-in route selection.

No AWS calls or proof of live state. AWS-managed S3/DynamoDB entries
use an unversioned, asserted complete matching-read profile (v2). The normalized wrapper
asserts metadata and full pagination; it is not an authenticated API export.
"""
import hashlib
import re
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network
from backend.iac.plan_adapter import _read

FORMAT = 'cloudpath-aws-prefix-lists-v1'
FORMAT_V2 = 'cloudpath-aws-prefix-lists-v2'


def _time(value):
    try:
        t = datetime.fromisoformat(value)
        if t.tzinfo is not None and t.utcoffset() is not None:
            return t
    except (ValueError, TypeError, OverflowError):
        pass
    raise ValueError('Prefix list timestamp requires timezone')


def load_prefix_lists(raw, inventory_identity, region, collected_at, *, additional_times=()):
    """Return (validated list map, public evidence summary), without mutating input.

    Invalid envelope rejected; valid but incomplete, stale, mismatched or
    unsupported records remain unresolved. Absence is never an empty list.
    """
    if raw is None:
        return {}, None
    if not isinstance(raw, bytes) or len(raw) > 5*1024*1024:
        raise ValueError('Prefix list evidence exceeds input limit or is not bytes')
    d = _read(raw)
    if set(d) != {'format','inventory_identity','region','collected_at','prefix_lists'} or d['format'] not in (FORMAT, FORMAT_V2):
        raise ValueError('Expected normalized prefix list evidence wrapper')
    t = _time(d['collected_at']); times = [t, _time(collected_at), *(_time(x) for x in additional_times)]
    rows = d['prefix_lists']
    if not isinstance(rows, list) or len(rows) > 300:
        raise ValueError('Invalid prefix list count')
    gap = (max(times)-min(times)).total_seconds()
    scope = ('PREFIX_LIST_INVENTORY_IDENTITY_MISMATCH' if d['inventory_identity'] != inventory_identity else
             'PREFIX_LIST_REGION_MISMATCH' if d['region'] != region else
             'PREFIX_LIST_SNAPSHOT_TIME_GAP' if gap > 300 else None)
    result = {}
    keys = {'id','kind','address_family','state','version_before','version_after','entries_version','complete','entries'}
    for r in rows:
        aws = isinstance(r,dict) and d['format']==FORMAT_V2 and r.get('kind')=='AWS_MANAGED'
        expected = (keys-{'version_before','version_after','entries_version'})|{'owner_id','name','entries_confirmed'} if aws else keys
        if not isinstance(r, dict) or set(r) != expected or not isinstance(r['id'], str) or not re.fullmatch(r'pl-[0-9a-f]{8,17}',r['id']):
            raise ValueError('Invalid normalized prefix list record')
        pid = r['id']
        if pid in result:
            raise ValueError('Duplicate prefix list ID')
        entries = r['entries']
        if not isinstance(entries,list) or len(entries)>1000:
            raise ValueError('Invalid prefix list entry count')
        versions = [r[k] for k in ('version_before','version_after','entries_version')] if not aws else [None]
        reason = scope
        if reason is None:
            if (not aws and r['kind'] != 'CUSTOMER_MANAGED') or r['address_family'] != 'IPv4':
                reason = 'PREFIX_LIST_PROFILE_UNSUPPORTED'
            elif r['state'] not in ('create-complete','modify-complete','restore-complete'):
                reason = 'PREFIX_LIST_STATE_UNCONFIRMED'
            elif aws and (r['owner_id']!='AWS' or r['name'] not in ('com.amazonaws.'+region+'.s3','com.amazonaws.'+region+'.dynamodb') or r['entries_confirmed'] is not True):
                reason = 'AWS_MANAGED_PREFIX_LIST_IDENTITY_UNCONFIRMED'
            elif not aws and (not all(type(v) is int and v > 0 for v in versions) or len(set(versions)) != 1):
                reason = 'PREFIX_LIST_VERSION_UNCONFIRMED'
            elif r['complete'] is not True or (aws and not entries):
                reason = 'PREFIX_LIST_ENTRIES_INCOMPLETE'
        nets = []
        if reason is None:
            try:
                if any(not isinstance(x,str) for x in entries): raise ValueError()
                nets = [IPv4Network(x, strict=True) for x in entries]
                if len(set(nets)) != len(nets): raise ValueError()
            except (ValueError,TypeError):
                reason = 'PREFIX_LIST_CIDRS_INVALID'
        result[pid] = dict(reason=reason, version=versions[0] if reason is None else None, networks=nets if reason is None else [], **({'kind':'AWS_MANAGED','name':r['name'] if reason is None else None} if aws else {}))
    summary = dict(input_identity='sha256-aws-prefix-lists-'+('v2' if d['format']==FORMAT_V2 else 'v1')+':'+hashlib.sha256(raw).hexdigest(),
                   status='UNRESOLVED' if scope else 'NORMALIZED_EVIDENCE_CANDIDATE',
                   reason=scope, time_gap_seconds=gap,
                   lists=[dict(id=k,status='UNKNOWN' if v['reason'] else 'ENTRIES_CANDIDATE',reason=v['reason'],version=v['version'], **({'kind':v['kind'],'name':v['name']} if 'kind' in v else {})) for k,v in sorted(result.items())],
                   live_observation=False)
    return result, summary


def match_prefix_list(pair, lists, ip):
    if not isinstance(pair,dict) or set(pair)!={'PrefixListId'}:
        return None, dict(reason='PREFIX_LIST_REFERENCE_UNCONFIRMED')
    pid = pair['PrefixListId']
    if not isinstance(pid,str) or pid not in lists:
        return None, dict(reason='PREFIX_LIST_EVIDENCE_MISSING')
    row = lists[pid]
    if row['reason']:
        return None, dict(prefix_list_id=pid,reason=row['reason'])
    detail=dict(prefix_list_id=pid,prefix_list_version=row['version'])
    if row.get('kind')=='AWS_MANAGED': detail.update(prefix_list_kind=row['kind'],prefix_list_name=row['name'])
    for net in row['networks']:
        if IPv4Address(ip) in net:
            return True, dict(detail,matched_cidr=str(net))
    return False, detail
