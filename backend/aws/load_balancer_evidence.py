"""Offline ELBv2 listener/default-action configuration evidence, not a forwarding verdict."""
import hashlib
import re
from backend.aws.peering_evidence import _load, _timestamp
from backend.iac.plan_adapter import _read

FORMAT = 'cloudpath-elbv2-evidence-v1'
ARN = re.compile(r'arn:aws:elasticloadbalancing:([a-z0-9-]+):([0-9]{12}):(loadbalancer/(?:app|net)/[A-Za-z0-9-]+/[0-9a-f]{16}|listener/(?:app|net)/[A-Za-z0-9-]+/[0-9a-f]{16}/[0-9a-f]{16}|targetgroup/[A-Za-z0-9-]+/[0-9a-f]{16})')


def _arn(value, kind):
    match = ARN.fullmatch(value) if isinstance(value, str) else None
    if not match or not match[3].startswith(kind + '/'):
        raise ValueError('Invalid ELBv2 ARN')
    return match.groups()


def _rows(rows, field, kind):
    if not isinstance(rows, list) or len(rows) > 300:
        raise ValueError('Invalid ELBv2 evidence list')
    indexed = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Invalid ELBv2 evidence row')
        key = row.get(field)
        _arn(key, kind)
        if key in indexed:
            raise ValueError('Duplicate ELBv2 ARN')
        indexed[key] = row
    return indexed


def _port(value):
    return type(value) is int and 1 <= value <= 65535


def _id(arn):
    return arn.rsplit('/', 1)[-1]


def inspect_load_balancer(inventory_raw, evidence_raw, load_balancer_id, listener_port):
    """Inspect one LB/listener and its default forward configuration. Never select a target."""
    if not isinstance(load_balancer_id, str) or not re.fullmatch(r'[0-9a-f]{16}', load_balancer_id) or not _port(listener_port):
        raise ValueError('Invalid load balancer ID or listener port')
    identity, meta, inventory = _load(inventory_raw)
    doc = _read(evidence_raw)
    if not isinstance(doc, dict) or set(doc) != {'format','collected_at','LoadBalancers','Listeners','TargetGroups'} or doc['format'] != FORMAT:
        raise ValueError('Expected dated ELBv2 evidence wrapper')
    gap = abs((_timestamp(doc['collected_at']) - _timestamp(meta['collected_at'])).total_seconds())
    lbs = _rows(doc['LoadBalancers'], 'LoadBalancerArn', 'loadbalancer')
    listeners = _rows(doc['Listeners'], 'ListenerArn', 'listener')
    groups = _rows(doc['TargetGroups'], 'TargetGroupArn', 'targetgroup')
    result = dict(analysis_type='STATIC_AWS_ELBV2_CONFIGURATION', input_identity=identity,
                  elbv2_input_identity='sha256-elbv2-v1:'+hashlib.sha256(evidence_raw).hexdigest(),
                  region=meta['region'], vpc_id=meta['vpc_id'], time_gap_seconds=gap,
                  load_balancer_id=load_balancer_id, listener_port=listener_port,
                  load_balancer=None, listener=None, default_target_groups=[],
                  rule_selection='NOT_EVALUATED', target_selection='NOT_EVALUATED',
                  target_health='NOT_EVALUATED', policy_status='NOT_EVALUATED',
                  session_status='UNKNOWN', live_observation=False,
                  limitations=['Offline unauthenticated snapshots; 300s time proximity is heuristic only.',
                               'Default action configuration is not effective rule selection or target registration.',
                               'No DNS, listener rule matching, TLS, address processing, health, SG/NACL or runtime checks.',
                               'IPv4 ALB HTTP/HTTPS and NLB TCP/TLS, same VPC instance/ip target groups only.',
                               'No AWS API calls or packet transmission.'])
    def finish(reason, status='UNKNOWN'):
        return dict(result, status=status, reason=reason)
    if gap > 300:
        return finish('SNAPSHOT_TIME_GAP')
    matches = [arn for arn in lbs if _id(arn) == load_balancer_id]
    if len(matches) != 1:
        return finish('LOAD_BALANCER_MISSING_OR_AMBIGUOUS')
    arn = matches[0]; lb = lbs[arn]; region, account, resource = _arn(arn,'loadbalancer')
    kind = lb.get('Type')
    if region != meta['region'] or lb.get('VpcId') != meta['vpc_id']:
        return finish('LOAD_BALANCER_SCOPE_MISMATCH')
    if kind not in ('application','network') or resource.split('/')[1] != {'application':'app','network':'net'}[kind]:
        return finish('UNSUPPORTED_LOAD_BALANCER_TYPE')
    if lb.get('IpAddressType') != 'ipv4' or lb.get('Scheme') not in ('internal','internet-facing'):
        return finish('UNSUPPORTED_ADDRESS_OR_SCHEME')
    if not isinstance(lb.get('State'),dict) or lb['State'].get('Code') != 'active':
        return finish('LOAD_BALANCER_NOT_CONFIRMED_ACTIVE')
    subnets = {s['SubnetId']:s for s in inventory['Subnets']}
    zones = lb.get('AvailabilityZones')
    if not isinstance(zones,list) or not 1 <= len(zones) <= 100:
        return finish('LOAD_BALANCER_SUBNETS_UNCONFIRMED')
    mapped = []; seen = set()
    for z in zones:
        if not isinstance(z,dict) or not isinstance(z.get('SubnetId'),str) or not isinstance(z.get('ZoneName'),str):
            return finish('LOAD_BALANCER_SUBNETS_UNCONFIRMED')
        sid, az = z['SubnetId'], z['ZoneName']; subnet = subnets.get(sid)
        if not subnet or subnet.get('VpcId') != meta['vpc_id'] or subnet.get('State') != 'available' or subnet.get('AvailabilityZone') != az or az in seen:
            return finish('LOAD_BALANCER_SUBNETS_UNCONFIRMED')
        seen.add(az); mapped.append({'subnet_id':sid,'availability_zone':az})
    if kind == 'application' and len(mapped) < 2:
        return finish('ALB_MULTI_AZ_UNCONFIRMED')
    result['load_balancer'] = dict(type=kind, scheme=lb['Scheme'], address_type='ipv4', subnets=mapped)
    selected = [(a,l) for a,l in listeners.items() if l.get('LoadBalancerArn') == arn and type(l.get('Port')) is int and l['Port'] == listener_port]
    if len(selected) != 1:
        return finish('LISTENER_MISSING_OR_AMBIGUOUS')
    la, listener = selected[0]
    lr, ac, res = _arn(la,'listener')
    if (lr,ac) != (region,account) or res.rsplit('/',1)[0] != resource.replace('loadbalancer/','listener/',1):
        return finish('LISTENER_PARENT_MISMATCH')
    protocol = listener.get('Protocol')
    if protocol not in ({'application':('HTTP','HTTPS'),'network':('TCP','TLS')}[kind]):
        return finish('UNSUPPORTED_LISTENER_PROTOCOL')
    result['listener'] = dict(id=_id(la), protocol=protocol, port=listener_port)
    actions = listener.get('DefaultActions')
    if not isinstance(actions,list) or len(actions)!=1 or not isinstance(actions[0],dict):
        return finish('DEFAULT_ACTION_CHAIN_UNSUPPORTED')
    action = actions[0]
    if action.get('Type') != 'forward':
        return finish('DEFAULT_ACTION_NOT_FORWARD')
    refs = []
    if 'ForwardConfig' in action:
        fc = action['ForwardConfig']; rows = fc.get('TargetGroups') if isinstance(fc,dict) else None
        if not isinstance(rows,list) or not 1 <= len(rows) <= 5:
            return finish('FORWARD_CONFIG_UNCONFIRMED')
        for row in rows:
            if not isinstance(row,dict) or not isinstance(row.get('TargetGroupArn'),str):
                return finish('FORWARD_CONFIG_UNCONFIRMED')
            w = row.get('Weight')
            if w is not None and (type(w) is not int or not 0 <= w <= 999):
                return finish('FORWARD_WEIGHT_INVALID')
            refs.append((row['TargetGroupArn'],w))
        if 'TargetGroupArn' in action and (len(refs)!=1 or action['TargetGroupArn']!=refs[0][0]):
            return finish('FORWARD_REFERENCES_CONFLICT')
    elif isinstance(action.get('TargetGroupArn'),str):
        refs=[(action['TargetGroupArn'],None)]
    else:
        return finish('FORWARD_CONFIG_UNCONFIRMED')
    if len({a for a,w in refs}) != len(refs):
        return finish('DUPLICATE_TARGET_GROUP_REFERENCE')
    if all(w == 0 for a,w in refs):
        return finish('NO_POSITIVE_FORWARD_WEIGHT')
    pending=[]
    for ga,w in refs:
        gr,gac,_ = _arn(ga,'targetgroup'); group=groups.get(ga)
        if not group or (gr,gac)!=(region,account) or group.get('VpcId')!=meta['vpc_id'] or group.get('LoadBalancerArns')!=[arn]:
            return finish('TARGET_GROUP_LINK_UNCONFIRMED')
        gp=group.get('Protocol'); gt=group.get('TargetType')
        allowed = ('HTTP','HTTPS') if kind=='application' else ('TCP',) if protocol=='TCP' else ('TCP','TLS')
        if gp not in allowed or gt not in ('instance','ip') or not _port(group.get('Port')) or group.get('IpAddressType','ipv4')!='ipv4':
            return finish('UNSUPPORTED_TARGET_GROUP_CONFIGURATION')
        pending.append(dict(id=_id(ga), protocol=gp, port=group['Port'], target_type=gt, configured_weight=w))
    result['default_target_groups']=pending
    return finish('OBSERVED_DEFAULT_FORWARD_CONFIGURATION','DEFAULT_FORWARD_CONFIG_CANDIDATE')
