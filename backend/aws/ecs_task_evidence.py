"""Bounded offline ECS awsvpc task-to-ENI identity correlation, not a path verdict."""
import hashlib
import re
from ipaddress import IPv4Address, IPv4Network
from backend.aws.peering_evidence import _load, _timestamp, _primary_only
from backend.iac.plan_adapter import _read

FORMAT = 'cloudpath-ecs-task-evidence-v1'
TASK_ARN = re.compile(r'arn:aws:ecs:([a-z0-9-]+):([0-9]{12}):task/([A-Za-z0-9_-]+)/([0-9a-f]{32})')
DEF_ARN = re.compile(r'arn:aws:ecs:([a-z0-9-]+):([0-9]{12}):task-definition/([A-Za-z0-9_-]+):([1-9][0-9]*)')


def _rows(value):
    if not isinstance(value, list) or len(value) > 300 or any(not isinstance(x, dict) for x in value):
        raise ValueError('Invalid ECS evidence rows')
    return value


def _index(rows, key, pattern):
    result = {}
    for row in _rows(rows):
        arn = row.get(key)
        if not isinstance(arn, str) or not pattern.fullmatch(arn) or arn in result:
            raise ValueError('Invalid or duplicate ECS ARN')
        result[arn] = row
    return result


def inspect_ecs_task(inventory_raw, ecs_raw, task_id):
    """Correlate one RUNNING Fargate or EC2 awsvpc task and its primary IPv4 ENI."""
    if not isinstance(task_id, str) or not re.fullmatch(r'[0-9a-f]{32}', task_id):
        raise ValueError('Expected 32-character lowercase ECS task ID')
    identity, meta, inv = _load(inventory_raw)
    doc = _read(ecs_raw)
    if set(doc) != {'format','collected_at','tasks','taskDefinitions'} or doc['format'] != FORMAT:
        raise ValueError('Expected normalized dated ECS evidence wrapper')
    gap = abs((_timestamp(doc['collected_at']) - _timestamp(meta['collected_at'])).total_seconds())
    tasks = _index(doc['tasks'], 'taskArn', TASK_ARN)
    defs = _index(doc['taskDefinitions'], 'taskDefinitionArn', DEF_ARN)
    result = dict(analysis_type='STATIC_AWS_ECS_TASK_ENDPOINT', input_identity=identity,
                  ecs_input_identity='sha256-ecs-task-v1:'+hashlib.sha256(ecs_raw).hexdigest(),
                  region=meta['region'], vpc_id=meta['vpc_id'], task_id=task_id, time_gap_seconds=gap,
                  endpoint=None, route_status='NOT_EVALUATED', policy_status='NOT_EVALUATED',
                  session_status='UNKNOWN', live_observation=False,
                  limitations=['Offline unauthenticated snapshots; time proximity is heuristic only.',
                               'Running EC2/Fargate awsvpc tasks with one attached primary IPv4 ENI only.',
                               'No account attestation, container port, service, EKS, or runtime verification.',
                               'No routing, policy, AWS API calls or packets.'])
    def unknown(reason):
        return dict(result, status='UNKNOWN', reason=reason)
    if gap > 300:
        return unknown('SNAPSHOT_TIME_GAP')
    candidates = [a for a in tasks if a.rsplit('/',1)[-1] == task_id]
    if len(candidates) != 1:
        return unknown('TASK_MISSING_OR_AMBIGUOUS')
    arn = candidates[0]; task = tasks[arn]; region, account, cluster, _ = TASK_ARN.fullmatch(arn).groups()
    if region != meta['region'] or task.get('clusterArn') != f'arn:aws:ecs:{region}:{account}:cluster/{cluster}':
        return unknown('TASK_SCOPE_MISMATCH')
    if task.get('lastStatus') != 'RUNNING' or task.get('desiredStatus') != 'RUNNING':
        return unknown('TASK_NOT_RUNNING')
    launch = task.get('launchType')
    if launch not in ('EC2','FARGATE'):
        return unknown('UNSUPPORTED_LAUNCH_TYPE')
    da = task.get('taskDefinitionArn')
    definition = defs.get(da) if isinstance(da,str) else None
    if not definition or DEF_ARN.fullmatch(da).groups()[:2] != (region, account):
        return unknown('TASK_DEFINITION_UNCONFIRMED')
    if definition.get('networkMode') != 'awsvpc':
        return unknown('UNSUPPORTED_NETWORK_MODE')
    attachments = [a for a in _rows(task.get('attachments',[])) if a.get('type') == 'ElasticNetworkInterface']
    if len(attachments) != 1 or attachments[0].get('status') != 'ATTACHED':
        return unknown('TASK_ENI_ATTACHMENT_UNCONFIRMED')
    details = {}
    for d in _rows(attachments[0].get('details',[])):
        name, value = d.get('name'), d.get('value')
        if not isinstance(name,str) or not isinstance(value,str) or name in details:
            return unknown('TASK_ENI_DETAILS_AMBIGUOUS')
        details[name] = value
    eid, sid, ip = (details.get(k) for k in ('networkInterfaceId','subnetId','privateIPv4Address'))
    if not all(isinstance(x,str) for x in (eid,sid,ip)):
        return unknown('TASK_ENI_DETAILS_MISSING')
    try:
        address = IPv4Address(ip)
    except ValueError:
        return unknown('TASK_IPV4_INVALID')
    # Never infer a second task from the same ENI in the supplied evidence.
    for other_arn, other in tasks.items():
        if other_arn == arn:
            continue
        for att in _rows(other.get('attachments',[])):
            if att.get('type') == 'ElasticNetworkInterface' and any(d.get('name') == 'networkInterfaceId' and d.get('value') == eid for d in _rows(att.get('details',[]))):
                return unknown('TASK_ENI_SHARED_OR_STALE')
    vpc = inv['Vpcs'][0]
    if not _primary_only(vpc) or address not in IPv4Network(vpc['CidrBlock']):
        return unknown('PRIMARY_VPC_CIDR_UNCONFIRMED')
    subnets = [s for s in inv['Subnets'] if s.get('SubnetId') == sid]
    if len(subnets) != 1 or subnets[0].get('State') != 'available' or address not in IPv4Network(subnets[0]['CidrBlock']):
        return unknown('TASK_SUBNET_UNCONFIRMED')
    subnet = subnets[0]
    az = subnet.get('AvailabilityZone')
    if not isinstance(az,str) or task.get('availabilityZone') != az:
        return unknown('TASK_AZ_UNCONFIRMED')
    enis = [e for e in inv['NetworkInterfaces'] if e.get('NetworkInterfaceId') == eid]
    if len(enis) != 1:
        return unknown('INVENTORY_ENI_UNCONFIRMED')
    eni = enis[0]
    if eni.get('SubnetId') != sid or eni.get('VpcId') != meta['vpc_id'] or eni.get('PrivateIpAddress') != ip:
        return unknown('TASK_ENI_IDENTITY_MISMATCH')
    if eni.get('Status') != 'in-use' or eni.get('InterfaceType') != 'interface' or eni.get('RequesterManaged') is not True:
        return unknown('TASK_ENI_STATE_UNCONFIRMED')
    # V1 does not preserve the Primary marker; require one unambiguous IPv4 entry.
    ips = eni.get('PrivateIpAddresses',[])
    if len(ips) != 1 or ips[0].get('PrivateIpAddress') != ip or ips[0].get('Primary') is False:
        return unknown('TASK_PRIMARY_IPV4_UNCONFIRMED')
    if any(e.get('NetworkInterfaceId') != eid and (e.get('PrivateIpAddress') == ip or any(p.get('PrivateIpAddress') == ip for p in e.get('PrivateIpAddresses',[]))) for e in inv['NetworkInterfaces']):
        return unknown('TASK_IPV4_AMBIGUOUS')
    instances = [i for r in inv['Reservations'] for i in r['Instances']]
    hosts = [i for i in instances if any(e.get('NetworkInterfaceId') == eid for e in i.get('NetworkInterfaces',[]))]
    attachment = eni.get('Attachment',{})
    if any(i.get('PrivateIpAddress') == ip for i in instances):
        return unknown('EC2_PRIMARY_OR_HOST_OWNERSHIP_CONFLICT')
    if any(a.get('NetworkInterfaceId') == eid for n in inv['NatGateways'] for a in n.get('NatGatewayAddresses',[])):
        return unknown('NAT_ENI_OWNERSHIP_CONFLICT')
    if launch == 'FARGATE':
        if hosts or attachment.get('InstanceId') is not None:
            return unknown('EC2_PRIMARY_OR_HOST_OWNERSHIP_CONFLICT')
    else:
        # Only ordinary directly attached EC2 task ENIs, not trunk/branch mode.
        if (len(hosts) != 1 or hosts[0].get('InstanceId') != attachment.get('InstanceId')
                or hosts[0].get('State',{}).get('Name') != 'running'
                or type(attachment.get('DeviceIndex')) is not int or attachment['DeviceIndex'] < 1):
            return unknown('EC2_PRIMARY_OR_HOST_OWNERSHIP_CONFLICT')
    sg_ids = [g.get('GroupId') for g in eni.get('Groups',[])]
    known = {g['GroupId'] for g in inv['SecurityGroups']}
    if not sg_ids or len(set(sg_ids)) != len(sg_ids) or not set(sg_ids).issubset(known):
        return unknown('TASK_SECURITY_GROUPS_UNCONFIRMED')
    result['endpoint'] = dict(kind='ECS_TASK', launch_type=launch, network_mode='awsvpc',
                              subnet_id=sid, eni_id=eid, private_ip=ip, availability_zone=az,
                              security_group_ids=sorted(sg_ids))
    return dict(result,status='TASK_ENDPOINT_CANDIDATE',reason='MATCHED_TASK_AND_INVENTORY_ENI')
