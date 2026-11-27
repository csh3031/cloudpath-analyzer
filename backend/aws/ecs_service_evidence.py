"""Offline correlation of ECS service, selected ELB group, IP registration and task ENI."""
import hashlib
import re
from ipaddress import IPv4Address
from backend.aws.ecs_task_evidence import inspect_ecs_task, _index, _rows, TASK_ARN, DEF_ARN
from backend.aws.elb_target_evidence import inspect_elb_targets
from backend.aws.load_balancer_evidence import _arn, _id, _port
from backend.aws.peering_evidence import _load, _timestamp
from backend.iac.plan_adapter import _read

FORMAT = 'cloudpath-ecs-service-evidence-v1'
SERVICE_ARN = re.compile(r'arn:aws:ecs:([a-z0-9-]+):([0-9]{12}):service/([A-Za-z0-9_-]+)/([A-Za-z0-9_-]+)')


def inspect_ecs_service(inventory_raw, ecs_raw, service_raw, elbv2_raw, health_raw,
                        service_arn, load_balancer_id, listener_port, client_ip, *,
                        rules_raw=None, host=None, path=None, attributes_raw=None):
    """Bounded single-group, current-revision correlation; never a forwarding verdict."""
    if not isinstance(service_arn,str) or not SERVICE_ARN.fullmatch(service_arn):
        raise ValueError('Expected full ECS service ARN')
    region, account, cluster, name = SERVICE_ARN.fullmatch(service_arn).groups()
    identity, meta, _ = _load(inventory_raw)
    ecs = _read(ecs_raw); service = _read(service_raw); elb = _read(elbv2_raw)
    if set(ecs) != {'format','collected_at','tasks','taskDefinitions'} or ecs['format'] != 'cloudpath-ecs-task-evidence-v1':
        raise ValueError('Expected ECS task evidence')
    if set(service) != {'format','collected_at','complete','ecs_input_identity','services'} or service['format'] != FORMAT:
        raise ValueError('Expected ECS service evidence')
    tasks = _index(ecs['tasks'],'taskArn',TASK_ARN)
    definitions = _index(ecs['taskDefinitions'],'taskDefinitionArn',DEF_ARN)
    services = _index(service['services'],'serviceArn',SERVICE_ARN)
    ecs_identity = 'sha256-ecs-task-v1:'+hashlib.sha256(ecs_raw).hexdigest()
    out = dict(analysis_type='STATIC_AWS_ECS_SERVICE_ELB_CORRELATION',input_identity=identity,
               ecs_input_identity=ecs_identity,service_input_identity='sha256-ecs-service-v1:'+hashlib.sha256(service_raw).hexdigest(),
               service_arn=service_arn,region=meta['region'],vpc_id=meta['vpc_id'],
               service_binding=None,elb_analysis=None,registrations=[],tasks=[],time_gap_seconds=None,
               target_selection='NOT_EVALUATED',policy_status='NOT_EVALUATED',session_status='UNKNOWN',live_observation=False,
               limitations=['Offline unauthenticated snapshots; completeness asserted only.',
                            'Single ECS service current task definition and single IP target group; rolling revisions, blue/green, and multi-group selection not modeled.',
                            'Primary IPv4 single ENI running awsvpc tasks only; health snapshot is not delivery eligibility.',
                            'Registration correlation only; no ELB-to-task policy/path, DNS, container listener or actual target selection verified.',
                            'No AWS API calls or packet transmission.'])
    def finish(reason,status='UNKNOWN'): return dict(out,status=status,reason=reason)
    if service['complete'] is not True or service['ecs_input_identity'] != ecs_identity:
        return finish('SERVICE_COMPLETENESS_OR_IDENTITY_UNCONFIRMED')
    times=[_timestamp(x.get('collected_at')) for x in (meta,ecs,service,elb,_read(health_raw))]
    for raw in (rules_raw,attributes_raw):
        if raw is not None: times.append(_timestamp(_read(raw).get('collected_at')))
    out['time_gap_seconds']=(max(times)-min(times)).total_seconds()
    if out['time_gap_seconds']>300: return finish('SNAPSHOT_TIME_GAP')
    s=services.get(service_arn); cluster_arn=f'arn:aws:ecs:{region}:{account}:cluster/{cluster}'
    if not s or region!=meta['region'] or s.get('clusterArn')!=cluster_arn or s.get('serviceName')!=name:
        return finish('SERVICE_SCOPE_UNCONFIRMED')
    if s.get('status')!='ACTIVE' or s.get('deploymentController')!={'type':'ECS'} or s.get('schedulingStrategy')!='REPLICA':
        return finish('SERVICE_DEPLOYMENT_SCOPE_UNSUPPORTED')
    da=s.get('taskDefinition'); definition=definitions.get(da) if isinstance(da,str) else None
    if not definition or DEF_ARN.fullmatch(da).groups()[:2]!=(region,account) or definition.get('networkMode')!='awsvpc':
        return finish('SERVICE_TASK_DEFINITION_UNCONFIRMED')
    bindings=_rows(s.get('loadBalancers',[]))
    if len(bindings)!=1 or set(bindings[0])!={'targetGroupArn','containerName','containerPort'}:
        return finish('SERVICE_SINGLE_TARGET_GROUP_REQUIRED')
    b=bindings[0]; tg=b['targetGroupArn']; container=b['containerName']; port=b['containerPort']
    if _arn(tg,'targetgroup')[:2]!=(region,account) or not isinstance(container,str) or not container or not _port(port):
        return finish('SERVICE_BINDING_UNCONFIRMED')
    containers=[c for c in _rows(definition.get('containerDefinitions',[])) if c.get('name')==container]
    if len(containers)!=1: return finish('CONTAINER_DEFINITION_UNCONFIRMED')
    mappings=[m for m in _rows(containers[0].get('portMappings',[])) if type(m.get('containerPort')) is int and m['containerPort']==port and m.get('protocol','tcp')=='tcp' and type(m.get('hostPort',port)) is int and m.get('hostPort',port)==port and 'containerPortRange' not in m]
    if len(mappings)!=1: return finish('CONTAINER_PORT_MAPPING_UNCONFIRMED')
    out['service_binding']=dict(target_group_arn=tg,container_name=container,container_port=port,task_definition_arn=da)
    analysis=inspect_elb_targets(inventory_raw,elbv2_raw,health_raw,load_balancer_id,listener_port,client_ip,rules_raw=rules_raw,host=host,path=path,attributes_raw=attributes_raw)
    # Only consume registration and rule evidence; EC2-specific target policy/endpoint outputs are not used.
    out['elb_analysis']=dict(status=analysis['status'],reason=analysis['reason'],configuration=analysis['configuration'],forwarding=analysis['forwarding'],health_input_identity=analysis['health_input_identity'])
    if analysis['status']!='TARGET_CONSTRAINTS_CANDIDATE': return finish('ELB_REGISTRATION_UNCONFIRMED')
    groups=analysis['groups']
    if len(groups)!=1 or groups[0]['target_group']['id']!=_id(tg): return finish('SERVICE_TARGET_GROUP_NOT_SELECTED')
    group=groups[0]
    matches=[g for g in elb['TargetGroups'] if _id(g['TargetGroupArn'])==_id(tg)]
    if len(matches)!=1 or matches[0]['TargetGroupArn']!=tg: return finish('TARGET_GROUP_IDENTITY_UNCONFIRMED')
    if group['target_group']['target_type']!='ip': return finish('AWS_VPC_MODE_REQUIRES_IP_TARGET_GROUP')
    if group['target_group']['configured_weight']==0: return finish('ZERO_WEIGHT_TARGET_GROUP_UNSUPPORTED')
    # ECS group is service:name and is scoped to cluster; a standalone task must never be joined by IP alone.
    relevant=[(a,t) for a,t in tasks.items() if t.get('clusterArn')==cluster_arn and t.get('group')=='service:'+name]
    if len(relevant)>100: return finish('SERVICE_TASK_LIMIT_EXCEEDED')
    by_ip={}; all_confirmed=bool(relevant)
    for arn,t in relevant:
        row=dict(task_arn=arn,endpoint=None,status='UNKNOWN',reason='TASK_REVISION_UNCONFIRMED',registration_status='UNKNOWN')
        out['tasks'].append(row)
        if TASK_ARN.fullmatch(arn).groups()[:3]!=(region,account,cluster) or t.get('taskDefinitionArn')!=da:
            all_confirmed=False; continue
        ep=inspect_ecs_task(inventory_raw,ecs_raw,arn.rsplit('/',1)[-1])
        row['endpoint']=ep['endpoint']; row['reason']=ep['reason']
        if ep['status']!='TASK_ENDPOINT_CANDIDATE': all_confirmed=False; continue
        running=[c for c in _rows(t.get('containers',[])) if c.get('name')==container and c.get('lastStatus')=='RUNNING']
        if len(running)!=1: row['reason']='TASK_CONTAINER_UNCONFIRMED'; all_confirmed=False; continue
        row.update(status='TASK_CONTAINER_CANDIDATE',reason='MATCHED_SERVICE_TASK_CONTAINER_AND_ENI',registration_status='NOT_OBSERVED')
        by_ip.setdefault(ep['endpoint']['private_ip'],[]).append(row)
    for t in group['targets']:
        ip=str(IPv4Address(t['id'])); candidates=by_ip.get(ip,[])
        row=dict(ip=ip,registered_port=t['registered_port'],health_state=t['health_state'],health_reason=t['health_reason'],task_arn=None,endpoint=None,status='UNKNOWN',reason='REGISTERED_IP_NOT_CONFIRMED_SERVICE_TASK')
        out['registrations'].append(row)
        if len(candidates)!=1: all_confirmed=False; continue
        candidate=candidates[0]
        if t['registered_port']!=port:
            row['reason']='REGISTERED_PORT_DIFFERS_FROM_SERVICE_CONTAINER_PORT'; all_confirmed=False; continue
        candidate['registration_status']='MATCHED_REGISTRATION'
        row.update(task_arn=candidate['task_arn'],endpoint=candidate['endpoint'],status='REGISTRATION_MATCH_CANDIDATE',reason='MATCHED_TASK_ENI_IP_AND_CONTAINER_PORT')
    if any(t['registration_status']!='MATCHED_REGISTRATION' for t in out['tasks']): all_confirmed=False
    return finish('MATCHED_SERVICE_TASK_AND_ELB_IP_REGISTRATIONS' if all_confirmed else 'SERVICE_REGISTRATIONS_PARTIALLY_UNCONFIRMED','SERVICE_ELB_CORRELATION_CANDIDATE' if all_confirmed else 'UNKNOWN')
