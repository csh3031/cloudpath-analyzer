"""Offline registration, health snapshot and independent target-side TCP rule checks."""
import hashlib
import re
from ipaddress import IPv4Address, IPv4Network
from backend.aws.load_balancer_evidence import inspect_load_balancer, _arn, _id, _port
from backend.aws.alb_rule_evidence import inspect_alb_rule
from backend.aws.nlb_forwarding_evidence import inspect_nlb_forwarding
from backend.aws.peering_evidence import _load, _timestamp, _primary_only
from backend.aws.endpoint_evidence import lookup_observed_endpoint
from backend.aws.policy_evidence import _sg, _acl
from backend.iac.plan_adapter import _read

FORMAT = 'cloudpath-elb-target-health-v1'
HEALTH = {'initial','healthy','unhealthy','unused','draining','unavailable','unhealthy.draining'}


def inspect_elb_targets(inventory_raw, elbv2_raw, health_raw, load_balancer_id,
                        listener_port, client_ip, *, rules_raw=None, host=None,
                        path=None, attributes_raw=None, backend_node_ip=None,
                        backend_source_port=None):
    """Never select a target or claim a session. Node IP/port are hypothetical inputs."""
    def ipv4(value):
        if not isinstance(value,str): raise ValueError('Expected IPv4 string')
        ip=IPv4Address(value)
        if ip.is_unspecified or ip.is_multicast or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError('Expected unicast IPv4')
        return ip
    client=ipv4(client_ip)
    node=ipv4(backend_node_ip) if backend_node_ip is not None else None
    if backend_source_port is not None and not _port(backend_source_port):
        raise ValueError('Invalid hypothetical backend source port')
    base=inspect_load_balancer(inventory_raw,elbv2_raw,load_balancer_id,listener_port)
    identity,meta,inv=_load(inventory_raw)
    doc=_read(elbv2_raw); health=_read(health_raw)
    if not isinstance(health,dict) or set(health)!={'format','collected_at','elbv2_input_identity','complete','target_groups'} or health['format']!=FORMAT:
        raise ValueError('Expected dated target health wrapper')
    if not isinstance(health['target_groups'],list) or len(health['target_groups'])>300:
        raise ValueError('Invalid target group health list')
    exports={}
    for group in health['target_groups']:
        if not isinstance(group,dict) or set(group)!={'TargetGroupArn','TargetHealthDescriptions'}:
            raise ValueError('Invalid target group health row')
        arn=group['TargetGroupArn']; _arn(arn,'targetgroup')
        if arn in exports or not isinstance(group['TargetHealthDescriptions'],list) or len(group['TargetHealthDescriptions'])>1000:
            raise ValueError('Duplicate group or invalid target health list')
        exports[arn]=group['TargetHealthDescriptions']
    timestamps=[_timestamp(x) for x in (meta['collected_at'],doc['collected_at'],health['collected_at'])]
    out=dict(analysis_type='STATIC_AWS_ELB_TARGET_CONSTRAINTS',input_identity=identity,
             elbv2_input_identity=base['elbv2_input_identity'],health_input_identity='sha256-elb-target-health-v1:'+hashlib.sha256(health_raw).hexdigest(),
             configuration=base,forwarding=None,groups=[],target_selection='NOT_EVALUATED',
             target_health='NOT_EVALUATED',policy_status='NOT_EVALUATED',session_status='UNKNOWN',live_observation=False,
             scenario=dict(client_ip=str(client),hypothetical_backend_node_ip=str(node) if node else None,hypothetical_backend_source_port=backend_source_port),
             limitations=['Offline unauthenticated non-atomic snapshots; completeness asserted only.',
                          'Health snapshot is not delivery eligibility: fail-open, thresholds, zonal shift and runtime selection unresolved.',
                          'Primary IPv4 single-ENI running EC2 targets in same VPC only; instance and IP registrations supported.',
                          'Independent target-side CIDR rule checks only; SG references/prefix lists unresolved.',
                          'Hypothetical backend node IP/port are not observed mappings; NACL applicability and LB-side policy/route not established.',
                          'No health-check execution, frontend path, DNS, TLS, host or application verification; no AWS calls or packets.'])
    def finish(reason,status='UNKNOWN'): return dict(out,status=status,reason=reason)
    if not base['load_balancer'] or not base['listener'] or not _primary_only(inv['Vpcs'][0]):
        return finish('BASE_SCOPE_UNCONFIRMED')
    if health['complete'] is not True or health['elbv2_input_identity']!=base['elbv2_input_identity']:
        return finish('HEALTH_COMPLETENESS_OR_IDENTITY_UNCONFIRMED')
    kind=base['load_balancer']['type']
    if kind=='application':
        if rules_raw is None or attributes_raw is not None: return finish('ALB_RULE_EVIDENCE_REQUIRED')
        fwd=inspect_alb_rule(inventory_raw,elbv2_raw,rules_raw,load_balancer_id,listener_port,host,path)
        timestamps.append(_timestamp(_read(rules_raw)['collected_at']))
        selected=fwd['selected_target_groups']; expected='RULE_FORWARD_CONFIG_CANDIDATE'
    else:
        if attributes_raw is None or rules_raw is not None: return finish('NLB_ATTRIBUTES_REQUIRED')
        fwd=inspect_nlb_forwarding(inventory_raw,elbv2_raw,attributes_raw,load_balancer_id,listener_port,client_ip)
        timestamps.append(_timestamp(_read(attributes_raw)['collected_at']))
        selected=[fwd['target_group']] if fwd['target_group'] else []; expected='NLB_FORWARD_CONFIG_CANDIDATE'
    out['forwarding']=fwd
    out['time_gap_seconds']=(max(timestamps)-min(timestamps)).total_seconds()
    if out['time_gap_seconds']>300: return finish('SNAPSHOT_TIME_GAP')
    if fwd['status']!=expected: return finish('FORWARDING_UNCONFIRMED')
    subnets={s['SubnetId']:s for s in inv['Subnets']}
    lb_subnets={s['subnet_id'] for s in base['load_balancer']['subnets']}
    enabled_zones={s['availability_zone'] for s in base['load_balancer']['subnets']}
    instances=[i for r in inv['Reservations'] for i in r['Instances']]
    groups={g['GroupId']:g for g in inv['SecurityGroups']}
    # A scenario node is not an observed LB ENI; reject reserved and known occupied addresses.
    if node is not None:
        nets=[IPv4Network(subnets[s]['CidrBlock']) for s in lb_subnets if node in IPv4Network(subnets[s]['CidrBlock'])]
        owners=[e for e in inv['NetworkInterfaces'] if str(node)==e.get('PrivateIpAddress') or any(a.get('PrivateIpAddress')==str(node) for a in e.get('PrivateIpAddresses',[]))]
        if len(nets)!=1 or int(node)-int(nets[0].network_address)<4 or node==nets[0].broadcast_address or owners:
            return finish('HYPOTHETICAL_NODE_ADDRESS_OUT_OF_SCOPE')
    preserve=kind=='network' and fwd['address_processing']['preserve_client_ip']
    peer_ip=str(client) if preserve else str(node) if node else None
    out['backend_source_ip_kind']='CLIENT_IPV4_CANDIDATE' if preserve else 'HYPOTHETICAL_LB_NODE_IPV4' if node else 'LB_NODE_IPV4_UNCONFIRMED'
    all_complete=True; any_checks=False
    for g in selected:
        matches=[x['TargetGroupArn'] for x in doc['TargetGroups'] if _id(x['TargetGroupArn'])==g['id']]
        if len(matches)!=1 or matches[0] not in exports:
            all_complete=False; out['groups'].append(dict(target_group=g,status='UNKNOWN',reason='TARGET_HEALTH_EXPORT_MISSING_OR_AMBIGUOUS',targets=[])); continue
        rows=exports[matches[0]]; seen=set(); targets=[]
        for row in rows:
            if not isinstance(row,dict) or not isinstance(row.get('Target'),dict) or not isinstance(row.get('TargetHealth'),dict):
                raise ValueError('Invalid target health description')
            t=row['Target']; h=row['TargetHealth']; tid=t.get('Id'); port=t.get('Port')
            if not isinstance(tid,str) or not _port(port) or (tid,port) in seen or not isinstance(h.get('State'),str) or h['State'] not in HEALTH:
                raise ValueError('Invalid or duplicate target registration/health state')
            seen.add((tid,port)); target=dict(id=tid,registered_port=port,health_state=h['State'],health_reason=h.get('Reason') if isinstance(h.get('Reason'),str) else None,
                       registration_status='OBSERVED_REGISTRATION',endpoint=None,zone_status='UNKNOWN',policy_checks=[],policy_status='NOT_EVALUATED')
            targets.append(target)
            if g['target_type']=='instance':
                if not re.fullmatch(r'i-[0-9a-f]{8}(?:[0-9a-f]{9})?',tid): raise ValueError('Invalid instance registration ID')
                ip_matches=[i.get('PrivateIpAddress') for i in instances if i['InstanceId']==tid]
                ip=ip_matches[0] if len(ip_matches)==1 else None
            else:
                ip=str(ipv4(tid))
            if ip is None: continue
            ep=lookup_observed_endpoint(inventory_raw,ip); target['endpoint']=ep
            if ep['status']!='ENDPOINT_CANDIDATE' or (g['target_type']=='instance' and ep['instance_id']!=tid): continue
            subnet=subnets[ep['subnet_id']]; network=IPv4Network(subnet['CidrBlock']); dst=IPv4Address(ip)
            if int(dst)-int(network.network_address)<4 or dst==network.broadcast_address: continue
            zone=subnet.get('AvailabilityZone'); target['availability_zone']=zone
            if not zone or t.get('AvailabilityZone') not in (None,zone,'all'): continue
            # 'all' is not evidence of routing eligibility; only actual subnet AZ is reported.
            target['zone_status']='ENABLED_ZONE_CANDIDATE' if zone in enabled_zones else 'ZONE_NOT_CONFIRMED'
            if target['zone_status']!='ENABLED_ZONE_CANDIDATE' or g['configured_weight']==0: continue
            if peer_ip is None or peer_ip==ip: continue
            peer={'private_ip':peer_ip}; any_checks=True
            def add(stage,evidence): target['policy_checks'].append(dict(stage=stage,evaluation_mode='INDEPENDENT_RULE_CHECK',**evidence))
            add('TARGET_SG_INGRESS',_sg(groups,ep,peer,False,port))
            add('TARGET_NACL_INGRESS_RULE',_acl(inv['NetworkAcls'],ep,peer,False,port))
            add('TARGET_SG_REPLY',dict(status='CONDITIONAL',reason='REQUIRES_ESTABLISHED_TRACKED_REQUEST'))
            if backend_source_port is not None:
                add('TARGET_NACL_REPLY_RULE',_acl(inv['NetworkAcls'],ep,peer,True,backend_source_port))
            else:
                add('TARGET_NACL_REPLY_RULE',dict(status='UNKNOWN',reason='BACKEND_SOURCE_PORT_UNCONFIRMED'))
            states={r['status'] for r in target['policy_checks']}
            target['policy_status']='RULE_BLOCK_CANDIDATE' if 'BLOCKED' in states else 'UNKNOWN' if 'UNKNOWN' in states else 'RULE_ALLOW_CANDIDATE'
        healthy=sum(t['health_state']=='healthy' for t in targets)
        out['groups'].append(dict(target_group=g,status='REGISTRATION_SNAPSHOT_CANDIDATE',targets=targets,registered_count=len(targets),healthy_count=healthy,
                                  health_warning='NO_HEALTHY_TARGETS_FAIL_OPEN_POSSIBLE' if targets and not healthy else 'EMPTY_TARGET_GROUP' if not targets else 'HEALTH_NOT_ROUTING_GUARANTEE'))
    out['target_health']='OBSERVED_SNAPSHOT_CANDIDATE' if all_complete else 'UNKNOWN'
    out['policy_status']='INDEPENDENT_TARGET_RULE_CHECKS' if any_checks else 'NOT_EVALUATED'
    return finish('OBSERVED_TARGET_REGISTRATION_AND_HEALTH' if all_complete else 'TARGET_HEALTH_EVIDENCE_INCOMPLETE','TARGET_CONSTRAINTS_CANDIDATE' if all_complete else 'UNKNOWN')
