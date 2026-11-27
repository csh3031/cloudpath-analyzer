"""Bounded offline NLB default-only IPv4 forwarding configuration evidence."""
import hashlib
import ipaddress
from backend.aws.load_balancer_evidence import inspect_load_balancer, _arn, _id
from backend.aws.peering_evidence import _timestamp, _load
from backend.iac.plan_adapter import _read

FORMAT = 'cloudpath-nlb-attributes-v1'


def _attributes(rows):
    if not isinstance(rows, list) or len(rows) > 200:
        raise ValueError('Invalid attribute list')
    result = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('Key'), str) or not isinstance(row.get('Value'), str) or row['Key'] in result:
            raise ValueError('Invalid or duplicate attribute')
        result[row['Key']] = row['Value']
    return result


def inspect_nlb_forwarding(inventory_raw, evidence_raw, attributes_raw, load_balancer_id, listener_port, client_ip):
    """Configuration constraints only: no runtime node, target or port selection."""
    if not isinstance(client_ip, str):
        raise ValueError('Expected client IPv4 string')
    ip = ipaddress.IPv4Address(client_ip)
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        raise ValueError('Expected unicast client IPv4')
    base = inspect_load_balancer(inventory_raw, evidence_raw, load_balancer_id, listener_port)
    doc = _read(attributes_raw)
    if not isinstance(doc, dict) or set(doc) != {'format','collected_at','elbv2_input_identity','LoadBalancerArn','ListenerArn','TargetGroupArn','default_only_asserted','LoadBalancerAttributes','TargetGroupAttributes'} or doc['format'] != FORMAT:
        raise ValueError('Expected dated NLB attributes wrapper')
    for key, kind in [('LoadBalancerArn','loadbalancer'),('ListenerArn','listener'),('TargetGroupArn','targetgroup')]:
        _arn(doc[key], kind)
    lb_attr = _attributes(doc['LoadBalancerAttributes'])
    tg_attr = _attributes(doc['TargetGroupAttributes'])
    _, meta, _ = _load(inventory_raw)
    raw = _read(evidence_raw)
    time = _timestamp(doc['collected_at'])
    gap = max(abs((time-_timestamp(meta['collected_at'])).total_seconds()), abs((time-_timestamp(raw['collected_at'])).total_seconds()))
    out = dict(analysis_type='STATIC_AWS_NLB_FORWARDING_CONSTRAINTS', configuration=base,
               input_identity=base['input_identity'], elbv2_input_identity=base['elbv2_input_identity'],
               attributes_input_identity='sha256-nlb-attributes-v1:'+hashlib.sha256(attributes_raw).hexdigest(),
               scenario={'client_ip':str(ip),'listener_port':listener_port,'traffic_scope':'DIRECT_IPV4_NEW_CONNECTION_ASSUMED'},
               time_gap_seconds=gap, target_group=None, transport=None, address_processing=None, cross_zone=None,
               proxy_protocol_v2=None, target_selection='NOT_EVALUATED', target_health='NOT_EVALUATED',
               policy_status='NOT_EVALUATED', session_status='UNKNOWN', live_observation=False,
               limitations=['Offline unauthenticated evidence; time proximity and default-only assertion are not verified live.',
                            'Direct IPv4 new connections only; PrivateLink, IPv6 translation, TGW, inspection appliances and hairpin not evaluated.',
                            'No DNS, actual ingress node, registered target, target port override, runtime source port, health or policy selection.',
                            'TLS configuration only; handshake, certificates and payload are not verified.',
                            'No AWS API calls or packet transmission.'])
    def finish(reason, status='UNKNOWN'):
        return dict(out, status=status, reason=reason)
    if base['status'] != 'DEFAULT_FORWARD_CONFIG_CANDIDATE':
        return finish('BASE_CONFIGURATION_UNCONFIRMED')
    if base['load_balancer']['type'] != 'network':
        return finish('NLB_REQUIRED')
    if doc['elbv2_input_identity'] != base['elbv2_input_identity'] or gap > 300:
        return finish('ATTRIBUTES_IDENTITY_OR_TIME_MISMATCH')
    groups = base['default_target_groups']
    if len(groups) != 1:
        return finish('SINGLE_DEFAULT_TARGET_GROUP_REQUIRED')
    # Match full ARNs, not only their suffixes, against the validated selected objects.
    lbs = [x for x in raw['LoadBalancers'] if _id(x['LoadBalancerArn']) == load_balancer_id]
    listeners = [x for x in raw['Listeners'] if x.get('LoadBalancerArn') == lbs[0]['LoadBalancerArn'] and x.get('Port') == listener_port]
    gs = [x for x in raw['TargetGroups'] if _id(x['TargetGroupArn']) == groups[0]['id']]
    if len(gs) != 1 or (doc['LoadBalancerArn'], doc['ListenerArn'], doc['TargetGroupArn']) != (lbs[0]['LoadBalancerArn'], listeners[0]['ListenerArn'], gs[0]['TargetGroupArn']):
        return finish('ATTRIBUTES_RESOURCE_SCOPE_MISMATCH')
    if doc['default_only_asserted'] is not True:
        return finish('DEFAULT_ONLY_LISTENER_UNCONFIRMED')
    preserve = tg_attr.get('preserve_client_ip.enabled')
    cross = tg_attr.get('load_balancing.cross_zone.enabled')
    lb_cross = lb_attr.get('load_balancing.cross_zone.enabled')
    proxy = tg_attr.get('proxy_protocol_v2.enabled')
    group = groups[0]
    out['target_group'] = group
    lp, gp = base['listener']['protocol'], group['protocol']
    out['transport'] = {'listener_protocol':lp,'target_group_protocol':gp,'configured_target_port':group['port'],
                        'tls_mode': 'TCP_NO_LB_TLS_TERMINATION' if lp=='TCP' else 'TLS_TERMINATION_REENCRYPTION_CONFIG' if gp=='TLS' else 'TLS_TERMINATION_TCP_BACKEND_CONFIG'}
    if preserve not in ('true','false'):
        return finish('CLIENT_IP_PRESERVATION_UNCONFIRMED')
    out['address_processing'] = {'preserve_client_ip':preserve=='true',
                                 'backend_source_ip_kind':'CLIENT_IPV4_CANDIDATE' if preserve=='true' else 'NLB_NODE_PRIVATE_IPV4_CANDIDATE',
                                 'backend_source_ip':str(ip) if preserve=='true' else None,
                                 'backend_source_port':None,'backend_destination_ip':None,'runtime_mapping_observed':False}
    if proxy not in ('true','false'):
        return finish('PROXY_PROTOCOL_UNCONFIRMED')
    out['proxy_protocol_v2'] = proxy=='true'
    if cross == 'use_load_balancer_configuration':
        effective = lb_cross
    else:
        effective = cross
    if effective not in ('true','false'):
        return finish('CROSS_ZONE_CONFIGURATION_UNCONFIRMED')
    out['cross_zone'] = {'enabled':effective=='true','source':'LOAD_BALANCER' if cross=='use_load_balancer_configuration' else 'TARGET_GROUP',
                         'eligible_zone_scope':'ALL_ENABLED_ZONES_CANDIDATE' if effective=='true' else 'INGRESS_NODE_ZONE_ONLY_CANDIDATE',
                         'enabled_zones':[x['availability_zone'] for x in base['load_balancer']['subnets']], 'ingress_node_zone':None}
    return finish('OBSERVED_DEFAULT_FORWARD_AND_ATTRIBUTES','NLB_FORWARD_CONFIG_CANDIDATE')
