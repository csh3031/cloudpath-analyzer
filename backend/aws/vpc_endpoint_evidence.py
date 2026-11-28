"""Offline IPv4 VPC endpoint configuration correlation, not reachability or IAM."""
import hashlib
import re
from ipaddress import IPv4Address, IPv4Network
from backend.aws.peering_evidence import _load, _timestamp, _primary_only, TARGET_KEYS
from backend.iac.plan_adapter import _read

FORMAT = 'cloudpath-vpc-endpoints-v1'


def _id(value, prefix):
    return isinstance(value, str) and re.fullmatch(prefix + r'-[0-9a-f]{8,17}', value) is not None


def _rows(value):
    if not isinstance(value, list) or len(value)>300 or any(not isinstance(row,dict) for row in value):
        raise ValueError('Invalid VPC endpoint evidence rows')
    return value


def _ids(value, prefix):
    if not isinstance(value,list) or len(value)>300 or any(not _id(x,prefix) for x in value) or len(set(value))!=len(value):
        raise ValueError('Invalid or duplicate VPC endpoint relationship ID')
    return value


def _dns(value):
    if not isinstance(value,str) or len(value)>253: return False
    if value.startswith('*.'): value=value[2:]
    return value.endswith('.amazonaws.com') and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',p) for p in value.split('.'))


def inspect_vpc_endpoint(inventory_raw, endpoint_raw, endpoint_id):
    """Validate logical membership, never infer a selected route or DNS answer."""
    if not _id(endpoint_id,'vpce'): raise ValueError('Expected VPC endpoint ID')
    if not isinstance(endpoint_raw,bytes) or len(endpoint_raw)>5*1024*1024:
        raise ValueError('Invalid VPC endpoint evidence size')
    identity, meta, inv = _load(inventory_raw)
    doc = _read(endpoint_raw)
    if set(doc)!={'format','inventory_identity','region','collected_at','complete','VpcEndpoints'} or doc['format']!=FORMAT:
        raise ValueError('Expected normalized VPC endpoint wrapper')
    gap=abs((_timestamp(doc['collected_at'])-_timestamp(meta['collected_at'])).total_seconds())
    rows={}
    for row in _rows(doc['VpcEndpoints']):
        key=row.get('VpcEndpointId')
        if not _id(key,'vpce') or key in rows: raise ValueError('Invalid or duplicate endpoint ID')
        rows[key]=row
    out=dict(analysis_type='STATIC_AWS_VPC_ENDPOINT_CONFIGURATION',input_identity=identity,
             endpoint_input_identity='sha256-vpc-endpoints-v1:'+hashlib.sha256(endpoint_raw).hexdigest(),
             endpoint_id=endpoint_id,region=meta['region'],vpc_id=meta['vpc_id'],time_gap_seconds=gap,
             endpoint_type=None,service_name=None,private_dns_enabled=None,dns_entries=[],network_interfaces=[],route_tables=[],
             endpoint_policy_present=None,dns_status='NOT_EVALUATED',route_status='NOT_EVALUATED',
             policy_status='NOT_EVALUATED',authorization_status='NOT_EVALUATED',session_status='UNKNOWN',live_observation=False,
             limitations=['Offline normalized snapshots; ownership, completeness and concurrent state asserted only.',
                          'Same-region AWS service IPv4 Interface and S3/DynamoDB Gateway endpoints only.',
                          'ENI membership is not DNS selection; Gateway route links are not IP route selection or verified prefix list membership.',
                          'No endpoint policy evaluation, IAM, TLS, API requests, AWS calls or packets.'])
    def unknown(reason): return dict(out,status='UNKNOWN',reason=reason)
    if doc['inventory_identity']!=identity or doc['region']!=meta['region']: return unknown('ENDPOINT_INVENTORY_SCOPE_MISMATCH')
    if gap>300: return unknown('SNAPSHOT_TIME_GAP')
    if doc['complete'] is not True: return unknown('ENDPOINT_EVIDENCE_INCOMPLETE')
    row=rows.get(endpoint_id)
    if row is None: return unknown('VPC_ENDPOINT_MISSING')
    if row.get('VpcId')!=meta['vpc_id'] or row.get('ServiceRegion',meta['region'])!=meta['region']:
        return unknown('ENDPOINT_VPC_OR_REGION_MISMATCH')
    if row.get('State')!='available': return unknown('ENDPOINT_STATE_UNCONFIRMED')
    kind=row.get('VpcEndpointType'); service=row.get('ServiceName')
    if kind not in ('Interface','Gateway'): return unknown('ENDPOINT_TYPE_UNSUPPORTED')
    prefix='com.amazonaws.'+meta['region']+'.'
    if not isinstance(service,str) or not service.startswith(prefix) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,100}',service[len(prefix):]) or service[len(prefix):].startswith('vpce-svc-'):
        return unknown('ENDPOINT_SERVICE_SCOPE_UNSUPPORTED')
    if kind=='Gateway' and service not in (prefix+'s3',prefix+'dynamodb'): return unknown('ENDPOINT_SERVICE_SCOPE_UNSUPPORTED')
    if row.get('IpAddressType')!='ipv4' or inv['Vpcs'][0].get('State')!='available' or not _primary_only(inv['Vpcs'][0]):
        return unknown('ENDPOINT_IPV4_PROFILE_UNCONFIRMED')
    out.update(endpoint_type=kind,service_name=service,endpoint_policy_present=isinstance(row.get('PolicyDocument'),(str,dict)) and bool(row['PolicyDocument']))
    enis=_ids(row.get('NetworkInterfaceIds',[]),'eni'); subs=_ids(row.get('SubnetIds',[]),'subnet'); tables=_ids(row.get('RouteTableIds',[]),'rtb')
    groups=_ids([g.get('GroupId') for g in _rows(row.get('Groups',[]))],'sg')
    dns=_rows(row.get('DnsEntries',[]))
    if kind=='Interface':
        if tables or not enis or not subs or not groups or len(enis)!=len(subs): return unknown('INTERFACE_RELATIONSHIPS_UNCONFIRMED')
        if type(row.get('PrivateDnsEnabled')) is not bool or not dns: return unknown('INTERFACE_DNS_CONFIGURATION_UNCONFIRMED')
        names=[d.get('DnsName') for d in dns]
        if any(not _dns(n) for n in names) or len(set(names))!=len(names): return unknown('INTERFACE_DNS_CONFIGURATION_UNCONFIRMED')
        out.update(private_dns_enabled=row['PrivateDnsEnabled'],dns_entries=sorted(names))
        if any(sum(g['GroupId']==gid and g.get('VpcId')==meta['vpc_id'] for g in inv['SecurityGroups'])!=1 for gid in groups): return unknown('INTERFACE_SECURITY_GROUP_UNCONFIRMED')
        primary=IPv4Network(inv['Vpcs'][0]['CidrBlock']); matched=[]; zones=set(); seen=set()
        for eid in enis:
            if any(eid in _ids(other.get('NetworkInterfaceIds',[]),'eni') for k,other in rows.items() if k!=endpoint_id): return unknown('INTERFACE_ENI_OWNERSHIP_CONFLICT')
            found=[e for e in inv['NetworkInterfaces'] if e['NetworkInterfaceId']==eid]
            if len(found)!=1: return unknown('INTERFACE_ENI_UNCONFIRMED')
            e=found[0]; addresses=e.get('PrivateIpAddresses',[])
            if e.get('VpcId')!=meta['vpc_id'] or e.get('Status')!='in-use' or e.get('InterfaceType')!='vpc_endpoint' or e.get('RequesterManaged') is not True or e.get('Attachment',{}).get('InstanceId') or e.get('Association') or len(addresses)!=1 or addresses[0].get('Primary') is not True or addresses[0].get('Association') or addresses[0].get('PrivateIpAddress')!=e.get('PrivateIpAddress'):
                return unknown('INTERFACE_ENI_PROFILE_UNCONFIRMED')
            ip=e.get('PrivateIpAddress')
            try: addr=IPv4Address(ip) if isinstance(ip,str) else None
            except ValueError: addr=None
            if addr is None: return unknown('INTERFACE_ENI_IP_UNCONFIRMED')
            owners=[n for n in inv['NetworkInterfaces'] if n.get('PrivateIpAddress')==ip or any(a.get('PrivateIpAddress')==ip for a in n.get('PrivateIpAddresses',[]))]
            if len(owners)!=1 or any(i.get('PrivateIpAddress')==ip or any(n.get('NetworkInterfaceId')==eid for n in i.get('NetworkInterfaces',[])) for res in inv['Reservations'] for i in res['Instances']) or any(a.get('NetworkInterfaceId')==eid for nat in inv['NatGateways'] for a in nat.get('NatGatewayAddresses',[])):
                return unknown('INTERFACE_ENI_OWNERSHIP_CONFLICT')
            sid=e.get('SubnetId'); candidates=[s for s in inv['Subnets'] if addr in IPv4Network(s['CidrBlock'])]
            if len(candidates)!=1 or candidates[0]['SubnetId']!=sid or sid not in subs or sid in seen: return unknown('INTERFACE_SUBNET_UNCONFIRMED')
            s=candidates[0]; net=IPv4Network(s['CidrBlock']); az=s.get('AvailabilityZone')
            if s.get('VpcId')!=meta['vpc_id'] or s.get('State')!='available' or not net.subnet_of(primary) or int(addr)-int(net.network_address)<4 or addr==net.broadcast_address or not isinstance(az,str) or az in zones:
                return unknown('INTERFACE_SUBNET_UNCONFIRMED')
            if sorted(g['GroupId'] for g in e['Groups'])!=sorted(groups): return unknown('INTERFACE_SECURITY_GROUP_CONFLICT')
            seen.add(sid); zones.add(az)
            matched.append(dict(kind='VPC_INTERFACE_ENDPOINT_ENI',eni_id=eid,private_ip=ip,subnet_id=sid,availability_zone=az,security_group_ids=sorted(groups)))
        if seen!=set(subs): return unknown('INTERFACE_SUBNET_UNCONFIRMED')
        out['network_interfaces']=sorted(matched,key=lambda x:x['eni_id'])
        return dict(out,status='VPC_ENDPOINT_CONFIGURATION_CANDIDATE',reason='MATCHED_INTERFACE_ENDPOINT_ENI_CONFIGURATION')
    if enis or subs or groups or dns or (row.get('PrivateDnsEnabled') is not None and row.get('PrivateDnsEnabled') is not False) or not tables:
        return unknown('GATEWAY_RELATIONSHIPS_UNCONFIRMED')
    matched=[]; prefixes=set()
    for table in inv['RouteTables']:
        tid=table['RouteTableId']; routes=[r for r in table['Routes'] if any(r.get(k)==endpoint_id for k in TARGET_KEYS)]
        if tid not in tables:
            if routes: return unknown('GATEWAY_ROUTE_TABLE_CONFLICT')
            continue
        if table.get('VpcId')!=meta['vpc_id'] or len(routes)!=1: return unknown('GATEWAY_ROUTE_UNCONFIRMED')
        route=routes[0]; targets=[k for k in TARGET_KEYS if k in route]
        pl=route.get('DestinationPrefixListId')
        if targets not in (['GatewayId'],['VpcEndpointId']) or route.get('State')!='active' or not _id(pl,'pl') or 'DestinationCidrBlock' in route or 'DestinationIpv6CidrBlock' in route:
            return unknown('GATEWAY_ROUTE_UNCONFIRMED')
        prefixes.add(pl)
        matched.append(dict(route_table_id=tid,destination_prefix_list_id=pl,target_endpoint_id=endpoint_id,route_state='active',prefix_list_membership='NOT_EVALUATED'))
    if len(matched)!=len(tables) or len(prefixes)!=1: return unknown('GATEWAY_ROUTE_TABLE_CONFLICT')
    out['route_tables']=sorted(matched,key=lambda x:x['route_table_id'])
    return dict(out,status='VPC_ENDPOINT_CONFIGURATION_CANDIDATE',reason='MATCHED_GATEWAY_ENDPOINT_ROUTE_CONFIGURATION')
