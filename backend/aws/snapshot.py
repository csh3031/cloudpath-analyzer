"""Single-VPC EC2 inventory, not a packet observation or an authenticated attestation."""
import hashlib
import ipaddress
import json
import re
from datetime import datetime
from backend.models.infrastructure import InfrastructureResource

FORMAT = 'cloudpath-aws-inventory-v1'
FORMAT_V2 = 'cloudpath-aws-inventory-v2'
FORMATS = (FORMAT, FORMAT_V2)
OPERATIONS = {
    'describe-vpcs': ('Vpcs', 'vpc-id'),
    'describe-subnets': ('Subnets', 'vpc-id'),
    'describe-route-tables': ('RouteTables', 'vpc-id'),
    'describe-internet-gateways': ('InternetGateways', 'attachment.vpc-id'),
    'describe-nat-gateways': ('NatGateways', 'vpc-id'),
    'describe-security-groups': ('SecurityGroups', 'vpc-id'),
    'describe-network-acls': ('NetworkAcls', 'vpc-id'),
    'describe-instances': ('Reservations', 'vpc-id'),
    'describe-network-interfaces': ('NetworkInterfaces', 'vpc-id'),
}
# Explicit allowlist: never copy descriptions, tags, DNS names, credentials, owner/account IDs,
# user data, arbitrary metadata, or full responses to the snapshot.
SCHEMAS = {
 'Vpcs': 'VpcId CidrBlock State CidrBlockAssociationSet[CidrBlock] Ipv6CidrBlockAssociationSet[Ipv6CidrBlock]',
 'Subnets': 'SubnetId VpcId CidrBlock AvailabilityZone State',
 'RouteTables': 'RouteTableId VpcId Associations[RouteTableAssociationId,SubnetId,Main,GatewayId,AssociationState.State] Routes[DestinationCidrBlock,DestinationIpv6CidrBlock,DestinationPrefixListId,GatewayId,NatGatewayId,TransitGatewayId,VpcPeeringConnectionId,NetworkInterfaceId,InstanceId,EgressOnlyInternetGatewayId,LocalGatewayId,CarrierGatewayId,CoreNetworkArn,VpcEndpointId,State,Origin] PropagatingVgws[GatewayId]',
 'InternetGateways': 'InternetGatewayId Attachments[VpcId,State]',
 'NatGateways': 'NatGatewayId VpcId SubnetId State ConnectivityType',
 'SecurityGroups': 'GroupId VpcId IpPermissions[IpProtocol,FromPort,ToPort,IpRanges.CidrIp,Ipv6Ranges.CidrIpv6,UserIdGroupPairs.GroupId,PrefixListIds.PrefixListId] IpPermissionsEgress[IpProtocol,FromPort,ToPort,IpRanges.CidrIp,Ipv6Ranges.CidrIpv6,UserIdGroupPairs.GroupId,PrefixListIds.PrefixListId]',
 'NetworkAcls': 'NetworkAclId VpcId Associations[SubnetId,NetworkAclAssociationId] Entries[RuleNumber,Protocol,RuleAction,Egress,CidrBlock,Ipv6CidrBlock,PortRange.From,PortRange.To,IcmpTypeCode.Type,IcmpTypeCode.Code]',
 'Reservations': 'Instances[InstanceId,VpcId,SubnetId,PrivateIpAddress,State.Name,SecurityGroups.GroupId,NetworkInterfaces.NetworkInterfaceId]',
 'NetworkInterfaces': 'NetworkInterfaceId VpcId SubnetId PrivateIpAddress PrivateIpAddresses[PrivateIpAddress] Groups[GroupId] Attachment.InstanceId Attachment.DeviceIndex Status InterfaceType RequesterManaged',
}

SCHEMAS_V2 = dict(SCHEMAS)
SCHEMAS_V2['NatGateways'] += ' NatGatewayAddresses[PrivateIp,PublicIp,NetworkInterfaceId,AllocationId,AssociationId,IsPrimary,Status]'
SCHEMAS_V2['NetworkInterfaces'] = SCHEMAS['NetworkInterfaces'].replace(
    'PrivateIpAddresses[PrivateIpAddress]',
    'PrivateIpAddresses[PrivateIpAddress,Primary,Association.PublicIp,Association.CarrierIp,Association.CustomerOwnedIp,Association.AllocationId,Association.AssociationId]') + ' Association.PublicIp Association.CarrierIp Association.CustomerOwnedIp Association.AllocationId Association.AssociationId'
SCHEMAS_V2['Reservations'] = SCHEMAS['Reservations'].replace('PrivateIpAddress,State.Name', 'PrivateIpAddress,PublicIpAddress,State.Name')

def _obj(x):
    if not isinstance(x,dict): raise ValueError('Invalid AWS inventory object')
    return x

def _arr(x):
    if not isinstance(x,list): raise ValueError('Invalid AWS inventory list')
    return x

def _tree(spec):
    out={}
    for field in spec.split():
        if '[' in field:
            k,inner=field.split('[',1); out[k]=[_tree(inner[:-1].replace(',',' '))]; continue
        p=field.split('.'); d=out
        for k in p[:-1]: d=d.setdefault(k,{})
        d[p[-1]]=None
    return out

def _pick(value,tree):
    if isinstance(value,list):
        if tree is None:raise ValueError('Expected AWS inventory scalar')
        return [_pick(x,tree[0] if isinstance(tree,list) else tree) for x in value]
    if isinstance(tree,list): raise ValueError('Expected AWS inventory list')
    if tree is None:
        if type(value) in (bool,int):return value
        if isinstance(value,str) and len(value)<=512 and not any(c in value for c in ('${','%{','<','>','\n','\r')):return value
        raise ValueError('Invalid AWS inventory scalar')
    return {k:('REDACTED' if k=='CoreNetworkArn' else _pick(v,tree[k])) for k,v in _obj(value).items() if k in tree and v is not None}

def sanitize_inventory(data, *, version=FORMAT):
    if version not in FORMATS: raise ValueError('Invalid AWS inventory version')
    schemas=SCHEMAS_V2 if version==FORMAT_V2 else SCHEMAS
    if set(_obj(data))!=set(schemas):raise ValueError('Incomplete AWS inventory: nine response groups required')
    return {k:_pick(_arr(data[k]),[_tree(spec)]) for k,spec in schemas.items()}

def _id(value,prefix):
    if not isinstance(value,str) or not re.fullmatch(re.escape(prefix)+r'-[0-9a-f]{8,17}',value):raise ValueError('Invalid AWS resource ID')
    return value

def _net(value,version):
    try:
        n=ipaddress.ip_network(value,strict=True)
        if n.version!=version:raise ValueError()
        return str(n)
    except (TypeError,ValueError):raise ValueError('Invalid AWS CIDR') from None

def _ip(value):
    try:return str(ipaddress.IPv4Address(value)) if isinstance(value,str) else None
    except ValueError:raise ValueError('Invalid AWS IPv4 address') from None

def _ref(kind,value,prefix):return '${aws_'+kind+'.'+_id(value,prefix)+'.id}'

def load_aws_snapshot(raw,name='aws_snapshot.json',max_resources=300):
    try:
        from backend.iac.plan_adapter import _read
        doc=_read(raw)
        if doc.get('format') not in FORMATS or set(doc)!={'format','region','vpc_id','collected_at','inventory'}:raise ValueError('Invalid AWS inventory format')
        region=doc['region'];vpc=_id(doc['vpc_id'],'vpc')
        if not isinstance(region,str) or not re.fullmatch(r'[a-z]{2}(?:-[a-z0-9]+)+-\d+',region):raise ValueError('Invalid AWS region')
        time=datetime.fromisoformat(doc['collected_at'])
        if time.tzinfo is None:raise ValueError('Collection timestamp needs timezone')
        inv=sanitize_inventory(doc['inventory'], version=doc['format'])
        if len(inv['Vpcs'])!=1 or inv['Vpcs'][0].get('VpcId')!=vpc:raise ValueError('Expected exactly selected VPC')
        resources=[];seen=set();warnings={'AWS inventory only: no live packet or session verdict.','Sequential API reads are not an atomic snapshot; uploaded inventory is not authenticated.','Single VPC / region, EC2 networking only; ALB, RDS, ECS, TGW and external peer configurations not collected.'}
        def add(kind,native,attrs):
            rid='aws_'+kind+'.'+native
            if rid in seen:raise ValueError('Duplicate AWS resource ID')
            seen.add(rid);resources.append(InfrastructureResource(rid,'aws','compute' if kind=='instance' else 'security' if kind in ('security_group','network_acl') else 'network',kind,native,attrs))
            if len(resources)>max_resources:raise ValueError('AWS inventory resource/association limit exceeded')
        def scope(row):
            if row.get('VpcId')!=vpc:raise ValueError('Resource outside selected VPC')
        def optional_ip(row,attrs):
            if row.get('PrivateIpAddress') is not None:attrs['private_ip']=_ip(row['PrivateIpAddress'])
        vr=_ref('vpc',vpc,'vpc');v=inv['Vpcs'][0]
        add('vpc',vpc,{'cidr_block':_net(v['CidrBlock'],4),'observed_state':v.get('State'), 'observed_ipv4_cidrs':[_net(x['CidrBlock'],4) for x in v.get('CidrBlockAssociationSet',[])], 'observed_ipv6_cidrs':[_net(x['Ipv6CidrBlock'],6) for x in v.get('Ipv6CidrBlockAssociationSet',[])]})
        for s in inv['Subnets']:
            scope(s);add('subnet',_id(s['SubnetId'],'subnet'),{'vpc_id':vr,'cidr_block':_net(s['CidrBlock'],4),'availability_zone':s.get('AvailabilityZone'),'observed_state':s.get('State')})
        for g in inv['InternetGateways']:
            attachments=_arr(g.get('Attachments',[]));matches=[x for x in attachments if x.get('VpcId')==vpc]
            if len(matches)!=1:raise ValueError('Internet gateway outside selected VPC')
            a=matches[0];add('internet_gateway',_id(g['InternetGatewayId'],'igw'),{'vpc_id':vr,'observed_state':a.get('State')})
        for g in inv['NatGateways']:
            scope(g);attrs={'vpc_id':vr,'observed_state':g.get('State'),'connectivity_type':g.get('ConnectivityType')}
            if g.get('SubnetId'):attrs['subnet_id']=_ref('subnet',g['SubnetId'],'subnet')
            else:warnings.add('NAT gateway without known subnet; placement not inferred.')
            if doc['format']==FORMAT_V2:attrs['observed_nat_addresses']=g.get('NatGatewayAddresses',[])
            add('nat_gateway',_id(g['NatGatewayId'],'nat'),attrs)
        def sg_rules(rows):
            result=[]
            for r in _arr(rows):
                rule={'protocol':r['IpProtocol'],'cidr_blocks':[_net(x['CidrIp'],4) for x in r.get('IpRanges',[])], 'ipv6_cidr_blocks':[_net(x['CidrIpv6'],6) for x in r.get('Ipv6Ranges',[])], 'security_groups':[_ref('security_group',x['GroupId'],'sg') for x in r.get('UserIdGroupPairs',[]) if x.get('GroupId')], 'prefix_list_ids':[_id(x['PrefixListId'],'pl') for x in r.get('PrefixListIds',[])]}
                for a,b in [('FromPort','from_port'),('ToPort','to_port')]:
                    if a in r:rule[b]=r[a]
                result.append(rule)
            return result
        for g in inv['SecurityGroups']:
            scope(g);add('security_group',_id(g['GroupId'],'sg'),{'vpc_id':vr,'ingress':sg_rules(g['IpPermissions']),'egress':sg_rules(g['IpPermissionsEgress'])})
        for a in inv['NetworkAcls']:
            scope(a);attrs={'vpc_id':vr,'subnet_ids':[_ref('subnet',x['SubnetId'],'subnet') for x in a['Associations']],'ingress':[],'egress':[]}
            for e in a['Entries']:
                if type(e['Egress']) is not bool:raise ValueError('Invalid ACL direction')
                r={'rule_no':e['RuleNumber'],'protocol':e['Protocol'],'action':e['RuleAction']}
                if 'CidrBlock' in e:r['cidr_block']=_net(e['CidrBlock'],4)
                if 'Ipv6CidrBlock' in e:r['ipv6_cidr_block']=_net(e['Ipv6CidrBlock'],6)
                for source,target in [('From','from_port'),('To','to_port')]:
                    if source in e.get('PortRange',{}):r[target]=e['PortRange'][source]
                for source,target in [('Type','icmp_type'),('Code','icmp_code')]:
                    if source in e.get('IcmpTypeCode',{}):r[target]=e['IcmpTypeCode'][source]
                attrs['egress' if e['Egress'] else 'ingress'].append(r)
            add('network_acl',_id(a['NetworkAclId'],'acl'),attrs)
        for reservation in inv['Reservations']:
            for i in _arr(reservation['Instances']):
                scope(i);a={'vpc_id':vr,'observed_state':i.get('State',{}).get('Name'),'vpc_security_group_ids':[_ref('security_group',x['GroupId'],'sg') for x in i.get('SecurityGroups',[])], 'observed_interfaces':[_ref('network_interface',x['NetworkInterfaceId'],'eni') for x in i.get('NetworkInterfaces',[])]}
                if i.get('SubnetId'):a['subnet_id']=_ref('subnet',i['SubnetId'],'subnet')
                optional_ip(i,a);add('instance',_id(i['InstanceId'],'i'),a)
        for i in inv['NetworkInterfaces']:
            scope(i);a={'vpc_id':vr,'subnet_id':_ref('subnet',i['SubnetId'],'subnet'),'security_groups':[_ref('security_group',g['GroupId'],'sg') for g in i['Groups']], 'private_ips':[_ip(x['PrivateIpAddress']) for x in i.get('PrivateIpAddresses',[])], 'observed_state':i.get('Status'),'observed_interface_type':i.get('InterfaceType'),'requester_managed':i.get('RequesterManaged')}
            optional_ip(i,a)
            a['observed_device_index']=i.get('Attachment',{}).get('DeviceIndex')
            if doc['format']==FORMAT_V2:
                a['observed_address_associations']=[{'private_ip':x.get('PrivateIpAddress'),'association':x.get('Association',{})} for x in i.get('PrivateIpAddresses',[])]
                if i.get('Association'):a['observed_address_associations'].append({'private_ip':i.get('PrivateIpAddress'),'association':i['Association']})
            if i.get('Attachment',{}).get('InstanceId'):a['instance_id']=_ref('instance',i['Attachment']['InstanceId'],'i')
            add('network_interface',_id(i['NetworkInterfaceId'],'eni'),a)
        targets={'NatGatewayId':('nat_gateway_id','nat_gateway','nat'),'NetworkInterfaceId':('network_interface_id','network_interface','eni'),'InstanceId':('instance_id','instance','i'),'TransitGatewayId':('transit_gateway_id','transit_gateway','tgw'),'VpcPeeringConnectionId':('vpc_peering_connection_id','vpc_peering_connection','pcx'),'EgressOnlyInternetGatewayId':('egress_only_gateway_id','egress_only_internet_gateway','eigw'),'LocalGatewayId':('local_gateway_id','local_gateway','lgw'),'CarrierGatewayId':('carrier_gateway_id','carrier_gateway','cagw'),'VpcEndpointId':('vpc_endpoint_id','vpc_endpoint','vpce')}
        for t in inv['RouteTables']:
            scope(t);tid=_id(t['RouteTableId'],'rtb');tr=_ref('route_table',tid,'rtb');routes=[]
            for r in t['Routes']:
                a={'observed_state':r.get('State'),'observed_origin':r.get('Origin')}
                if 'DestinationCidrBlock' in r:a['cidr_block']=_net(r['DestinationCidrBlock'],4)
                if 'DestinationIpv6CidrBlock' in r:a['ipv6_cidr_block']=_net(r['DestinationIpv6CidrBlock'],6)
                if 'DestinationPrefixListId' in r:a['destination_prefix_list_id']=_id(r['DestinationPrefixListId'],'pl')
                # Preserve inactive targets as evidence, not as active topology links.
                if r.get('State')!='active':
                    warnings.add('Inactive/blackhole route: no resolved target link asserted.')
                    a['observed_target_ids']=[r[k] for k in ('GatewayId','CoreNetworkArn',*targets) if k in r and k!='CoreNetworkArn'];routes.append(a);continue
                if 'GatewayId' in r:
                    val=r['GatewayId'];a['gateway_id']='local' if val=='local' else _ref('internet_gateway',val,'igw') if val.startswith('igw-') else val
                for key,(attr,kind,prefix) in targets.items():
                    if key in r:a[attr]=_ref(kind,r[key],prefix)
                if 'CoreNetworkArn' in r:warnings.add('Core network route target not modeled.')
                routes.append(a)
            add('route_table',tid,{'vpc_id':vr,'route':routes})
            for assoc in t['Associations']:
                if assoc.get('AssociationState',{}).get('State')!='associated':warnings.add('Route table association state not confirmed; link omitted.');continue
                aid=_id(assoc['RouteTableAssociationId'],'rtbassoc')
                if assoc.get('Main') is True:add('main_route_table_association',aid,{'vpc_id':vr,'route_table_id':tr})
                elif assoc.get('SubnetId'):add('route_table_association',aid,{'subnet_id':_ref('subnet',assoc['SubnetId'],'subnet'),'route_table_id':tr})
                else:warnings.add('Gateway route table association not modeled.')
        from backend.analyzer.reference_graph_analyzer import analyze_reference_graph
        if analyze_reference_graph(resources)['issues']:warnings.add('Some referenced resources were not collected; no missing links are invented.')
        # The old graph synthesizes implicit main routes. The web integration removes these.
        identity=('sha256-aws-v2:' if doc['format']==FORMAT_V2 else 'sha256-aws-v1:')+hashlib.sha256(raw).hexdigest()
        return resources,identity,{'files':[{'name':name,'bytes':len(raw)}],'resource_count':len(resources),'analysis_restricted':True,'warnings':sorted(warnings),'input_type':'AWS_INVENTORY_JSON','region':region,'vpc_id':vpc,'collected_at':time.isoformat(),'relationship_source':'AWS_ID_RELATIONSHIPS_UNVERIFIED_SNAPSHOT'}
    except (KeyError,TypeError,AttributeError,OverflowError,RecursionError) as exc:raise ValueError('Invalid or incomplete AWS inventory fields') from exc
