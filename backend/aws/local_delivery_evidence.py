"""Conditional direct same-subnet delivery; no runtime L2 or host routing attestation."""
from ipaddress import IPv4Address, IPv4Network
from backend.aws.route_evidence import select_subnet_ipv4_route


def same_subnet_delivery(inv, start, end, *, prefix_lists=None):
    """Caller must already correlate endpoints with ENIs in this inventory.

    Require normal local configuration as a conservative guard, not as a
    traversed route lookup. Unusual routing stays UNKNOWN, not BLOCKED.
    """
    result = dict(status='UNKNOWN', reason='SAME_SUBNET_DIRECT_SCOPE_UNCONFIRMED',
                  path_kind='SAME_SUBNET_DIRECT', route_lookup=None)
    if start['subnet_id'] != end['subnet_id'] or start['eni_id']==end['eni_id'] or start['private_ip']==end['private_ip']:
        return result
    vpc=inv['Vpcs'][0]; net=IPv4Network(vpc['CidrBlock'])
    if vpc.get('State')!='available': return result
    for ep in (start,end):
        ip=IPv4Address(ep['private_ip']); matches=[s for s in inv['Subnets'] if ip in IPv4Network(s['CidrBlock'])]
        if len(matches)!=1 or matches[0]['SubnetId']!=ep['subnet_id'] or matches[0].get('State')!='available': return result
        sn=IPv4Network(matches[0]['CidrBlock'])
        if not sn.subnet_of(net) or int(ip)-int(sn.network_address)<4 or ip==sn.broadcast_address: return result
    selected=select_subnet_ipv4_route(inv,start['subnet_id'],IPv4Address(end['private_ip']),prefix_lists=prefix_lists)
    result['configuration_guard']=selected
    route=selected['selected_route'] or {}
    targets=set(route)&{'GatewayId','NatGatewayId','TransitGatewayId','VpcPeeringConnectionId','NetworkInterfaceId','InstanceId','VpcEndpointId','LocalGatewayId','CarrierGatewayId','CoreNetworkArn','EgressOnlyInternetGatewayId'}
    if selected['status']!='ACTIVE_ROUTE_CANDIDATE' or targets!={'GatewayId'} or route.get('GatewayId')!='local' or route.get('DestinationCidrBlock')!=str(net) or any(t.get('PropagatingVgws') for t in inv['RouteTables'] if t['RouteTableId']==selected['route_table_id']):
        return dict(result,reason='SAME_SUBNET_NORMAL_LOCAL_CONFIGURATION_UNCONFIRMED')
    return dict(result,status='ALLOW_CANDIDATE',reason='CONDITIONAL_SAME_SUBNET_DIRECT_DELIVERY',assumptions=['DIRECT_ON_LINK_DELIVERY_NO_MIDDLEBOX','HOST_NETWORK_CONFIGURATION_UNVERIFIED'])


def subnet_policy(acl_check, inv, start, end, egress, port, local):
    if start['subnet_id']==end['subnet_id']:
        if local['status']=='ALLOW_CANDIDATE':
            return dict(status='NOT_APPLICABLE',reason='DIRECT_SAME_SUBNET_NO_NACL_BOUNDARY')
        return dict(status='UNKNOWN',reason='SAME_SUBNET_NACL_APPLICABILITY_UNCONFIRMED')
    return acl_check(inv['NetworkAcls'],start,end,egress,port)
