"""Configuration address mapping candidates, not observed NAT or session state."""
from ipaddress import IPv4Address, IPv4Network


def _public(value):
    try:
        addr = IPv4Address(value) if isinstance(value, str) else None
        return bool(addr and addr.is_global and not addr.is_multicast and not addr.is_reserved)
    except ValueError:
        return False


def _unique_owner(inv, ip, eni_id):
    owners = [e['NetworkInterfaceId'] for e in inv['NetworkInterfaces']
              if e.get('PrivateIpAddress') == ip or any(a.get('PrivateIpAddress') == ip for a in e.get('PrivateIpAddresses', []))]
    return owners == [eni_id]


def _public_claims(inv, ip):
    return {e['NetworkInterfaceId'] for e in inv['NetworkInterfaces']
            if e.get('Association', {}).get('PublicIp') == ip or any(a.get('Association', {}).get('PublicIp') == ip for a in e.get('PrivateIpAddresses', []))}


def mapping_evidence(inv, endpoint, nat=None):
    """Called only after a supported complete egress route candidate.

    Single primary IPv4 address only. Do not infer missing mappings or NAT ports.
    """
    source = endpoint['private_ip']
    result = dict(kind='PUBLIC_NAT_THEN_IGW' if nat else 'IGW_PUBLIC_IPV4_MAPPING',
                  state='UNKNOWN', original_source_ip=source, translated_private_ip=None,
                  translated_public_ip=None, translated_source_port=None,
                  runtime_translation_observed=False)

    def unknown(reason):
        return dict(result, reason=reason)

    if nat is None:
        eni = next(e for e in inv['NetworkInterfaces'] if e['NetworkInterfaceId'] == endpoint['eni_id'])
        address = eni['PrivateIpAddresses'][0]
        association = address.get('Association', {})
        top = eni.get('Association', {})
        instance = next(i for r in inv['Reservations'] for i in r['Instances'] if i['InstanceId'] == endpoint['instance_id'])
        if any(a.get('CarrierIp') or a.get('CustomerOwnedIp') for a in (top, association)):
            return unknown('NON_STANDARD_PUBLIC_ASSOCIATION')
        public = association.get('PublicIp')
        if not public or address.get('Primary') is not True:
            return unknown('PRIMARY_PUBLIC_ASSOCIATION_NOT_CONFIRMED')
        if top.get('PublicIp') != public or instance.get('PublicIpAddress') != public:
            return unknown('PUBLIC_ASSOCIATION_INCONSISTENT')
        if not _public(public) or _public_claims(inv, public) != {eni['NetworkInterfaceId']}:
            return unknown('PUBLIC_ADDRESS_INVALID_OR_AMBIGUOUS')
        if any(a.get('PublicIp') == public for g in inv['NatGateways'] for a in g.get('NatGatewayAddresses', [])):
            return unknown('PUBLIC_ADDRESS_INVALID_OR_AMBIGUOUS')
        private = source
    else:
        addresses = nat.get('NatGatewayAddresses', [])
        if len(addresses) != 1:
            return unknown('NAT_SINGLE_ADDRESS_NOT_CONFIRMED')
        address = addresses[0]
        if address.get('Status') != 'succeeded' or address.get('IsPrimary') is not True:
            return unknown('NAT_ADDRESS_STATE_NOT_CONFIRMED')
        private, public = address.get('PrivateIp'), address.get('PublicIp')
        eni_id = address.get('NetworkInterfaceId')
        matches = [e for e in inv['NetworkInterfaces'] if e['NetworkInterfaceId'] == eni_id]
        if len(matches) != 1:
            return unknown('NAT_ADDRESS_ENI_MISSING')
        eni = matches[0]
        if (eni.get('SubnetId') != nat.get('SubnetId') or eni.get('Status') != 'in-use'
                or eni.get('InterfaceType') != 'nat_gateway' or eni.get('RequesterManaged') is not True
                or eni.get('PrivateIpAddress') != private
                or [a.get('PrivateIpAddress') for a in eni.get('PrivateIpAddresses', [])] != [private]
                or not private or not _unique_owner(inv, private, eni_id)):
            return unknown('NAT_ADDRESS_ENI_INCONSISTENT')
        subnet = next(s for s in inv['Subnets'] if s['SubnetId'] == nat['SubnetId'])
        net = IPv4Network(subnet['CidrBlock'])
        try:
            ip = IPv4Address(private)
        except ValueError:
            return unknown('NAT_PRIVATE_ADDRESS_INVALID')
        if ip not in net or int(ip)-int(net.network_address)<4 or ip==net.broadcast_address:
            return unknown('NAT_PRIVATE_ADDRESS_INVALID')
        claims = _public_claims(inv, public) if public else set()
        # NAT ENI association is optional; if provided it must agree with the NAT object.
        eni_public = [a.get('PublicIp') for a in [eni.get('Association', {}), eni['PrivateIpAddresses'][0].get('Association', {})] if a.get('PublicIp')]
        if not _public(public) or claims-{eni_id} or any(p != public for p in eni_public):
            return unknown('NAT_PUBLIC_ADDRESS_INVALID_OR_AMBIGUOUS')
        if sum(a.get('PublicIp') == public for g in inv['NatGateways'] for a in g.get('NatGatewayAddresses', [])) != 1:
            return unknown('NAT_PUBLIC_ADDRESS_INVALID_OR_AMBIGUOUS')
        # Require explicit EIP association identifiers, not merely a public address string.
        import re
        if not all(isinstance(address.get(k), str) and re.fullmatch(prefix+r'-[0-9a-f]{8,17}',address[k]) for k,prefix in [('AllocationId','eipalloc'),('AssociationId','eipassoc')]):
            return unknown('NAT_EIP_ASSOCIATION_NOT_CONFIRMED')
    return dict(result, state='ADDRESS_MAPPING_CANDIDATE', reason='OBSERVED_CONFIGURATION_ADDRESS_MAPPING',
                translated_private_ip=private, translated_public_ip=public)
