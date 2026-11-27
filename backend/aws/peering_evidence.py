"""Bounded offline direct VPC peering route evidence; no session verdict."""
import hashlib
import re
from datetime import datetime
from ipaddress import IPv4Address, IPv4Network

from backend.aws.snapshot import load_aws_snapshot, sanitize_inventory
from backend.aws.endpoint_evidence import lookup_observed_endpoint
from backend.aws.route_evidence import select_subnet_ipv4_route
from backend.iac.plan_adapter import _read

TARGET_KEYS = ('GatewayId', 'NatGatewayId', 'TransitGatewayId', 'VpcPeeringConnectionId',
               'NetworkInterfaceId', 'InstanceId', 'EgressOnlyInternetGatewayId',
               'LocalGatewayId', 'CarrierGatewayId', 'CoreNetworkArn', 'VpcEndpointId')


def _timestamp(value):
    try:
        t = datetime.fromisoformat(value)
        if t.tzinfo is None:
            raise ValueError()
        return t
    except (ValueError, TypeError):
        raise ValueError('Peering collection timestamp requires timezone') from None


def _load(raw):
    _, identity, meta = load_aws_snapshot(raw)
    doc = _read(raw)
    return identity, meta, sanitize_inventory(doc['inventory'], version=doc['format'])


def _primary_only(vpc):
    primary = IPv4Network(vpc['CidrBlock'])
    return all(IPv4Network(a['CidrBlock']) == primary for a in vpc.get('CidrBlockAssociationSet', []))


def trace_direct_peering(source_raw, destination_raw, peering_raw, source_ip, destination_ip):
    """Compare two independently validated inventory snapshots and a dated Describe export.

    All results are configuration candidates, not proof of policy or live delivery.
    No cross-account identity verification, transitive routing or TGW inference.
    """
    aid, a, ai = _load(source_raw)
    bid, b, bi = _load(destination_raw)
    evidence = _read(peering_raw)
    if not isinstance(evidence, dict) or set(evidence) != {'collected_at', 'VpcPeeringConnections'}:
        raise ValueError('Expected dated VpcPeeringConnections export')
    stamp = _timestamp(evidence['collected_at'])
    rows = evidence['VpcPeeringConnections']
    if not isinstance(rows, list) or len(rows) > 300:
        raise ValueError('Invalid peering connection list')
    times = [_timestamp(a['collected_at']), _timestamp(b['collected_at']), stamp]
    gap = (max(times)-min(times)).total_seconds()
    result = dict(analysis_type='STATIC_AWS_DIRECT_PEERING_ROUTE',
                  source_input_identity=aid, destination_input_identity=bid,
                  peering_input_identity='sha256-peering-v1:'+hashlib.sha256(peering_raw).hexdigest(),
                  source_vpc_id=a['vpc_id'], destination_vpc_id=b['vpc_id'],
                  source_ip=source_ip, destination_ip=destination_ip,
                  time_gap_seconds=gap, peering_id=None, request_route=None, response_route=None,
                  source_endpoint=None, destination_endpoint=None,
                  request_status='NOT_EVALUATED', response_status='NOT_EVALUATED',
                  policy_status='NOT_EVALUATED', session_status='UNKNOWN', live_observation=False,
                  limitations=['Independent unauthenticated non-atomic snapshots; 300s time heuristic only.',
                               'Same-region direct peering, primary IPv4 CIDRs and single-ENI EC2 only.',
                               'No SG/NACL, account identity, external forwarding or runtime verification.',
                               'No transitive peering, TGW, AWS API calls or packets.'])
    def finish(status, reason):
        return dict(result, status=status, reason=reason)
    if a['vpc_id'] == b['vpc_id']:
        return finish('UNKNOWN','SAME_VPC_NOT_PEERING')
    if a['region'] != b['region']:
        return finish('UNKNOWN','INTER_REGION_UNSUPPORTED')
    if gap > 300:
        return finish('UNKNOWN','SNAPSHOT_TIME_GAP')
    av,bv = ai['Vpcs'][0],bi['Vpcs'][0]
    if not _primary_only(av) or not _primary_only(bv):
        return finish('UNKNOWN','SECONDARY_CIDR_UNSUPPORTED')
    if IPv4Network(av['CidrBlock']).overlaps(IPv4Network(bv['CidrBlock'])):
        return finish('UNKNOWN','OVERLAPPING_VPC_CIDRS')
    ae,be = lookup_observed_endpoint(source_raw,source_ip),lookup_observed_endpoint(destination_raw,destination_ip)
    result.update(source_endpoint=ae,destination_endpoint=be)
    if any(e['status'] != 'ENDPOINT_CANDIDATE' for e in (ae,be)):
        return finish('UNKNOWN','ENDPOINT_NOT_CONFIRMED')
    # Validate relevant connection fields without returning full AWS export or account data.
    candidates=[]; seen=set()
    for row in rows:
        if not isinstance(row,dict):
            raise ValueError('Invalid peering connection object')
        pcx=row.get('VpcPeeringConnectionId')
        if not isinstance(pcx,str) or not re.fullmatch(r'pcx-[0-9a-f]{8,17}',pcx) or pcx in seen:
            raise ValueError('Invalid or duplicate peering ID')
        seen.add(pcx)
        x,y=row.get('RequesterVpcInfo'),row.get('AccepterVpcInfo')
        if not isinstance(x,dict) or not isinstance(y,dict):
            raise ValueError('Missing peering endpoint information')
        if not all(isinstance(z.get('VpcId'),str) and re.fullmatch(r'vpc-[0-9a-f]{8,17}',z['VpcId']) for z in (x,y)):
            raise ValueError('Invalid peering VPC ID')
        if {x['VpcId'],y['VpcId']} == {a['vpc_id'],b['vpc_id']}:
            candidates.append((pcx,row,x,y))
    if len(candidates)!=1:
        return finish('UNKNOWN','DIRECT_PEERING_MISSING_OR_AMBIGUOUS')
    pcx,row,x,y=candidates[0]
    result['peering_id']=pcx
    for side in (x,y):
        expected = av if side['VpcId']==a['vpc_id'] else bv
        if side.get('Region')!=a['region'] or side.get('CidrBlock')!=expected['CidrBlock']:
            return finish('UNKNOWN','PEERING_VPC_METADATA_MISMATCH')
    state=row.get('Status')
    if not isinstance(state,dict) or state.get('Code')!='active':
        return finish('UNKNOWN','PEERING_NOT_CONFIRMED_ACTIVE')
    def direction(inv,endpoint,peer):
        route=select_subnet_ipv4_route(inv,endpoint['subnet_id'],IPv4Address(peer))
        if route['status']!='ACTIVE_ROUTE_CANDIDATE':
            return route
        selected=route['selected_route']
        if [k for k in TARGET_KEYS if k in selected]!=['VpcPeeringConnectionId'] or selected['VpcPeeringConnectionId']!=pcx:
            return dict(route,status='UNKNOWN',reason='SELECTED_ROUTE_NOT_DIRECT_PEER')
        return dict(route,status='PEERING_ROUTE_CANDIDATE',reason='OBSERVED_ACTIVE_DIRECT_PEER_ROUTE')
    req=direction(ai,ae,destination_ip); resp=direction(bi,be,source_ip)
    result.update(request_route=req,response_route=resp,request_status=req['status'],response_status=resp['status'])
    if 'BLOCKED' in (req['status'],resp['status']):
        return finish('BLOCKED','SELECTED_BLACKHOLE_ROUTE')
    if req['status']==resp['status']=='PEERING_ROUTE_CANDIDATE':
        return finish('BIDIRECTIONAL_ROUTE_CANDIDATE','OBSERVED_DIRECT_PEER_ROUTES')
    return finish('UNKNOWN','BIDIRECTIONAL_ROUTE_NOT_CONFIRMED')
