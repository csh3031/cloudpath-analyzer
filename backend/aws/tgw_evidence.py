"""Offline, bounded single-TGW IPv4 route evidence (not live reachability)."""
import hashlib
import re
from ipaddress import IPv4Address, IPv4Network

from backend.aws.peering_evidence import _load, _timestamp, _primary_only, TARGET_KEYS
from backend.aws.endpoint_evidence import lookup_observed_endpoint
from backend.aws.route_evidence import select_subnet_ipv4_route
from backend.iac.plan_adapter import _read


def _id(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(prefix + r'-[0-9a-f]{8,17}', value):
        raise ValueError('Invalid TGW evidence identifier: '+prefix)
    return value


def _rows(value, key, prefix):
    if not isinstance(value, list) or len(value)>300:
        raise ValueError('Invalid bounded TGW evidence list')
    out={}
    for row in value:
        if not isinstance(row,dict):
            raise ValueError('Invalid TGW evidence row')
        ident=_id(row.get(key),prefix)
        if ident in out:
            raise ValueError('Duplicate TGW evidence identifier')
        out[ident]=row
    return out


def _select_tgw(routes, dst):
    if not isinstance(routes,list) or len(routes)>300:
        raise ValueError('Invalid TGW routes list')
    matches=[]
    for r in routes:
        if not isinstance(r,dict):
            raise ValueError('Invalid TGW route')
        if r.get('PrefixListId') or r.get('DestinationPrefixListId') or not r.get('DestinationCidrBlock'):
            return dict(status='UNKNOWN',reason='TGW_DESTINATION_UNRESOLVED')
        try:
            net=IPv4Network(r['DestinationCidrBlock'])
        except (ValueError,TypeError):
            return dict(status='UNKNOWN',reason='TGW_NON_IPV4_OR_INVALID_ROUTE')
        if dst in net:
            matches.append((net.prefixlen,r))
    if not matches:
        return dict(status='UNKNOWN',reason='TGW_MATCHING_ROUTE_NOT_OBSERVED')
    longest=max(n for n,_ in matches)
    chosen=[r for n,r in matches if n==longest]
    # Do not infer priority among different equal-prefix types in this unit.
    if len(chosen)!=1:
        return dict(status='UNKNOWN',reason='TGW_EQUAL_PREFIX_PRIORITY_UNSUPPORTED')
    r=chosen[0]
    # Keep only bounded, relevant evidence, not arbitrary uploaded fields.
    target=r.get('TransitGatewayAttachments',[])
    if not isinstance(target,list) or len(target)>300 or any(not isinstance(x,dict) for x in target):
        raise ValueError('Invalid TGW route attachments')
    ids=[_id(x.get('TransitGatewayAttachmentId'),'tgw-attach') for x in target]
    result=dict(selected_route=dict(DestinationCidrBlock=r['DestinationCidrBlock'],State=r.get('State'),Type=r.get('Type'),attachment_ids=ids))
    if r.get('State')=='blackhole':
        return dict(result,status='BLOCKED',reason='TGW_SELECTED_BLACKHOLE')
    if r.get('State')!='active' or r.get('Type') not in ('static','propagated') or len(ids)!=1:
        return dict(result,status='UNKNOWN',reason='TGW_ROUTE_TARGET_UNCONFIRMED')
    return dict(result,status='ACTIVE_ROUTE_CANDIDATE',reason='TGW_ACTIVE_ROUTE')


def trace_transit_gateway(source_raw,destination_raw,tgw_raw,source_ip,destination_ip):
    aid,a,ai=_load(source_raw); bid,b,bi=_load(destination_raw)
    doc=_read(tgw_raw)
    if set(doc)!={'format','collected_at','region','TransitGateways','TransitGatewayVpcAttachments','TransitGatewayRouteTables','route_exports'} or doc['format']!='cloudpath-tgw-evidence-v1':
        raise ValueError('Expected cloudpath-tgw-evidence-v1 wrapper')
    gateways=_rows(doc['TransitGateways'],'TransitGatewayId','tgw')
    attachments=_rows(doc['TransitGatewayVpcAttachments'],'TransitGatewayAttachmentId','tgw-attach')
    tables=_rows(doc['TransitGatewayRouteTables'],'TransitGatewayRouteTableId','tgw-rtb')
    exports=_rows(doc['route_exports'],'TransitGatewayRouteTableId','tgw-rtb')
    times=[_timestamp(x) for x in (a['collected_at'],b['collected_at'],doc['collected_at'])]
    gap=(max(times)-min(times)).total_seconds()
    result=dict(analysis_type='STATIC_AWS_SINGLE_TGW_ROUTE',source_input_identity=aid,destination_input_identity=bid,
                tgw_input_identity='sha256-tgw-v1:'+hashlib.sha256(tgw_raw).hexdigest(),source_vpc_id=a['vpc_id'],destination_vpc_id=b['vpc_id'],
                source_ip=source_ip,destination_ip=destination_ip,time_gap_seconds=gap,transit_gateway_id=None,
                source_endpoint=None,destination_endpoint=None,request=None,response=None,request_status='NOT_EVALUATED',response_status='NOT_EVALUATED',
                policy_status='NOT_EVALUATED',session_status='UNKNOWN',live_observation=False,
                limitations=['Uploaded normalized evidence is unauthenticated and non-atomic; completeness asserted, not verified.',
                             'Same-region single TGW, two nonoverlapping primary IPv4 VPC CIDRs, single-ENI EC2; same-AZ attachment subnet required on both sides for this bounded model.',
                             'No prefix-list expansion, equal-prefix priority, appliance mode, VPN, Direct Connect or TGW peering inference.',
                             'No SG/NACL, host, runtime, account identity or AWS API verification.'])
    def finish(status,reason): return dict(result,status=status,reason=reason)
    if a['vpc_id']==b['vpc_id'] or a['region']!=b['region'] or doc['region']!=a['region']:
        return finish('UNKNOWN','VPC_OR_REGION_SCOPE_UNSUPPORTED')
    if gap>300: return finish('UNKNOWN','SNAPSHOT_TIME_GAP')
    av,bv=ai['Vpcs'][0],bi['Vpcs'][0]
    if not _primary_only(av) or not _primary_only(bv) or IPv4Network(av['CidrBlock']).overlaps(IPv4Network(bv['CidrBlock'])):
        return finish('UNKNOWN','VPC_CIDR_SCOPE_UNSUPPORTED')
    ae,be=lookup_observed_endpoint(source_raw,source_ip),lookup_observed_endpoint(destination_raw,destination_ip)
    result.update(source_endpoint=ae,destination_endpoint=be)
    if any(e['status']!='ENDPOINT_CANDIDATE' for e in (ae,be)):
        return finish('UNKNOWN','ENDPOINT_NOT_CONFIRMED')
    def find_attach(vpc):
        rows=[r for r in attachments.values() if r.get('VpcId')==vpc]
        return rows[0] if len(rows)==1 else None
    aa,ba=find_attach(a['vpc_id']),find_attach(b['vpc_id'])
    if aa is None or ba is None: return finish('UNKNOWN','VPC_ATTACHMENT_MISSING_OR_AMBIGUOUS')
    gateway=aa.get('TransitGatewayId')
    if not isinstance(gateway,str) or gateway!=ba.get('TransitGatewayId') or gateway not in gateways or gateways[gateway].get('State')!='available':
        return finish('UNKNOWN','SHARED_TGW_NOT_CONFIRMED')
    result['transit_gateway_id']=gateway
    if any(r.get('State')!='available' or not isinstance(r.get('Options'),dict) or r['Options'].get('ApplianceModeSupport')!='disable' for r in (aa,ba)):
        return finish('UNKNOWN','ATTACHMENT_STATE_OR_MODE_UNCONFIRMED')
    def attachment_subnet(inv, endpoint, attach):
        subnets={s['SubnetId']:s for s in inv['Subnets']}
        workload=subnets[endpoint['subnet_id']]; az=workload.get('AvailabilityZone')
        ids=attach.get('SubnetIds')
        if not isinstance(ids,list) or not ids or any(not isinstance(x,str) for x in ids) or len(ids)!=len(set(ids)) or any(x not in subnets for x in ids): return None
        if not isinstance(az,str) or not az: return None
        rows=[subnets[x] for x in ids if subnets[x].get('AvailabilityZone')==az and subnets[x].get('State')=='available']
        return rows[0]['SubnetId'] if len(rows)==1 else None
    asub,bsub=attachment_subnet(ai,ae,aa),attachment_subnet(bi,be,ba)
    if not asub or not bsub: return finish('UNKNOWN','SAME_AZ_ATTACHMENT_SUBNET_NOT_CONFIRMED')
    def direction(inv,other,ep,src,dst,target_subnet,dest):
        out=dict(source_attachment_id=src['TransitGatewayAttachmentId'],destination_attachment_id=dst['TransitGatewayAttachmentId'],destination_attachment_subnet_id=target_subnet,source_route=None,tgw_route_table_id=None,tgw_route=None,destination_local_route=None)
        def stop(status,reason): return dict(out,status=status,reason=reason)
        r=select_subnet_ipv4_route(inv,ep['subnet_id'],IPv4Address(dest)); out['source_route']=r
        if r['status']!='ACTIVE_ROUTE_CANDIDATE': return stop(r['status'],r['reason'])
        selected=r['selected_route']
        if [k for k in TARGET_KEYS if k in selected]!=['TransitGatewayId'] or selected['TransitGatewayId']!=gateway:
            return stop('UNKNOWN','SOURCE_ROUTE_NOT_SELECTED_TGW')
        # Association is normalized from DescribeTransitGatewayAttachments, not inferred from propagation.
        assoc=src.get('Association')
        if not isinstance(assoc,dict) or assoc.get('State')!='associated': return stop('UNKNOWN','TGW_ASSOCIATION_NOT_CONFIRMED')
        tid=assoc.get('TransitGatewayRouteTableId')
        if not isinstance(tid,str) or tid not in tables or tables[tid].get('TransitGatewayId')!=gateway or tables[tid].get('State')!='available': return stop('UNKNOWN','TGW_TABLE_NOT_CONFIRMED')
        out['tgw_route_table_id']=tid
        export=exports.get(tid)
        if not export or export.get('AdditionalRoutesAvailable') is not False or export.get('complete') is not True:
            return stop('UNKNOWN','TGW_ROUTE_EXPORT_INCOMPLETE')
        r=_select_tgw(export.get('Routes'),IPv4Address(dest)); out['tgw_route']=r
        if r['status']!='ACTIVE_ROUTE_CANDIDATE': return stop(r['status'],r['reason'])
        if r['selected_route']['attachment_ids']!=[dst['TransitGatewayAttachmentId']]: return stop('UNKNOWN','TGW_ROUTE_NOT_DESTINATION_ATTACHMENT')
        r=select_subnet_ipv4_route(other,target_subnet,IPv4Address(dest)); out['destination_local_route']=r
        if r['status']!='ACTIVE_ROUTE_CANDIDATE': return stop(r['status'],r['reason'])
        selected=r['selected_route']
        if [k for k in TARGET_KEYS if k in selected]!=['GatewayId'] or selected['GatewayId']!='local' or selected['DestinationCidrBlock']!=other['Vpcs'][0]['CidrBlock']:
            return stop('UNKNOWN','DESTINATION_ATTACHMENT_LOCAL_ROUTE_NOT_CONFIRMED')
        return stop('TGW_ROUTE_CANDIDATE','OBSERVED_SINGLE_TGW_ROUTE')
    req=direction(ai,bi,ae,aa,ba,bsub,destination_ip); resp=direction(bi,ai,be,ba,aa,asub,source_ip)
    result.update(request=req,response=resp,request_status=req['status'],response_status=resp['status'])
    if 'BLOCKED' in (req['status'],resp['status']): return finish('BLOCKED','STATIC_ROUTE_BLOCKER')
    if req['status']==resp['status']=='TGW_ROUTE_CANDIDATE': return finish('BIDIRECTIONAL_ROUTE_CANDIDATE','OBSERVED_SINGLE_TGW_ROUTES')
    return finish('UNKNOWN','BIDIRECTIONAL_TGW_ROUTE_NOT_CONFIRMED')
