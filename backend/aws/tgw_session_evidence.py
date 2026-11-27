"""Bounded offline TGW TCP policy checks; no packet or runtime observation."""
from ipaddress import IPv4Address, IPv4Network

from backend.aws.peering_evidence import _load
from backend.aws.policy_evidence import _acl, _sg, _port
from backend.aws.tgw_evidence import trace_transit_gateway


def analyze_tgw_session(source_raw, destination_raw, tgw_raw, source_ip, destination_ip,
                        source_port, destination_port):
    if not _port(source_port) or not _port(destination_port):
        raise ValueError('Expected explicit TCP ports in 1..65535')
    route = trace_transit_gateway(source_raw, destination_raw, tgw_raw, source_ip, destination_ip)
    _, _, ai = _load(source_raw)
    _, _, bi = _load(destination_raw)
    ae, be = route['source_endpoint'], route['destination_endpoint']
    request, response = [], []
    result = dict(analysis_type='STATIC_AWS_SINGLE_TGW_TCP_CONSTRAINTS',
                  **{k: route[k] for k in ('source_input_identity','destination_input_identity','tgw_input_identity')},
                  scenario=dict(source_ip=source_ip,destination_ip=destination_ip,source_port=source_port,destination_port=destination_port,protocol='tcp'),
                  route=route,request=request,response=response,live_observation=False,
                  limitations=['Uploaded non-atomic snapshots; authenticity, account and AZ identity unverified.',
                               'Same-region single TGW, primary IPv4, single-ENI EC2 and same-AZ attachment model only.',
                               'TGW NACL checks distinguish shared and distinct workload/attachment subnets.',
                               'SG references and prefix lists unresolved; no runtime SG tracking, host or application checks.',
                               'Conditional reply is not a packet observation. No AWS calls or packet transmission.'])

    def reserved(inv, ep):
        net=IPv4Network(next(s['CidrBlock'] for s in inv['Subnets'] if s['SubnetId']==ep['subnet_id']))
        ip=IPv4Address(ep['private_ip'])
        return int(ip)-int(net.network_address)<4 or ip==net.broadcast_address

    def add(rows, stage, evidence, active, ep=None, subnet=None):
        rows.append(dict(stage=stage,evaluation_mode=('CONDITIONAL_CHECK' if rows is response else 'PREDICTED_PATH') if active else 'INDEPENDENT_CHECK',
                         vpc_id=ep['vpc_id'] if ep else None, subnet_id=subnet or (ep['subnet_id'] if ep else None),
                         eni_id=ep['eni_id'] if ep and (subnet is None or subnet==ep['subnet_id']) else None, **evidence))
        return active and evidence['status'] in ('ALLOW_CANDIDATE','CONDITIONAL','NOT_APPLICABLE')

    def direction(rows,src,dst,si,di,r,rev,port,enabled):
        # Destination attachment subnet is recorded before each direction's route checks.
        sa,da=rev['destination_attachment_subnet_id'],r['destination_attachment_subnet_id']
        sg=lambda inv,ep,peer,egress: _sg({g['GroupId']:g for g in inv['SecurityGroups']},ep,peer,egress,port)
        acl=lambda inv,sub,peer,egress: _acl(inv['NetworkAcls'],dict(subnet_id=sub),peer,egress,port)
        tracked=dict(status='CONDITIONAL',reason='REQUIRES_ESTABLISHED_TRACKED_REQUEST')
        skip=dict(status='NOT_APPLICABLE',reason='TGW_SAME_SUBNET_DESTINATION_NACL_NOT_EVALUATED')
        # Keep each route layer separate; a missing layer cannot be rendered as a pass.
        def route_step(key, accepted, final=False):
            layer=r.get(key)
            if not layer:
                return dict(status='UNKNOWN',reason=r['reason'],route_evidence=None)
            status=layer['status']; reason=layer['reason']
            if status==accepted:
                status='ALLOW_CANDIDATE'
                if final and r['status']!='TGW_ROUTE_CANDIDATE':
                    status=r['status'] if r['status'] in ('BLOCKED','UNKNOWN') else 'UNKNOWN'; reason=r['reason']
            elif status!='BLOCKED': status='UNKNOWN'
            # A successful low-level lookup does not establish the selected target.
            if key=='source_route' and status=='ALLOW_CANDIDATE' and not r.get('tgw_route_table_id'):
                status='UNKNOWN';reason=r['reason']
            if key=='tgw_route' and status=='ALLOW_CANDIDATE' and not r.get('destination_local_route'):
                status='UNKNOWN';reason=r['reason']
            return dict(status=status,reason=reason,route_evidence=layer,route_table_id=layer.get('route_table_id') or (r.get('tgw_route_table_id') if key=='tgw_route' else None))
        sr=route_step('source_route','ACTIVE_ROUTE_CANDIDATE')
        dr=route_step('destination_local_route','ACTIVE_ROUTE_CANDIDATE',True)
        for inv, row in ((si,sr),(di,dr)):
            table=next((t for t in inv['RouteTables'] if t['RouteTableId']==row.get('route_table_id')), {})
            if table.get('PropagatingVgws'):
                row.update(status='UNKNOWN',reason='ROUTE_PROPAGATION_NOT_IN_SCOPE')
        reply=rows is response
        steps=[('SOURCE_SG_EGRESS',tracked if reply else sg(si,src,dst,True),src,None),
               ('SOURCE_WORKLOAD_NACL_EGRESS',acl(si,src['subnet_id'],dst,True),src,None),
               ('SOURCE_VPC_ROUTE',sr,src,None),
               # AWS applies attachment ingress (original source IP) on traffic toward TGW.
               ('SOURCE_ATTACHMENT_NACL_INGRESS',acl(si,sa,src,False),src,sa),
               ('TGW_ROUTE',route_step('tgw_route','ACTIVE_ROUTE_CANDIDATE'),src,sa),
               ('DESTINATION_ATTACHMENT_LOCAL_ROUTE',dr,dst,da),
               # AWS: no NACL evaluation from TGW to instance in same subnet.
               ('DESTINATION_ATTACHMENT_NACL_EGRESS',skip if da==dst['subnet_id'] else acl(di,da,dst,True),dst,da),
               ('DESTINATION_WORKLOAD_NACL_INGRESS',skip if da==dst['subnet_id'] else acl(di,dst['subnet_id'],src,False),dst,None),
               ('DESTINATION_SG_INGRESS',tracked if reply else sg(di,dst,src,False),dst,None)]
        active=enabled; stop=None; status='CONDITIONAL_CANDIDATE' if enabled else 'NOT_EVALUATED'
        for stage,ev,ep,sub in steps:
            was=active; active=add(rows,stage,ev,active,ep,sub)
            if was and not active:
                stop=stage; status='BLOCKED' if ev['status']=='BLOCKED' else 'UNKNOWN'
        return status,stop

    if not route['request'] or not route['response'] or not ae or not be:
        add(request,'TGW_SCOPE',dict(status='UNKNOWN',reason=route['reason']),True)
        req,stop='UNKNOWN','TGW_SCOPE'; resp,rstop='NOT_EVALUATED',None
    elif reserved(ai,ae) or reserved(bi,be):
        add(request,'TGW_SCOPE',dict(status='UNKNOWN',reason='AWS_RESERVED_SUBNET_ADDRESS'),True)
        req,stop='UNKNOWN','TGW_SCOPE'; resp,rstop='NOT_EVALUATED',None
    else:
        req,stop=direction(request,ae,be,ai,bi,route['request'],route['response'],destination_port,True)
        resp,rstop=direction(response,be,ae,bi,ai,route['response'],route['request'],source_port,req=='CONDITIONAL_CANDIDATE')
    return dict(result,request_status=req,response_status=resp,first_request_stop=stop,
                conditional_first_response_stop=rstop,session_status='BLOCKED' if req=='BLOCKED' else 'UNKNOWN',
                response_assumptions=['REQUEST_DELIVERY_PREDICTED','TCP_REPLY_CONNECTION_TRACKED'])
