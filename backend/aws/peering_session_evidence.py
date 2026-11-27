"""Offline TCP constraints for two directly peered IPv4 VPCs."""
from ipaddress import IPv4Address, IPv4Network

from backend.aws.peering_evidence import trace_direct_peering, _load
from backend.aws.policy_evidence import _acl, _sg, _port


def analyze_peering_session(source_raw, destination_raw, peering_raw, source_ip,
                            destination_ip, source_port, destination_port):
    if not _port(source_port) or not _port(destination_port):
        raise ValueError('Expected explicit TCP ports in 1..65535')
    route = trace_direct_peering(source_raw, destination_raw, peering_raw, source_ip, destination_ip)
    _, _, ai = _load(source_raw)
    _, _, bi = _load(destination_raw)
    ae, be = route['source_endpoint'], route['destination_endpoint']
    request, response = [], []
    result = dict(analysis_type='STATIC_AWS_DIRECT_PEERING_TCP_CONSTRAINTS',
                  source_input_identity=route['source_input_identity'],
                  destination_input_identity=route['destination_input_identity'],
                  peering_input_identity=route['peering_input_identity'],
                  scenario=dict(source_ip=source_ip,destination_ip=destination_ip,
                                source_port=source_port,destination_port=destination_port,protocol='tcp'),
                  route=route,request=request,response=response,live_observation=False,
                  limitations=['Uploaded snapshots are unauthenticated, non-atomic; 300s time heuristic only.',
                               'Same-region direct peering, primary IPv4 and single-ENI EC2 only.',
                               'SG references and prefix list contents unresolved; CIDR rules only.',
                               'Reply assumes delivered request and tracked TCP connection.',
                               'Host, application, VPC BPA, gateway ingress routing and live state unverified.',
                               'No AWS API calls or packet transmission.'])
    def reserved(inv, ep):
        subnet = next(s for s in inv['Subnets'] if s['SubnetId']==ep['subnet_id'])
        net=IPv4Network(subnet['CidrBlock']); ip=IPv4Address(ep['private_ip'])
        return int(ip)-int(net.network_address)<4 or ip==net.broadcast_address
    def add(rows,stage,evidence,active,ep=None):
        mode=('CONDITIONAL_CHECK' if rows is response else 'PREDICTED_PATH') if active else 'INDEPENDENT_CHECK'
        rows.append(dict(stage=stage,evaluation_mode=mode,vpc_id=ep['vpc_id'] if ep else None,
                         subnet_id=ep['subnet_id'] if ep else None,eni_id=ep['eni_id'] if ep else None,
                         **evidence))
        return active and evidence['status'] in ('ALLOW_CANDIDATE','CONDITIONAL')
    def run(rows,src,dst,si,di,lookup,port,enabled):
        reply=rows is response
        sg=lambda inv,ep,peer,egress: _sg({g['GroupId']:g for g in inv['SecurityGroups']},ep,peer,egress,port)
        tracked=dict(status='CONDITIONAL',reason='REQUIRES_ESTABLISHED_TRACKED_REQUEST')
        re=dict(lookup)
        re['status']='ALLOW_CANDIDATE' if lookup['status']=='PEERING_ROUTE_CANDIDATE' else lookup['status']
        table=next((t for t in si['RouteTables'] if t['RouteTableId']==lookup.get('route_table_id')), {})
        if table.get('PropagatingVgws'):
            re.update(status='UNKNOWN',reason='ROUTE_PROPAGATION_NOT_IN_SCOPE')
        steps=[('SOURCE_SG_EGRESS',tracked if reply else sg(si,src,dst,True),src),
               ('SOURCE_NACL_EGRESS',_acl(si['NetworkAcls'],src,dst,True,port),src),
               ('PEERING_ROUTE',re,src),
               ('DESTINATION_NACL_INGRESS',_acl(di['NetworkAcls'],dst,src,False,port),dst),
               ('DESTINATION_SG_INGRESS',tracked if reply else sg(di,dst,src,False),dst)]
        active=enabled; stop=None; status='CONDITIONAL_CANDIDATE' if enabled else 'NOT_EVALUATED'
        for stage,evidence,ep in steps:
            was=active; active=add(rows,stage,evidence,active,ep=ep)
            if was and not active:
                stop=stage; status='BLOCKED' if evidence['status']=='BLOCKED' else 'UNKNOWN'
        return status,stop
    if not route['request_route'] or not route['response_route'] or not ae or not be:
        add(request,'PEERING_SCOPE',dict(status='UNKNOWN',reason=route['reason']),True)
        req,stop='UNKNOWN','PEERING_SCOPE'; resp,rstop='NOT_EVALUATED',None
    elif reserved(ai,ae) or reserved(bi,be):
        add(request,'PEERING_SCOPE',dict(status='UNKNOWN',reason='AWS_RESERVED_SUBNET_ADDRESS'),True)
        req,stop='UNKNOWN','PEERING_SCOPE'; resp,rstop='NOT_EVALUATED',None
    else:
        req,stop=run(request,ae,be,ai,bi,route['request_route'],destination_port,True)
        resp,rstop=run(response,be,ae,bi,ai,route['response_route'],source_port,req=='CONDITIONAL_CANDIDATE')
    return dict(result,request_status=req,response_status=resp,first_request_stop=stop,
                conditional_first_response_stop=rstop,session_status='BLOCKED' if req=='BLOCKED' else 'UNKNOWN',
                response_assumptions=['REQUEST_DELIVERY_PREDICTED','TCP_REPLY_CONNECTION_TRACKED'])
