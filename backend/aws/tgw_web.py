"""Stateless local web adapter for the bounded single TGW analyzer."""
from ipaddress import IPv4Address
from backend.aws.peering_evidence import _load
from backend.aws.tgw_session_evidence import analyze_tgw_session
from backend.iac.upload_snapshot import validate_files, MAX_BYTES


def analyze_tgw_upload(data, current_identity):
    fields = {'input_identity','source_file','destination_file','tgw_file','source_ip','destination_ip','source_port','destination_port','protocol'}
    if not isinstance(data, dict) or set(data) != fields or data['input_identity'] != current_identity or data['protocol'] != 'tcp':
        raise ValueError('Invalid TGW request or stale page')
    raws = []
    for role in ('source_file','destination_file','tgw_file'):
        name, raw = validate_files([data[role]], allow_plan=True)[0]
        if not name.endswith('.json'):
            raise ValueError('JSON only')
        raws.append(raw)
    if sum(map(len,raws)) > MAX_BYTES:
        raise ValueError('Total file size exceeds 5 MiB')
    for key in ('source_ip','destination_ip'):
        value = data[key]
        if not isinstance(value,str) or str(IPv4Address(value)) != value:
            raise ValueError('Explicit IPv4 required')
    for key in ('source_port','destination_port'):
        if type(data[key]) is not int or not 1 <= data[key] <= 65535:
            raise ValueError('Invalid TCP port')
    result = analyze_tgw_session(*raws,data['source_ip'],data['destination_ip'],data['source_port'],data['destination_port'])
    views = []
    for raw in raws[:2]:
        identity, meta, inv = _load(raw)
        vpc = inv['Vpcs'][0]
        subnets = [{'id':s['SubnetId'],'cidr':s['CidrBlock']} for s in inv['Subnets']]
        instances = [{'id':i['InstanceId'],'subnet_id':i['SubnetId'],'ip':i.get('PrivateIpAddress')} for r in inv['Reservations'] for i in r['Instances']]
        views.append(dict(identity=identity,id=vpc['VpcId'],cidr=vpc['CidrBlock'],region=meta['region'],subnets=subnets,instances=instances))
    return dict(result=result,vpcs=views)
