"""Stateless local web adapter for bounded offline ELB path inspection."""
from ipaddress import IPv4Address
from backend.aws.elb_path_evidence import inspect_elb_paths
from backend.aws.peering_evidence import _load
from backend.iac.upload_snapshot import validate_files, MAX_BYTES

FILES = ('inventory_file', 'elbv2_file', 'health_file', 'path_file', 'rules_file', 'attributes_file')
PORTS = ('listener_port', 'client_port', 'backend_source_port', 'health_source_port')
IPS = ('client_ip', 'frontend_node_ip', 'backend_node_ip')


def analyze_elb_upload(data, current_identity):
    fields = set(FILES + PORTS + IPS + ('input_identity', 'kind', 'load_balancer_id', 'host', 'path'))
    if not isinstance(data, dict) or set(data) != fields or data['input_identity'] != current_identity:
        raise ValueError('Invalid ELB request or stale input')
    kind = data['kind']
    if kind not in ('alb', 'nlb'):
        raise ValueError('Expected ALB or NLB')
    required = set(FILES[:4]) | {'rules_file' if kind == 'alb' else 'attributes_file'}
    raws = {}
    for role in FILES:
        if role not in required:
            if data[role] is not None: raise ValueError('Unexpected file role')
            raws[role] = None
            continue
        name, raw = validate_files([data[role]], allow_plan=True)[0]
        if not name.endswith('.json'): raise ValueError('JSON only')
        raws[role] = raw
    if sum(len(x) for x in raws.values() if x is not None) > MAX_BYTES:
        raise ValueError('Total file size exceeds 5 MiB')
    for k in PORTS:
        if type(data[k]) is not int or not 1 <= data[k] <= 65535: raise ValueError('Invalid TCP port')
    for k in IPS:
        if not isinstance(data[k], str) or str(IPv4Address(data[k])) != data[k]: raise ValueError('Explicit IPv4 required')
    if not isinstance(data['load_balancer_id'], str) or not 1 <= len(data['load_balancer_id']) <= 128:
        raise ValueError('Invalid LB identifier')
    for k in ('host', 'path'):
        if kind == 'alb':
            if not isinstance(data[k], str) or not 1 <= len(data[k]) <= 2048: raise ValueError('Host and path required')
        elif data[k] is not None: raise ValueError('Unexpected ALB scenario')
    r = inspect_elb_paths(*(raws[k] for k in FILES[:4]), data['load_balancer_id'], data['listener_port'], data['client_ip'],
        frontend_node_ip=data['frontend_node_ip'], backend_node_ip=data['backend_node_ip'], client_port=data['client_port'],
        backend_source_port=data['backend_source_port'], health_source_port=data['health_source_port'],
        rules_raw=raws['rules_file'], attributes_raw=raws['attributes_file'], host=data['host'], path=data['path'])
    lb = r['target_analysis']['configuration']['load_balancer']
    if lb and lb['type'] != ('application' if kind == 'alb' else 'network'):
        raise ValueError('LB type does not match selected mode')
    identity, meta, inv = _load(raws['inventory_file'])
    vpc = inv['Vpcs'][0]
    return dict(result=r, vpc=dict(identity=identity, id=vpc['VpcId'], cidr=vpc['CidrBlock'], region=meta['region'],
        subnets=[dict(id=s['SubnetId'], cidr=s['CidrBlock'], zone=s['AvailabilityZone']) for s in inv['Subnets']],
        instances=[dict(id=i['InstanceId'], subnet_id=i['SubnetId'], ip=i.get('PrivateIpAddress')) for row in inv['Reservations'] for i in row['Instances']]))
