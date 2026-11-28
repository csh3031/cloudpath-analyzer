"""Stateless, local Endpoint evidence adapter. Never replaces the current topology."""
from ipaddress import IPv4Address
from backend.iac.upload_snapshot import validate_files, MAX_BYTES
from backend.aws.vpc_endpoint_evidence import inspect_vpc_endpoint
from backend.aws.interface_endpoint_session_evidence import analyze_interface_endpoint_session
from backend.aws.gateway_endpoint_session_evidence import analyze_gateway_endpoint_session

BASE = ('inventory', 'endpoints')
MODES = {kind: (BASE, (), ('endpoint_id',)) for kind in ('interface', 'gateway')}
for kind in ('interface', 'gateway'):
    for source, extra, params in [('ec2', (), ('client_ip',)), ('ecs', ('ecs',), ('task_id',)), ('eks', ('eks','policy'), ('namespace','pod_name'))]:
        MODES[kind+'_'+source] = (BASE+extra, ('observation','prefix_list'), ('endpoint_id','source_port')+params)


def analyze_endpoint_upload(data, current_identity):
    if not isinstance(data, dict) or set(data) != {'input_identity','mode','files','params'} or data['input_identity'] != current_identity:
        raise ValueError('Invalid or stale Endpoint request')
    mode=data['mode']
    if not isinstance(mode,str) or mode not in MODES:
        raise ValueError('Unknown Endpoint mode')
    required, optional, fields=MODES[mode]
    files, params=data['files'],data['params']
    if not isinstance(files,dict) or not set(required)<=set(files)<=set(required+optional):
        raise ValueError('Incorrect Endpoint file roles')
    if not isinstance(params,dict) or set(params)!=set(fields):
        raise ValueError('Incorrect Endpoint parameters')
    for key,value in params.items():
        if key=='source_port':
            if type(value) is not int or not 1<=value<=65535: raise ValueError('Explicit TCP port required')
        elif not isinstance(value,str) or not 1<=len(value)<=512 or any(ord(c)<32 or ord(c)==127 for c in value):
            raise ValueError('Invalid Endpoint parameter')
        elif key=='client_ip' and str(IPv4Address(value))!=value: raise ValueError('Explicit IPv4 required')
    raw={}; total=0
    for role,entry in files.items():
        name, content=validate_files([entry],allow_plan=True)[0]
        if not name.endswith('.json'): raise ValueError('JSON evidence only')
        total+=len(content)
        if total>MAX_BYTES: raise ValueError('Total file size exceeds 5 MiB')
        raw[role]=content
    if mode in ('interface','gateway'):
        result=inspect_vpc_endpoint(raw['inventory'],raw['endpoints'],params['endpoint_id'])
        if result['endpoint_type'] is not None and result['endpoint_type'].lower()!=mode:
            raise ValueError('Endpoint type differs from configuration mode')
    else:
        kind,source=mode.split('_')
        opts={k:params[k] for k in ('client_ip','task_id','namespace','pod_name') if k in params}
        opts.update({k+'_raw':raw[k] for k in ('ecs','eks','policy','prefix_list') if k in raw})
        engine=analyze_interface_endpoint_session if kind=='interface' else analyze_gateway_endpoint_session
        result=engine(raw['inventory'],raw['endpoints'],raw.get('observation'),params['endpoint_id'],source,params['source_port'],**opts)
    return {'mode':mode,'result':result}
