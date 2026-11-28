"""Stateless, local RDS evidence adapter. Never replaces the current topology."""
from ipaddress import IPv4Address
from backend.iac.upload_snapshot import validate_files, MAX_BYTES
from backend.aws.rds_evidence import inspect_rds_configuration
from backend.aws.rds_session_evidence import analyze_rds_session
from backend.aws.rds_failover_evidence import compare_rds_snapshots

BASE = ('inventory', 'rds')
COMPARE = tuple(f'{w}_{k}' for w in ('before', 'after') for k in ('inventory','rds','observation'))
# mode -> required files, optional files, exact parameters
MODES = {
    'instance': (BASE, (), ('identifier',)),
    'cluster': (BASE, (), ('identifier',)),
    'compare_instance': (COMPARE, (), ('identifier','client_ip','source_port')),
    'compare_cluster': (COMPARE, (), ('identifier','client_ip','source_port')),
}
for source, extra, params in [('ec2', (), ('client_ip',)), ('ecs', ('ecs',), ('task_id',)), ('eks', ('eks','policy'), ('namespace','pod_name'))]:
    MODES['session_'+source] = (BASE+extra, ('observation','prefix_list'), ('identifier','source_port','endpoint_kind')+params)


def analyze_rds_upload(data, current_identity):
    if not isinstance(data, dict) or set(data) != {'input_identity','mode','files','params'} or data['input_identity'] != current_identity:
        raise ValueError('Invalid or stale RDS request')
    mode=data['mode']
    if not isinstance(mode,str) or mode not in MODES:
        raise ValueError('Unknown RDS mode')
    required, optional, fields=MODES[mode]
    files, params=data['files'],data['params']
    if not isinstance(files,dict) or not set(required)<=set(files)<=set(required+optional):
        raise ValueError('Incorrect RDS file roles')
    if not isinstance(params,dict) or set(params)!=set(fields):
        raise ValueError('Incorrect RDS parameters')
    for key,value in params.items():
        if key=='source_port':
            if type(value) is not int or not 1<=value<=65535: raise ValueError('Explicit TCP port required')
        elif not isinstance(value,str) or not 1<=len(value)<=512 or any(ord(c)<32 or ord(c)==127 for c in value):
            raise ValueError('Invalid RDS parameter')
        elif key=='client_ip' and str(IPv4Address(value))!=value: raise ValueError('Explicit IPv4 required')
        elif key=='endpoint_kind' and value not in ('INSTANCE','WRITER','READER'): raise ValueError('Invalid endpoint kind')
    raw={}; total=0
    for role,entry in files.items():
        name, content=validate_files([entry],allow_plan=True)[0]
        if not name.endswith('.json'): raise ValueError('JSON evidence only')
        total+=len(content)
        if total>MAX_BYTES: raise ValueError('Total file size exceeds 5 MiB')
        raw[role]=content
    if mode in ('instance','cluster'):
        result=inspect_rds_configuration(raw['inventory'],raw['rds'],mode,params['identifier'])
    elif mode.startswith('compare_'):
        bundles=[tuple(raw[f'{w}_{k}'] for k in ('inventory','rds','observation')) for w in ('before','after')]
        result=compare_rds_snapshots(*bundles,params['identifier'],params['client_ip'],params['source_port'],cluster=mode=='compare_cluster')
    else:
        source=mode.removeprefix('session_')
        opts={k:params[k] for k in ('client_ip','task_id','namespace','pod_name') if k in params}
        opts.update({k+'_raw':raw[k] for k in ('ecs','eks','policy','prefix_list') if k in raw})
        endpoint=params['endpoint_kind']
        result=analyze_rds_session(raw['inventory'],raw['rds'],raw.get('observation'),params['identifier'],source,params['source_port'],endpoint_kind=None if endpoint=='INSTANCE' else endpoint,**opts)
    return {'mode':mode,'result':result}
