"""Local stateless adapter for existing ECS/EKS offline analysis engines.

Only declared file roles/parameters accepted. No AWS calls or input replacement.
"""
from ipaddress import IPv4Address
from backend.iac.upload_snapshot import validate_files, MAX_BYTES
from backend.aws.ecs_task_evidence import inspect_ecs_task
from backend.aws.ecs_session_evidence import analyze_ecs_task_session
from backend.aws.ecs_service_evidence import inspect_ecs_service
from backend.aws.ecs_elb_path_evidence import inspect_ecs_elb_paths
from backend.aws.eks_pod_evidence import inspect_eks_pod
from backend.aws.eks_service_evidence import inspect_eks_service
from backend.aws.eks_session_evidence import analyze_eks_pod_session
from backend.aws.eks_service_session_evidence import analyze_eks_service_session
from backend.aws.eks_cni_evidence import inspect_eks_cni

# Ordered positional inputs are shared with the CLI; options are explicitly scoped.
ECS = ('inventory', 'ecs')
EKS = ('inventory', 'eks')
POD_PAIR = ('source_namespace', 'source_pod', 'destination_namespace', 'destination_pod', 'source_port', 'destination_port')
SERVICE_PAIR = ('source_namespace', 'source_pod', 'service_namespace', 'service_name', 'source_port', 'service_port')
ELB_FILES = ECS + ('service', 'elbv2', 'health')
ELB_PARAMS = ('service_arn', 'load_balancer_id', 'listener_port', 'client_ip')
ELB_PATH_PARAMS = ('node_eni_id', 'client_port', 'backend_source_port', 'health_source_port')
PORTS = frozenset(('source_port', 'destination_port', 'service_port', 'listener_port', 'client_port', 'backend_source_port', 'health_source_port'))

# mode: engine, required positional files, positional params, keyword files, keyword params, optional files
MODES = {
    'ecs_task': (inspect_ecs_task, ECS, ('task_id',), (), (), ()),
    'ecs_session': (analyze_ecs_task_session, ECS, ('source_task_id', 'destination_task_id', 'source_port', 'destination_port'), (), (), ('prefix_list',)),
    'eks_pod': (inspect_eks_pod, EKS, ('namespace', 'pod_name'), (), (), ()),
    'eks_service': (inspect_eks_service, EKS + ('service',), ('namespace', 'service_name', 'service_port'), (), (), ()),
    'eks_session': (analyze_eks_pod_session, EKS + ('policy',), POD_PAIR, (), (), ('prefix_list',)),
    'eks_service_session': (analyze_eks_service_session, EKS + ('service', 'policy', 'translation'), SERVICE_PAIR, (), (), ()),
    'eks_cni': (inspect_eks_cni, EKS + ('policy', 'observation'), POD_PAIR, (), (), ()),
}
for kind in ('alb', 'nlb'):
    kwfiles = ('rules',) if kind == 'alb' else ('attributes',)
    kwparams = ('host', 'path') if kind == 'alb' else ()
    MODES['ecs_service_' + kind] = (inspect_ecs_service, ELB_FILES, ELB_PARAMS, kwfiles, kwparams, ())
    MODES['ecs_path_' + kind] = (inspect_ecs_elb_paths, ELB_FILES + ('node',), ELB_PARAMS, kwfiles, ELB_PATH_PARAMS + kwparams, ('prefix_list',))


def analyze_workload_upload(data, current_identity):
    if not isinstance(data, dict) or set(data) != {'input_identity', 'mode', 'files', 'params'} or data['input_identity'] != current_identity:
        raise ValueError('Invalid or stale workload request')
    mode = data['mode']
    if not isinstance(mode, str) or mode not in MODES:
        raise ValueError('Unknown workload mode')
    engine, files, params, kwfiles, kwparams, optional = MODES[mode]
    required = set(files + kwfiles)
    entries, values = data['files'], data['params']
    if not isinstance(entries, dict) or not required <= set(entries) <= required | set(optional):
        raise ValueError('Incorrect workload file roles')
    if not isinstance(values, dict) or set(values) != set(params + kwparams):
        raise ValueError('Incorrect workload parameters')
    raws, total = {}, 0
    for role, entry in entries.items():
        name, raw = validate_files([entry], allow_plan=True)[0]
        if not name.endswith('.json'):
            raise ValueError('JSON evidence only')
        total += len(raw)
        if total > MAX_BYTES:
            raise ValueError('Total file size exceeds 5 MiB')
        raws[role] = raw
    for key, value in values.items():
        if key in PORTS:
            if type(value) is not int or not 1 <= value <= 65535:
                raise ValueError('Explicit TCP port required')
        elif not isinstance(value, str) or not 1 <= len(value) <= (2048 if key in ('host', 'path') else 512) or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError('Invalid workload parameter')
        elif key == 'client_ip' and str(IPv4Address(value)) != value:
            raise ValueError('Explicit IPv4 required')
    result = engine(*(raws[k] for k in files), *(values[k] for k in params),
                    **{k + '_raw': raws[k] for k in kwfiles + optional if k in raws},
                    **{k: values[k] for k in kwparams})
    # Wrong LB type must not be presented under the selected mode. Unresolved type stays unresolved.
    if mode.startswith(('ecs_service_', 'ecs_path_')):
        svc = result.get('service_correlation', result)
        lb = ((svc.get('elb_analysis') or {}).get('configuration') or {}).get('load_balancer')
        if lb and lb.get('type') != ('application' if mode.endswith('_alb') else 'network'):
            raise ValueError('LB type mismatch')
    return {'mode': mode, 'result': result}
