#!/usr/bin/env python3
"""Offline unified S3 evidence report; no AWS calls."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.s3_unified_evidence import analyze_s3_unified

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--authorization',required=True)
    for name in ('identity','limits','organization','resource-organization','encryption','acl','manifest','inventory','endpoints','observation','binding','endpoint-id','endpoint-type','source-kind','client-ip','ecs','task-id','eks','policy','namespace','pod-name','prefix-lists'):
        p.add_argument('--'+name)
    p.add_argument('--source-port',type=int)
    a=p.parse_args()
    def read(path):
        if path is None:return None
        with open(path,'rb') as f: raw=f.read(5*1024*1024+1)
        if len(raw)>5*1024*1024: raise ValueError('Input exceeds 5 MiB')
        return raw
    try:
        network=None
        if any(v is not None for v in (a.inventory,a.endpoints,a.observation,a.binding,a.endpoint_id,a.endpoint_type,a.source_kind,a.source_port,a.client_ip,a.ecs,a.task_id,a.eks,a.policy,a.namespace,a.pod_name,a.prefix_lists)):
            if any(v is None for v in (a.inventory,a.endpoints,a.endpoint_id,a.endpoint_type,a.source_kind,a.source_port)): raise ValueError('Incomplete network arguments')
            network=dict(inventory_raw=read(a.inventory),endpoint_raw=read(a.endpoints),observation_raw=read(a.observation),binding_raw=read(a.binding),endpoint_id=a.endpoint_id,endpoint_type=a.endpoint_type,source_kind=a.source_kind,source_port=a.source_port,client_ip=a.client_ip,ecs_raw=read(a.ecs),task_id=a.task_id,eks_raw=read(a.eks),policy_raw=read(a.policy),namespace=a.namespace,pod_name=a.pod_name,prefix_list_raw=read(a.prefix_lists))
        r=analyze_s3_unified(read(a.authorization),identity=read(a.identity),limits=read(a.limits),organization=read(a.organization),resource_organization=read(a.resource_organization),encryption=read(a.encryption),acl=read(a.acl),manifest=read(a.manifest),network=network)
    except (ValueError,OSError,TypeError,KeyError) as exc:p.exit(2,'Analysis failed: '+str(exc)+'\n')
    print(json.dumps(r,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
