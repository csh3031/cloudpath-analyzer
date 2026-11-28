#!/usr/bin/env python3
"""Offline Interface Endpoint TCP path analysis."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.interface_endpoint_session_evidence import analyze_interface_endpoint_session


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('inventory','endpoints','endpoint-id','source-kind'):
        p.add_argument('--'+name,required=True)
    for name in ('observation','client-ip','ecs','task-id','eks','policy','namespace','pod-name','prefix-lists'):
        p.add_argument('--'+name)
    p.add_argument('--source-port',required=True,type=int)
    a=p.parse_args()
    def read(path):
        if path is None: return None
        with open(path,'rb') as f: raw=f.read(5*1024*1024+1)
        if len(raw)>5*1024*1024: raise ValueError('Input exceeds 5 MiB')
        return raw
    try:
        r=analyze_interface_endpoint_session(read(a.inventory),read(a.endpoints),read(a.observation),a.endpoint_id,a.source_kind,a.source_port,
            client_ip=a.client_ip,ecs_raw=read(a.ecs),task_id=a.task_id,eks_raw=read(a.eks),policy_raw=read(a.policy),namespace=a.namespace,pod_name=a.pod_name,prefix_list_raw=read(a.prefix_lists))
    except (ValueError,OSError) as exc: p.exit(2,'Analysis failed: '+str(exc)+'\n')
    print(json.dumps(r,ensure_ascii=False,indent=2))

if __name__=='__main__': main()
