#!/usr/bin/env python3
"""Offline ECS service and ELB IP registration correlation."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.ecs_service_evidence import inspect_ecs_service

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('inventory','ecs','service','elbv2','health','service-arn','load-balancer-id','client-ip'): p.add_argument('--'+n,required=True)
    for n in ('rules','host','path','attributes'): p.add_argument('--'+n)
    p.add_argument('--listener-port',required=True,type=int)
    a=p.parse_args()
    def read(path):
        if path is None: return None
        with open(path,'rb') as f: raw=f.read(5*1024*1024+1)
        if len(raw)>5*1024*1024: raise ValueError('Input exceeds 5 MiB')
        return raw
    try:
        r=inspect_ecs_service(*(read(getattr(a,n)) for n in ('inventory','ecs','service','elbv2','health')),a.service_arn,a.load_balancer_id,a.listener_port,a.client_ip,rules_raw=read(a.rules),host=a.host,path=a.path,attributes_raw=read(a.attributes))
    except (ValueError,OSError) as e: p.exit(2,'Analysis failed: '+str(e)+'\n')
    print(json.dumps(r,ensure_ascii=False,indent=2))
if __name__=='__main__': main()
