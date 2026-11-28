#!/usr/bin/env python3
"""Read-only ECS service and ELB node-specific path constraints."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.ecs_elb_path_evidence import inspect_ecs_elb_paths

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('inventory','ecs','service','elbv2','health','nodes','service-arn','load-balancer-id','client-ip','node-eni-id'):p.add_argument('--'+n,required=True)
    for n in ('rules','host','path','attributes','prefix-lists'):p.add_argument('--'+n)
    for n in ('listener-port','client-port','backend-source-port','health-source-port'):p.add_argument('--'+n,required=True,type=int)
    a=p.parse_args()
    def read(name):
        if name is None:return None
        with open(name,'rb') as f: data=f.read(5*1024*1024+1)
        if len(data)>5*1024*1024:raise ValueError('Input exceeds 5 MiB')
        return data
    try:
        result=inspect_ecs_elb_paths(*(read(getattr(a,n)) for n in ('inventory','ecs','service','elbv2','health','nodes')),a.service_arn,a.load_balancer_id,a.listener_port,a.client_ip,node_eni_id=a.node_eni_id,client_port=a.client_port,backend_source_port=a.backend_source_port,health_source_port=a.health_source_port,rules_raw=read(a.rules),host=a.host,path=a.path,attributes_raw=read(a.attributes),prefix_list_raw=read(a.prefix_lists))
    except (ValueError,OSError) as e:p.exit(2,'Analysis failed: '+str(e)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
