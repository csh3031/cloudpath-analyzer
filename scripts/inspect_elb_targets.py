#!/usr/bin/env python3
"""Offline ELB target health and independent policy rule checks."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.elb_target_evidence import inspect_elb_targets

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('inventory','elbv2','health','load-balancer-id','client-ip'): p.add_argument('--'+n,required=True)
    for n in ('rules','host','path','attributes','backend-node-ip'): p.add_argument('--'+n)
    p.add_argument('--listener-port',required=True,type=int); p.add_argument('--backend-source-port',type=int)
    a=p.parse_args()
    def read(path):
        if path is None:return None
        with open(path,'rb') as f: raw=f.read(5*1024*1024+1)
        if len(raw)>5*1024*1024: raise ValueError('Input exceeds 5 MiB')
        return raw
    try:
        r=inspect_elb_targets(read(a.inventory),read(a.elbv2),read(a.health),a.load_balancer_id,a.listener_port,a.client_ip,rules_raw=read(a.rules),host=a.host,path=a.path,attributes_raw=read(a.attributes),backend_node_ip=a.backend_node_ip,backend_source_port=a.backend_source_port)
    except (ValueError,OSError) as e:p.exit(2,'Analysis failed: '+str(e)+'\n')
    print(json.dumps(r,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
