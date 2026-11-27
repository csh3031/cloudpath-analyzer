#!/usr/bin/env python3
"""Offline ALB rule selection for a canonical host/path pair."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.alb_rule_evidence import inspect_alb_rule

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('inventory','elbv2','rules','load-balancer-id','host','path'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--listener-port',type=int,required=True)
    a=p.parse_args()
    def read(path):
        with open(path,'rb') as f: raw=f.read(5*1024*1024+1)
        if len(raw)>5*1024*1024: raise ValueError('Input exceeds 5 MiB')
        return raw
    try: result=inspect_alb_rule(read(a.inventory),read(a.elbv2),read(a.rules),a.load_balancer_id,a.listener_port,a.host,a.path)
    except (ValueError,OSError) as exc: p.exit(2,'Analysis failed: '+str(exc)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__': main()
