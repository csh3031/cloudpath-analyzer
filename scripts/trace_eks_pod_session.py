#!/usr/bin/env python3
"""Offline direct EKS Pod TCP configuration checks."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.eks_session_evidence import analyze_eks_pod_session

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('inventory','eks','policy','source-namespace','source-pod','destination-namespace','destination-pod'):
        p.add_argument('--'+n,required=True)
    for n in ('source-port','destination-port'): p.add_argument('--'+n,type=int,required=True)
    p.add_argument('--prefix-lists',help='Optional normalized prefix list evidence JSON')
    a=p.parse_args()
    def read(path):
        with open(path,'rb') as f: raw=f.read(5*1024*1024+1)
        if len(raw)>5*1024*1024: raise ValueError('Input exceeds 5 MiB')
        return raw
    try: result=analyze_eks_pod_session(read(a.inventory),read(a.eks),read(a.policy),a.source_namespace,a.source_pod,a.destination_namespace,a.destination_pod,a.source_port,a.destination_port,prefix_list_raw=read(a.prefix_lists) if a.prefix_lists else None)
    except (ValueError,OSError) as exc: p.exit(2,'Analysis failed: '+str(exc)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__': main()
