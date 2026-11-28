#!/usr/bin/env python3
"""Compare uploaded historical CNI evidence with declared policy."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.eks_cni_evidence import inspect_eks_cni

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('inventory','eks','policy','observation','source-namespace','source-pod','destination-namespace','destination-pod'):
        p.add_argument('--'+n,required=True)
    for n in ('source-port','destination-port'): p.add_argument('--'+n,type=int,required=True)
    a=p.parse_args()
    def read(path):
        with open(path,'rb') as f: raw=f.read(5*1024*1024+1)
        if len(raw)>5*1024*1024: raise ValueError('Input exceeds 5 MiB')
        return raw
    try: result=inspect_eks_cni(read(a.inventory),read(a.eks),read(a.policy),read(a.observation),a.source_namespace,a.source_pod,a.destination_namespace,a.destination_pod,a.source_port,a.destination_port)
    except (ValueError,OSError) as exc: p.exit(2,'Analysis failed: '+str(exc)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__': main()
