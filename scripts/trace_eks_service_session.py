#!/usr/bin/env python3
"""Offline ClusterIP translation scenarios and conditional backend checks."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.eks_service_session_evidence import analyze_eks_service_session

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('inventory','eks','service','policy','translation','source-namespace','source-pod','service-namespace','service-name'):
        p.add_argument('--'+n,required=True)
    for n in ('source-port','service-port'): p.add_argument('--'+n,type=int,required=True)
    a=p.parse_args()
    def read(path):
        with open(path,'rb') as f: raw=f.read(5*1024*1024+1)
        if len(raw)>5*1024*1024: raise ValueError('Input exceeds 5 MiB')
        return raw
    try:
        result=analyze_eks_service_session(*(read(getattr(a,k)) for k in ('inventory','eks','service','policy','translation')),a.source_namespace,a.source_pod,a.service_namespace,a.service_name,a.source_port,a.service_port)
    except (ValueError,OSError) as exc: p.exit(2,'Analysis failed: '+str(exc)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__': main()
