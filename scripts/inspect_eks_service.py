#!/usr/bin/env python3
"""Offline EKS Service endpoint correlation."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.eks_service_evidence import inspect_eks_service


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('inventory','eks','service','namespace','service-name'):
        p.add_argument('--'+name,required=True)
    p.add_argument('--service-port',required=True,type=int)
    a=p.parse_args()
    def read(path):
        with open(path,'rb') as f:
            raw=f.read(5*1024*1024+1)
        if len(raw)>5*1024*1024:
            raise ValueError('Input exceeds 5 MiB')
        return raw
    try:
        result=inspect_eks_service(read(a.inventory),read(a.eks),read(a.service),a.namespace,a.service_name,a.service_port)
    except (ValueError,OSError) as exc:
        p.exit(2,'Analysis failed: '+str(exc)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':
    main()
