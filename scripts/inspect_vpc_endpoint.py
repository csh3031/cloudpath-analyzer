#!/usr/bin/env python3
"""Offline VPC endpoint configuration inspection."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.vpc_endpoint_evidence import inspect_vpc_endpoint


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('inventory','endpoints','endpoint-id'):
        p.add_argument('--'+name,required=True)
    a=p.parse_args()
    def read(path):
        with open(path,'rb') as f:
            raw=f.read(5*1024*1024+1)
        if len(raw)>5*1024*1024:
            raise ValueError('Input exceeds 5 MiB')
        return raw
    try:
        result=inspect_vpc_endpoint(read(a.inventory),read(a.endpoints),a.endpoint_id)
    except (ValueError,OSError) as exc:
        p.exit(2,'Analysis failed: '+str(exc)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':
    main()
