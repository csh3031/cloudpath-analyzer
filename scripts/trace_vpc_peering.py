#!/usr/bin/env python3
"""Offline direct VPC peering route candidate comparison."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.peering_evidence import trace_direct_peering


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source-inventory','destination-inventory','peering','source-ip','destination-ip'):
        p.add_argument('--'+name,required=True)
    a=p.parse_args()
    def read(path):
        with open(path,'rb') as f:
            raw=f.read(5*1024*1024+1)
        if len(raw)>5*1024*1024:
            raise ValueError('Input exceeds 5 MiB')
        return raw
    try:
        result=trace_direct_peering(read(a.source_inventory),read(a.destination_inventory),read(a.peering),a.source_ip,a.destination_ip)
    except (ValueError,OSError) as exc:
        p.exit(2,'Analysis failed: '+str(exc)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':
    main()
