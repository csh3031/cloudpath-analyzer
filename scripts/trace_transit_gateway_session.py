#!/usr/bin/env python3
"""Offline single Transit Gateway TCP constraints."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.tgw_session_evidence import analyze_tgw_session


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source-inventory','destination-inventory','tgw','source-ip','destination-ip'):
        p.add_argument('--'+name,required=True)
    for name in ('source-port','destination-port'):
        p.add_argument('--'+name,required=True,type=int)
    a=p.parse_args()
    def read(path):
        with open(path,'rb') as f:
            raw=f.read(5*1024*1024+1)
        if len(raw)>5*1024*1024:
            raise ValueError('Input exceeds 5 MiB')
        return raw
    try:
        result=analyze_tgw_session(read(a.source_inventory),read(a.destination_inventory),read(a.tgw),a.source_ip,a.destination_ip,a.source_port,a.destination_port)
    except (ValueError,OSError) as exc:
        p.exit(2,'Analysis failed: '+str(exc)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':
    main()
