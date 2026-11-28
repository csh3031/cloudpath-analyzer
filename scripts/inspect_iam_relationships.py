#!/usr/bin/env python3
"""Inspect asserted IAM membership or workload role configuration offline."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.iam_inventory import MAX_BYTES
from backend.aws.iam_relationships import inspect_iam_relationships

def read(path):
    with open(path,'rb') as f: return f.read(MAX_BYTES+1)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory',required=True); p.add_argument('--relationships',required=True); p.add_argument('--overlay')
    g=p.add_mutually_exclusive_group(required=True); g.add_argument('--user'); g.add_argument('--workload',nargs=2,metavar=('SERVICE','REF'))
    a=p.parse_args()
    try:
        r=inspect_iam_relationships(read(a.inventory),read(a.relationships),user_arn=a.user,workload=a.workload,overlay_raw=read(a.overlay) if a.overlay else None)
    except (OSError,ValueError,TypeError,RecursionError) as exc: p.exit(2,'Relationship inspection failed: '+str(exc)+'\n')
    print(json.dumps(r,indent=2,ensure_ascii=False))
if __name__=='__main__': main()
