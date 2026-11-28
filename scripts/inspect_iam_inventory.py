#!/usr/bin/env python3
"""Inspect a normalized IAM inventory and optional isolated overlay, entirely offline."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.iam_inventory import MAX_BYTES, register_iam_inventory


def read(path):
    with open(path,'rb') as f:
        return f.read(MAX_BYTES+1)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory',required=True)
    p.add_argument('--overlay')
    p.add_argument('--include-model',action='store_true',help='Explicitly include policy documents and IAM records in output; may be sensitive')
    args=p.parse_args()
    try:
        result=register_iam_inventory(read(args.inventory),read(args.overlay) if args.overlay else None)
    except (ValueError,OSError,RecursionError,TypeError) as exc:
        p.exit(2,'Registration failed: '+str(exc)+'\n')
    if not args.include_model:
        result.pop('effective')
    print(json.dumps(result,ensure_ascii=False,indent=2))
