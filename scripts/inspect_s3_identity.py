#!/usr/bin/env python3
"""Offline S3 IAM attachment inspection; no AWS requests."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.s3_identity_evidence import analyze_s3_identity, MAX_IDENTITY_BYTES
from backend.aws.s3_authorization_evidence import MAX_BYTES


def read(path, limit):
    with open(path,'rb') as f:
        return f.read(limit+1)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--authorization',required=True)
    p.add_argument('--identity')
    args=p.parse_args()
    try:
        r=analyze_s3_identity(read(args.authorization,MAX_BYTES),read(args.identity,MAX_IDENTITY_BYTES) if args.identity else None)
    except (ValueError,OSError,RecursionError) as exc:
        p.exit(2,'Analysis failed: '+str(exc)+'\n')
    print(json.dumps(r,ensure_ascii=False,indent=2))
