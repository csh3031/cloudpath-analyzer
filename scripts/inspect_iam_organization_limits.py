#!/usr/bin/env python3
"""Inspect asserted SCP/RCP guardrails offline."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.iam_organization_limits import analyze_iam_organization_limits, MAX_ORG_BYTES
from backend.aws.s3_authorization_evidence import MAX_BYTES


def read(path,limit):
    if path is None: return None
    with open(path,'rb') as f: return f.read(limit+1)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--authorization',required=True)
    p.add_argument('--organization')
    a=p.parse_args()
    try:
        r=analyze_iam_organization_limits(read(a.authorization,MAX_BYTES),read(a.organization,MAX_ORG_BYTES))
    except (ValueError,OSError,RecursionError) as exc:
        p.exit(2,'Analysis failed: '+str(exc)+'\n')
    print(json.dumps(r,ensure_ascii=False,indent=2))
