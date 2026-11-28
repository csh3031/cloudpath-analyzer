#!/usr/bin/env python3
"""Offline S3 policy candidate inspection; no AWS requests."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.s3_authorization_evidence import analyze_s3_authorization, MAX_BYTES

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--evidence',required=True)
    args=p.parse_args()
    try:
        with open(args.evidence,'rb') as f:
            r=analyze_s3_authorization(f.read(MAX_BYTES+1))
    except (ValueError,OSError) as exc:
        p.exit(2,'Analysis failed: '+str(exc)+'\n')
    print(json.dumps(r,ensure_ascii=False,indent=2))
