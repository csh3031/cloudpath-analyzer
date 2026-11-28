#!/usr/bin/env python3
"""Inspect asserted S3 ownership ACL and public access offline."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.s3_acl_evidence import analyze_s3_acl, MAX_BYTES

def read(path):
    with open(path,'rb') as f: return f.read(MAX_BYTES+1)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--authorization',required=True)
    p.add_argument('--access')
    a=p.parse_args()
    try: result=analyze_s3_acl(read(a.authorization),read(a.access) if a.access else None)
    except (ValueError,OSError,RecursionError) as exc: p.exit(2,'Analysis failed: '+str(exc)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))
