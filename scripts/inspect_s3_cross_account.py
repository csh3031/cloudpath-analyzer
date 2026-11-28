#!/usr/bin/env python3
"""Inspect the asserted S3 cross-account policy path offline."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.aws.s3_cross_account_evidence import analyze_s3_cross_account
from backend.aws.s3_authorization_evidence import MAX_BYTES

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--authorization', required=True)
    a = p.parse_args()
    try:
        with open(a.authorization, 'rb') as f:
            result = analyze_s3_cross_account(f.read(MAX_BYTES + 1))
    except (ValueError, OSError, RecursionError) as exc:
        p.exit(2, 'Analysis failed: ' + str(exc) + '\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))
