#!/usr/bin/env python3
"""Offline comparison of already exported Reachability Analyzer evidence."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.aws.reachability_evidence import compare_reachability, MAX_BYTES


def read_limited(path):
    with open(path, 'rb') as f:
        return f.read(MAX_BYTES + 1)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('inventory','paths','analyses','source-ip','destination-ip'):
        p.add_argument('--'+name, required=True)
    for name in ('source-port','destination-port'):
        p.add_argument('--'+name, required=True, type=int)
    a = p.parse_args()
    try:
        result = compare_reachability(*(read_limited(x) for x in (a.inventory,a.paths,a.analyses)),
                                     a.source_ip,a.destination_ip,a.source_port,a.destination_port)
    except (ValueError, OSError) as exc:
        p.exit(2, 'Comparison failed: ' + str(exc) + '\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
