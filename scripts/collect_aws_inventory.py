#!/usr/bin/env python3
"""Collect configuration from one authorized VPC using AWS CLI v2 Describe calls."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime,timezone
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.snapshot import FORMAT, OPERATIONS, sanitize_inventory, load_aws_snapshot, _id


def collect(region,vpc_id,profile=None,*,run=subprocess.run):
    _id(vpc_id,'vpc')
    if not re.fullmatch(r'[a-z]{2}(?:-[a-z0-9]+)+-\d+',region):raise ValueError('Invalid AWS region')
    if profile is not None and not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@-]{0,127}',profile):raise ValueError('Invalid CLI profile')
    data={}
    for op,(key,filter_name) in OPERATIONS.items():
        cmd=['aws','ec2',op,'--region',region,'--filters',f'Name={filter_name},Values={vpc_id}','--output','json','--no-cli-pager','--no-cli-auto-prompt']
        if profile:cmd+=['--profile',profile]
        # CLI v2 handles pagination automatically. No --max-items / --no-paginate.
        try:
            result=run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=120,env={**os.environ,'AWS_PAGER':''})
            if len(result.stdout)>32*1024*1024:raise ValueError('AWS response exceeds size limit')
            response=json.loads(result.stdout)
            if not isinstance(response,dict) or not isinstance(response.get(key),list) or response.get('NextToken'):raise ValueError('Incomplete AWS CLI response')
            data[key]=response[key]
        except FileNotFoundError as exc:raise ValueError('AWS CLI v2 not found; install/configure through your authorized environment') from exc
        except (subprocess.CalledProcessError,subprocess.TimeoutExpired,UnicodeError,json.JSONDecodeError) as exc:raise ValueError(f'{op} failed; check authorized profile, region, permissions and connectivity') from exc
    doc={'format':FORMAT,'region':region,'vpc_id':vpc_id,'collected_at':datetime.now(timezone.utc).isoformat(),'inventory':sanitize_inventory(data)}
    raw=json.dumps(doc,ensure_ascii=False,indent=2,allow_nan=False).encode('utf-8')
    if len(raw)>5*1024*1024:raise ValueError('Inventory exceeds 5 MiB')
    load_aws_snapshot(raw)
    return raw


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--region',required=True);p.add_argument('--vpc-id',required=True);p.add_argument('--profile');p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.output.suffix!='.json' or a.output.exists():p.error('Choose a new .json output path; existing files never overwritten')
    try:
        raw=collect(a.region,a.vpc_id,a.profile)
        # Exclusive creation and private mode (Linux; Windows filesystem permissions may differ).
        fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        try:
            with os.fdopen(fd,'wb') as f:f.write(raw)
        except BaseException:
            a.output.unlink(missing_ok=True);raise
    except (ValueError,OSError) as exc:p.error(str(exc))
    print('[OK] Local AWS inventory saved:',a.output)
    print('[INFO] Configuration only; no active probing, deployment or AWS changes.')

if __name__=='__main__':main()
