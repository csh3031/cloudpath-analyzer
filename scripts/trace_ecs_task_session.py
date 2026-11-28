#!/usr/bin/env python3
"""Offline ECS task-to-task TCP path constraints."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.ecs_session_evidence import analyze_ecs_task_session


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('inventory','ecs','source-task-id','destination-task-id'):
        p.add_argument('--'+name,required=True)
    for name in ('source-port','destination-port'):
        p.add_argument('--'+name,required=True,type=int)
    p.add_argument('--prefix-lists',help='Optional normalized prefix list evidence JSON')
    a=p.parse_args()
    def read(path):
        with open(path,'rb') as f:
            raw=f.read(5*1024*1024+1)
        if len(raw)>5*1024*1024:
            raise ValueError('Input exceeds 5 MiB')
        return raw
    try:
        result=analyze_ecs_task_session(read(a.inventory),read(a.ecs),a.source_task_id,a.destination_task_id,a.source_port,a.destination_port,prefix_list_raw=read(a.prefix_lists) if a.prefix_lists else None)
    except (ValueError,OSError) as exc:
        p.exit(2,'Analysis failed: '+str(exc)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))

if __name__=='__main__':
    main()
