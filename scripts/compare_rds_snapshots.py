#!/usr/bin/env python3
"""Compare two historical RDS path snapshots from the same EC2 source."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from backend.aws.rds_failover_evidence import compare_rds_snapshots

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for when in ('before','after'):
        for kind in ('inventory','rds','observation'):p.add_argument('--'+when+'-'+kind,required=True)
    p.add_argument('--identifier',required=True);p.add_argument('--client-ip',required=True);p.add_argument('--source-port',required=True,type=int);p.add_argument('--cluster',action='store_true')
    a=p.parse_args()
    def read(path):
        with open(path,'rb') as f:r=f.read(5*1024*1024+1)
        if len(r)>5*1024*1024:raise ValueError('Input exceeds 5 MiB')
        return r
    try:
        bundles=[tuple(read(getattr(a,w+'_'+k)) for k in ('inventory','rds','observation')) for w in ('before','after')]
        r=compare_rds_snapshots(*bundles,a.identifier,a.client_ip,a.source_port,cluster=a.cluster)
    except (ValueError,OSError) as exc:p.exit(2,'Analysis failed: '+str(exc)+'\n')
    print(json.dumps(r,ensure_ascii=False,indent=2))
if __name__=='__main__':main()
