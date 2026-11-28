"""Compare independently validated historical EC2-to-RDS snapshots; no failover event proof."""
from backend.aws.rds_session_evidence import analyze_rds_session
from backend.aws.peering_evidence import _timestamp
from backend.iac.plan_adapter import _read


def compare_rds_snapshots(before, after, identifier, client_ip, source_port, *, cluster=False):
    """Each tuple is inventory, configuration, observation bytes; same EC2 source, writer or instance."""
    results=[analyze_rds_session(*bundle,identifier,'ec2',source_port,client_ip=client_ip,
                                 endpoint_kind='WRITER' if cluster else None) for bundle in (before,after)]
    a,b=results
    out=dict(analysis_type='STATIC_AWS_RDS_HISTORICAL_TRANSITION',before=a,after=b,
             status='UNKNOWN',reason=None,changes=None,failover_status='UNKNOWN',session_status='UNKNOWN',live_observation=False,
             limitations=['Two independently submitted historical snapshots only; not proof of failover, cause, outage duration or recovery.',
                          'Same EC2 source, account, VPC, stable DB resource identity and logical endpoint required.',
                          'No simulated promotion, AWS calls, DNS queries or packet transmission.'])
    def unknown(reason): return dict(out,reason=reason)
    if any(r['destination_endpoint'] is None for r in results): return unknown('RDS_TRANSITION_ENDPOINT_UNCONFIRMED')
    ds=[_read(bundle[1]) for bundle in (before,after)]
    obs=[_read(bundle[2]) for bundle in (before,after)]
    times=[]
    for bundle,o in zip((before,after),obs):
        ts=[_read(bundle[0])['collected_at'],_read(bundle[1])['collected_at'],o['collected_at'],o['resolved_at']]
        if cluster:ts.append(o['member_resolved_at'])
        times.append([_timestamp(t) for t in ts])
    if max(times[0])>=min(times[1]): return unknown('RDS_TRANSITION_TIME_ORDER_UNCONFIRMED')
    if ds[0]['account_id']!=ds[1]['account_id'] or any(a['rds_configuration'][k]!=b['rds_configuration'][k] for k in ('region','vpc_id')) or any(a['source_endpoint'].get(k)!=b['source_endpoint'].get(k) for k in ('eni_id','instance_id','private_ip','subnet_id')):
        return unknown('RDS_TRANSITION_SCOPE_MISMATCH')
    key='DBClusterIdentifier' if cluster else 'DBInstanceIdentifier'; field='DbClusterResourceId' if cluster else 'DbiResourceId'
    rs=[next(x for x in d['DBClusters' if cluster else 'DBInstances'] if x[key]==identifier) for d in ds]
    rid=rs[0].get(field)
    if not isinstance(rid,str) or not rid or rid!=rs[1].get(field): return unknown('RDS_TRANSITION_RESOURCE_ID_UNCONFIRMED')
    x,y=[r['destination_endpoint'] for r in results]
    if (x['hostname'],x['port'],rs[0]['Engine'])!=(y['hostname'],y['port'],rs[1]['Engine']): return unknown('RDS_TRANSITION_LOGICAL_ENDPOINT_CHANGED')
    if cluster:
        # Require stable member identities and roles, not reused names after recreation.
        member_maps=[]
        for d,r in zip(ds,results):
            members={m['identifier'] for m in r['rds_configuration']['members']}
            member_maps.append({i['DBInstanceIdentifier']:i.get('DbiResourceId') for i in d['DBInstances'] if i['DBInstanceIdentifier'] in members})
        if member_maps[0]!=member_maps[1] or any(not isinstance(v,str) or not v for v in member_maps[0].values()) or len(set(member_maps[0].values()))!=len(member_maps[0]): return unknown('RDS_TRANSITION_MEMBER_ID_UNCONFIRMED')
        transition=x['identifier']!=y['identifier']
        reason='RDS_WRITER_ROLE_CHANGE_CANDIDATE' if transition else 'RDS_NO_WRITER_ROLE_CHANGE_OBSERVED'
    else:
        if any(r.get('MultiAZ') is not True or r.get('DBClusterIdentifier') is not None for r in rs): return unknown('RDS_MULTI_AZ_INSTANCE_SCOPE_UNCONFIRMED')
        transition=x['availability_zone']!=y['availability_zone']
        reason='RDS_PRIMARY_AZ_CHANGE_CANDIDATE' if transition else 'RDS_NO_PRIMARY_AZ_CHANGE_OBSERVED'
    return dict(out,status='RDS_SNAPSHOT_TRANSITION_CANDIDATE',reason=reason,changes=dict(
        before_member=x['identifier'],after_member=y['identifier'],before_az=x['availability_zone'],after_az=y['availability_zone'],
        before_ip=x['private_ip'],after_ip=y['private_ip'],ip_changed=x['private_ip']!=y['private_ip'],
        eni_changed=x['eni_id']!=y['eni_id'],role_or_az_changed=transition,
        before_request=a['request_status'],after_request=b['request_status'],before_response=a['response_status'],after_response=b['response_status']))
