"""Offline RDS logical endpoint/configuration correlation; never DNS or path proof."""
import hashlib
import re
from backend.aws.peering_evidence import _load, _timestamp
from backend.iac.plan_adapter import _read

FORMAT = 'cloudpath-rds-config-v1'
IDENT = re.compile(r'[a-z][a-z0-9-]{0,62}')
HOST = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+rds\.amazonaws\.com')
ENGINES = ('mysql','postgres','mariadb','oracle-ee','oracle-se2','sqlserver-ee','sqlserver-se','sqlserver-ex','sqlserver-web','db2-ae','db2-se')
CLUSTER_ENGINES = ('aurora-mysql','aurora-postgresql','mysql','postgres')


def _identifier(v):
    return isinstance(v,str) and IDENT.fullmatch(v) is not None and not v.endswith('-') and '--' not in v


def _rows(v):
    if not isinstance(v,list) or len(v)>300 or any(not isinstance(x,dict) for x in v):
        raise ValueError('Invalid RDS evidence rows')
    return v


def _index(v,key):
    result={}
    for row in _rows(v):
        k=row.get(key)
        if not _identifier(k) or k in result:
            raise ValueError('Invalid or duplicate RDS identifier')
        result[k]=row
    return result


def _host(v):
    return isinstance(v,str) and HOST.fullmatch(v) is not None


def _port(v):
    return type(v) is int and 1<=v<=65535


def inspect_rds_configuration(inventory_raw,rds_raw,kind,identifier):
    if kind not in ('instance','cluster') or not _identifier(identifier):
        raise ValueError('Expected RDS instance/cluster and identifier')
    if not isinstance(rds_raw,bytes) or len(rds_raw)>5*1024*1024:
        raise ValueError('RDS evidence exceeds limit or is not bytes')
    identity,meta,inv=_load(inventory_raw)
    d=_read(rds_raw)
    if set(d)!={'format','inventory_identity','region','account_id','collected_at','complete','DBInstances','DBClusters','DBSubnetGroups'} or d['format']!=FORMAT:
        raise ValueError('Expected normalized RDS configuration wrapper')
    if not isinstance(d['account_id'],str) or not re.fullmatch(r'[0-9]{12}',d['account_id']):
        raise ValueError('Invalid RDS account scope')
    gap=abs((_timestamp(d['collected_at'])-_timestamp(meta['collected_at'])).total_seconds())
    instances=_index(d['DBInstances'],'DBInstanceIdentifier'); clusters=_index(d['DBClusters'],'DBClusterIdentifier'); groups=_index(d['DBSubnetGroups'],'DBSubnetGroupName')
    # Only selected fields are returned; never credentials or arbitrary source fields.
    result=dict(analysis_type='STATIC_AWS_RDS_CONFIGURATION',input_identity=identity,
                rds_input_identity='sha256-rds-config-v1:'+hashlib.sha256(rds_raw).hexdigest(),
                region=meta['region'],vpc_id=meta['vpc_id'],kind=kind,identifier=identifier,time_gap_seconds=gap,
                configuration=None,endpoints=[],members=[],dns_status='NOT_EVALUATED',route_status='NOT_EVALUATED',
                policy_status='NOT_EVALUATED',authentication_status='NOT_EVALUATED',session_status='UNKNOWN',live_observation=False,
                limitations=['Offline normalized configuration; account ownership, completeness and simultaneous state are asserted only.',
                             'Private IPv4 available provisioned RDS/Aurora configuration only; no global cluster, custom endpoints or proxy.',
                             'Subnet group membership and AZ are not exact ENI or IP placement; no DNS lookup, runtime target selection, failover or database authentication.',
                             'No AWS API calls or packets.'])
    def unknown(reason): return dict(result,status='UNKNOWN',reason=reason)
    if d['inventory_identity']!=identity or d['region']!=meta['region']: return unknown('RDS_INVENTORY_SCOPE_MISMATCH')
    if gap>300: return unknown('SNAPSHOT_TIME_GAP')
    if d['complete'] is not True: return unknown('RDS_EVIDENCE_INCOMPLETE')
    def arn_ok(row,k,name):
        return row.get('DBInstanceArn' if k=='db' else 'DBClusterArn')==f"arn:aws:rds:{meta['region']}:{d['account_id']}:{k}:{name}"
    def sg_ids(row):
        values=[]
        for s in _rows(row.get('VpcSecurityGroups',[])):
            g=s.get('VpcSecurityGroupId')
            if not isinstance(g,str) or s.get('Status')!='active' or g in values or not any(x.get('GroupId')==g and x.get('VpcId')==meta['vpc_id'] for x in inv['SecurityGroups']): return None
            values.append(g)
        return sorted(values) if values else None
    def subnet_group(name):
        group=groups.get(name) if isinstance(name,str) else None
        if not group or group.get('VpcId')!=meta['vpc_id'] or group.get('SubnetGroupStatus')!='Complete': return None
        values=[]; seen=set()
        for s in _rows(group.get('Subnets',[])):
            sid=s.get('SubnetIdentifier'); zone=s.get('SubnetAvailabilityZone')
            if not isinstance(sid,str) or sid in seen or not isinstance(zone,dict) or not isinstance(zone.get('Name'),str) or s.get('SubnetStatus')!='Active': return None
            matches=[x for x in inv['Subnets'] if x.get('SubnetId')==sid and x.get('VpcId')==meta['vpc_id'] and x.get('State')=='available' and x.get('AvailabilityZone')==zone.get('Name')]
            if len(matches)!=1: return None
            seen.add(sid);values.append(dict(subnet_id=sid,availability_zone=zone['Name']))
        return sorted(values,key=lambda x:x['subnet_id']) if values else None
    def instance_config(name,row):
        if not arn_ok(row,'db',name): return None,'RDS_INSTANCE_SCOPE_MISMATCH'
        if row.get('DBInstanceStatus')!='available': return None,'RDS_INSTANCE_STATE_UNCONFIRMED'
        if row.get('PubliclyAccessible') is not False or row.get('NetworkType')!='IPV4': return None,'RDS_NETWORK_PROFILE_UNSUPPORTED'
        if row.get('Engine') not in ENGINES+CLUSTER_ENGINES: return None,'RDS_ENGINE_UNSUPPORTED'
        embedded=row.get('DBSubnetGroup'); gn=embedded.get('DBSubnetGroupName') if isinstance(embedded,dict) else None
        subs=subnet_group(gn)
        if not subs or embedded.get('VpcId')!=meta['vpc_id']: return None,'RDS_SUBNET_GROUP_UNCONFIRMED'
        # Embedded group is also a snapshot assertion: do not silently ignore conflicting rows.
        erows=_rows(embedded.get('Subnets',[])); expected=groups[gn]
        if embedded.get('SubnetGroupStatus')!=expected['SubnetGroupStatus'] or sorted((str(x.get('SubnetIdentifier')),str(x.get('SubnetStatus')),str(x.get('SubnetAvailabilityZone',{}).get('Name') if isinstance(x.get('SubnetAvailabilityZone'),dict) else None)) for x in erows)!=sorted((str(x.get('SubnetIdentifier')),str(x.get('SubnetStatus')),str(x['SubnetAvailabilityZone']['Name'])) for x in expected['Subnets']): return None,'RDS_SUBNET_GROUP_CONFLICT'
        az=row.get('AvailabilityZone')
        if not isinstance(az,str) or not any(x['availability_zone']==az for x in subs): return None,'RDS_AZ_UNCONFIRMED'
        sg=sg_ids(row)
        if not sg: return None,'RDS_SECURITY_GROUPS_UNCONFIRMED'
        ep=row.get('Endpoint')
        if not isinstance(ep,dict) or not _host(ep.get('Address')) or not _port(ep.get('Port')): return None,'RDS_ENDPOINT_UNCONFIRMED'
        if type(row.get('MultiAZ')) is not bool: return None,'RDS_DEPLOYMENT_UNCONFIRMED'
        return dict(identifier=name,engine=row['Engine'],subnet_group=gn,subnets=subs,availability_zone=az,security_group_ids=sg,multi_az=row['MultiAZ'],endpoint=dict(kind='INSTANCE',hostname=ep['Address'],port=ep['Port'],ip=None,eni_id=None)),None
    def cluster_config(name,row):
        if not arn_ok(row,'cluster',name): return None,'RDS_CLUSTER_SCOPE_MISMATCH'
        if row.get('Status')!='available': return None,'RDS_CLUSTER_STATE_UNCONFIRMED'
        if row.get('Engine') not in CLUSTER_ENGINES or row.get('EngineMode')!='provisioned' or row.get('GlobalClusterIdentifier') or row.get('ReplicationSourceIdentifier') or row.get('ServerlessV2ScalingConfiguration') or row.get('NetworkType')!='IPV4': return None,'RDS_CLUSTER_PROFILE_UNSUPPORTED'
        gn=row.get('DBSubnetGroup'); subs=subnet_group(gn); sg=sg_ids(row)
        if not subs: return None,'RDS_SUBNET_GROUP_UNCONFIRMED'
        if not sg: return None,'RDS_SECURITY_GROUPS_UNCONFIRMED'
        if not _host(row.get('Endpoint')) or not _host(row.get('ReaderEndpoint')) or row['Endpoint']==row['ReaderEndpoint'] or not _port(row.get('Port')): return None,'RDS_ENDPOINT_UNCONFIRMED'
        members=[]; seen=set()
        for m in _rows(row.get('DBClusterMembers',[])):
            mid=m.get('DBInstanceIdentifier'); writer=m.get('IsClusterWriter')
            if not _identifier(mid) or mid in seen or type(writer) is not bool or mid not in instances: return None,'RDS_CLUSTER_MEMBERS_UNCONFIRMED'
            inst=instances[mid]; cfg,reason=instance_config(mid,inst)
            if reason: return None,reason
            if inst.get('DBClusterIdentifier')!=name or cfg['engine']!=row['Engine'] or cfg['subnet_group']!=gn or cfg['security_group_ids']!=sg or cfg['endpoint']['port']!=row['Port']: return None,'RDS_CLUSTER_MEMBER_CONFLICT'
            seen.add(mid);members.append(dict(cfg,role='WRITER' if writer else 'READER'))
        if sum(m['role']=='WRITER' for m in members)!=1 or seen!={k for k,v in instances.items() if v.get('DBClusterIdentifier')==name}: return None,'RDS_CLUSTER_MEMBERS_UNCONFIRMED'
        if len({m['endpoint']['hostname'] for m in members}|{row['Endpoint'],row['ReaderEndpoint']})!=len(members)+2: return None,'RDS_ENDPOINT_AMBIGUOUS'
        endpoints=[dict(kind=k,hostname=row[field],port=row['Port'],ip=None,eni_id=None) for k,field in [('WRITER','Endpoint'),('READER','ReaderEndpoint')]]
        return dict(identifier=name,engine=row['Engine'],subnet_group=gn,subnets=subs,security_group_ids=sg,endpoints=endpoints,members=members),None
    if kind=='instance':
        row=instances.get(identifier)
        if row is None: return unknown('RDS_INSTANCE_MISSING')
        cfg,reason=instance_config(identifier,row)
        if reason: return unknown(reason)
        cid=row.get('DBClusterIdentifier')
        if cid is not None:
            if not _identifier(cid) or cid not in clusters: return unknown('RDS_CLUSTER_UNCONFIRMED')
            cc,reason=cluster_config(cid,clusters[cid])
            if reason: return unknown(reason)
            cfg['cluster_identifier']=cid; cfg['cluster_role']=next((m['role'] for m in cc['members'] if m['identifier']==identifier),None)
            if cfg['cluster_role'] is None: return unknown('RDS_CLUSTER_MEMBER_CONFLICT')
        elif row['Engine'] in ('aurora-mysql','aurora-postgresql') or any(any(m.get('DBInstanceIdentifier')==identifier for m in _rows(c.get('DBClusterMembers',[]))) for c in clusters.values()): return unknown('RDS_CLUSTER_UNCONFIRMED')
        endpoint=cfg.pop('endpoint');result.update(configuration=cfg,endpoints=[endpoint])
    else:
        row=clusters.get(identifier)
        if row is None: return unknown('RDS_CLUSTER_MISSING')
        cfg,reason=cluster_config(identifier,row)
        if reason: return unknown(reason)
        result.update(endpoints=cfg.pop('endpoints'),members=cfg.pop('members'),configuration=cfg)
    return dict(result,status='RDS_CONFIGURATION_CANDIDATE',reason='MATCHED_RDS_LOGICAL_CONFIGURATION')
