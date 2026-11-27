"""Offline EKS cluster, EC2 node and Pod secondary IPv4 correlation only."""
import hashlib
import re
from ipaddress import IPv4Address, IPv4Network
from backend.aws.peering_evidence import _load, _timestamp, _primary_only
from backend.iac.plan_adapter import _read

FORMAT = 'cloudpath-eks-pod-evidence-v1'
ARN = re.compile(r'arn:aws:eks:([a-z0-9-]+):([0-9]{12}):cluster/([A-Za-z0-9_-]+)')
NAME = re.compile(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?')
UID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
PROVIDER = re.compile(r'aws:///([a-z0-9-]+)/((?:i-)[0-9a-f]{8,17})')
PROFILE = {'plugin':'aws-vpc-cni','address_mode':'secondary-ip','custom_networking':False,
           'security_groups_for_pods':False,'prefix_delegation':False,'auto_mode':False}


def obj(x):
    if not isinstance(x,dict): raise ValueError('Expected EKS object')
    return x


def rows(x):
    if not isinstance(x,list) or len(x)>300 or any(not isinstance(v,dict) for v in x):
        raise ValueError('Invalid EKS evidence rows')
    return x


def name(x):
    return isinstance(x,str) and NAME.fullmatch(x) is not None


def index(items, namespaced=False):
    result={}; uids=set()
    for row in rows(items):
        m=obj(row.get('metadata')); n=m.get('name'); uid=m.get('uid'); ns=m.get('namespace')
        if not name(n) or (namespaced and not name(ns)) or not isinstance(uid,str) or not UID.fullmatch(uid):
            raise ValueError('Invalid Kubernetes identity')
        key=(ns,n) if namespaced else n
        if key in result or uid in uids: raise ValueError('Duplicate Kubernetes identity')
        result[key]=row; uids.add(uid)
    return result


def inspect_eks_pod(inventory_raw, eks_raw, namespace, pod_name):
    if not name(namespace) or not name(pod_name): raise ValueError('Invalid namespace or pod name')
    identity,meta,inv=_load(inventory_raw); doc=_read(eks_raw)
    if set(doc)!={'format','collected_at','inventory_identity','complete','cluster','cni','namespaces','nodes','pods'} or doc['format']!=FORMAT:
        raise ValueError('Expected normalized EKS evidence wrapper')
    cluster=obj(doc['cluster']); cfg=obj(cluster.get('resourcesVpcConfig')); cni=obj(doc['cni'])
    namespaces=index(doc['namespaces']); nodes=index(doc['nodes']); pods=index(doc['pods'],True)
    gap=abs((_timestamp(doc['collected_at'])-_timestamp(meta['collected_at'])).total_seconds())
    result=dict(analysis_type='STATIC_AWS_EKS_POD_ENDPOINT',input_identity=identity,
        eks_input_identity='sha256-eks-pod-v1:'+hashlib.sha256(eks_raw).hexdigest(),
        region=meta['region'],vpc_id=meta['vpc_id'],namespace=namespace,pod_name=pod_name,time_gap_seconds=gap,
        cluster=None,node=None,pod=None,endpoint=None,route_status='NOT_EVALUATED',policy_status='NOT_EVALUATED',
        session_status='UNKNOWN',live_observation=False,limitations=[
            'Offline normalized evidence; asserted cluster membership, completeness and CNI mode are not authenticated.',
            'Ordinary Linux EC2 nodes, standard VPC CNI secondary IPv4 mode only; no prefix, custom networking, branch ENI, Fargate, Auto Mode or hostNetwork.',
            'Node and Pod IP association is not proof of CNI allocation, readiness, policy applicability or traffic delivery.',
            'Container names only; no runtime listener, Service, NetworkPolicy, AWS calls or packets.'])
    def unknown(reason): return dict(result,status='UNKNOWN',reason=reason)
    if doc['inventory_identity']!=identity: return unknown('INVENTORY_IDENTITY_MISMATCH')
    if doc['complete'] is not True: return unknown('EKS_EVIDENCE_INCOMPLETE')
    if gap>300: return unknown('SNAPSHOT_TIME_GAP')
    arn=cluster.get('arn'); match=ARN.fullmatch(arn) if isinstance(arn,str) else None
    if not match or match[1]!=meta['region'] or cluster.get('name')!=match[3] or cfg.get('vpcId')!=meta['vpc_id']:
        return unknown('CLUSTER_SCOPE_MISMATCH')
    if cluster.get('status')!='ACTIVE': return unknown('CLUSTER_NOT_ACTIVE')
    subnet_map={s['SubnetId']:s for s in inv['Subnets']}
    cluster_subnets=cfg.get('subnetIds')
    if not isinstance(cluster_subnets,list) or not cluster_subnets or any(not isinstance(s,str) or s not in subnet_map for s in cluster_subnets) or len(set(cluster_subnets))!=len(cluster_subnets):
        return unknown('CLUSTER_SUBNETS_UNCONFIRMED')
    result['cluster']={'name':match[3],'vpc_id':meta['vpc_id'],'configured_cluster_subnets':cluster_subnets}
    if set(cni)!=set(PROFILE) or any(type(cni[k]) is not type(v) or cni[k]!=v for k,v in PROFILE.items()):
        return unknown('UNSUPPORTED_OR_UNCONFIRMED_CNI_PROFILE')
    ns=namespaces.get(namespace); pod=pods.get((namespace,pod_name))
    if not ns or obj(ns.get('status',{})).get('phase')!='Active' or ns['metadata'].get('deletionTimestamp') is not None:
        return unknown('NAMESPACE_UNCONFIRMED')
    if not pod: return unknown('POD_NOT_FOUND')
    pm=pod['metadata']; spec=obj(pod.get('spec')); ps=obj(pod.get('status'))
    if pm.get('deletionTimestamp') is not None or ps.get('phase')!='Running': return unknown('POD_NOT_RUNNING')
    if spec.get('hostNetwork',False) is not False: return unknown('HOST_NETWORK_UNSUPPORTED')
    node_name=spec.get('nodeName'); node=nodes.get(node_name) if isinstance(node_name,str) else None
    if not node or node['metadata'].get('deletionTimestamp') is not None: return unknown('NODE_UNCONFIRMED')
    nm=node['metadata']; node_spec=obj(node.get('spec')); nstatus=obj(node.get('status'))
    labels=obj(nm.get('labels',{})); provider=node_spec.get('providerID'); p=PROVIDER.fullmatch(provider) if isinstance(provider,str) else None
    if not p or labels.get('kubernetes.io/os')!='linux' or labels.get('eks.amazonaws.com/compute-type') not in (None,'ec2'):
        return unknown('UNSUPPORTED_NODE_PROVIDER')
    az,iid=p.groups()
    if any(other is not node and obj(other.get('spec')).get('providerID')==provider for other in nodes.values()):
        return unknown('NODE_PROVIDER_AMBIGUOUS')
    instances=[i for r in inv['Reservations'] for i in r['Instances']]
    inst=next((i for i in instances if i.get('InstanceId')==iid),None)
    if not inst or inst.get('State',{}).get('Name')!='running': return unknown('NODE_INSTANCE_UNCONFIRMED')
    sid=inst.get('SubnetId'); subnet=subnet_map.get(sid)
    if not subnet or subnet.get('State')!='available' or subnet.get('AvailabilityZone')!=az or labels.get('topology.kubernetes.io/zone')!=az:
        return unknown('NODE_AZ_OR_SUBNET_MISMATCH')
    host_ip=inst.get('PrivateIpAddress'); internal=[x.get('address') for x in rows(nstatus.get('addresses',[])) if x.get('type')=='InternalIP']
    if internal!=[host_ip] or ps.get('hostIP')!=host_ip or not isinstance(host_ip,str): return unknown('NODE_HOST_IP_MISMATCH')
    enis=inv['NetworkInterfaces']; instance_enis={e.get('NetworkInterfaceId') for e in inst.get('NetworkInterfaces',[])}
    primary=[e for e in enis if e.get('Attachment',{}).get('InstanceId')==iid and e.get('Attachment',{}).get('DeviceIndex')==0]
    if len(primary)!=1 or primary[0]['NetworkInterfaceId'] not in instance_enis or primary[0].get('SubnetId')!=sid or primary[0].get('PrivateIpAddress')!=host_ip or primary[0].get('Status')!='in-use' or primary[0].get('InterfaceType')!='interface':
        return unknown('NODE_PRIMARY_ENI_UNCONFIRMED')
    result['node']={'name':node_name,'uid':nm['uid'],'instance_id':iid,'private_ip':host_ip,'primary_eni_id':primary[0]['NetworkInterfaceId'],'subnet_id':sid,'availability_zone':az}
    ip=ps.get('podIP')
    try:
        if not isinstance(ip,str): raise ValueError()
        address=IPv4Address(ip)
    except ValueError: return unknown('POD_IPV4_UNCONFIRMED')
    if rows(ps.get('podIPs',[]))!=[{'ip':ip}]: return unknown('POD_IP_LIST_UNSUPPORTED')
    if not _primary_only(inv['Vpcs'][0]) or address not in IPv4Network(inv['Vpcs'][0]['CidrBlock']) or address not in IPv4Network(subnet['CidrBlock']):
        return unknown('POD_SUBNET_OR_CIDR_UNSUPPORTED')
    if any(other is not pod and obj(other.get('status',{})).get('podIP')==ip for other in pods.values()): return unknown('POD_IP_AMBIGUOUS')
    if any(i.get('PrivateIpAddress')==ip for i in instances): return unknown('POD_IP_IS_INSTANCE_PRIMARY')
    matches=[e for e in enis if e.get('PrivateIpAddress')==ip or any(a.get('PrivateIpAddress')==ip for a in e.get('PrivateIpAddresses',[]))]
    if len(matches)!=1: return unknown('POD_ENI_MISSING_OR_AMBIGUOUS')
    eni=matches[0]; eid=eni['NetworkInterfaceId']; att=eni.get('Attachment',{}); ip_rows=[a for a in eni.get('PrivateIpAddresses',[]) if a.get('PrivateIpAddress')==ip]
    if eni.get('PrivateIpAddress')==ip or len(ip_rows)!=1 or ip_rows[0].get('Primary') is not False:
        return unknown('POD_SECONDARY_IP_UNCONFIRMED')
    if eid not in instance_enis or att.get('InstanceId')!=iid or type(att.get('DeviceIndex')) is not int or att['DeviceIndex']<0 or eni.get('SubnetId')!=sid or eni.get('Status')!='in-use' or eni.get('InterfaceType')!='interface' or eni.get('RequesterManaged') is not False:
        return unknown('POD_ENI_NODE_ATTACHMENT_UNCONFIRMED')
    if any(i is not inst and any(e.get('NetworkInterfaceId')==eid for e in i.get('NetworkInterfaces',[])) for i in instances):
        return unknown('POD_ENI_OWNERSHIP_AMBIGUOUS')
    groups=[g.get('GroupId') for g in eni.get('Groups',[])]; known={g['GroupId'] for g in inv['SecurityGroups']}
    if not groups or len(set(groups))!=len(groups) or any(g not in known for g in groups): return unknown('POD_ENI_GROUPS_UNCONFIRMED')
    containers=[c.get('name') for c in rows(spec.get('containers',[]))]
    if not containers or any(not name(c) for c in containers) or len(set(containers))!=len(containers): return unknown('POD_CONTAINERS_UNCONFIRMED')
    result['pod']={'name':pod_name,'namespace':namespace,'uid':pm['uid'],'namespace_uid':ns['metadata']['uid'],'node_name':node_name,'phase':ps['phase'],'containers':containers}
    result['endpoint']={'kind':'EKS_POD','private_ip':ip,'eni_id':eid,'subnet_id':sid,'availability_zone':az,'eni_security_group_ids':groups,'address_mode':'SECONDARY_IPV4','node_instance_id':iid}
    return dict(result,status='POD_ENDPOINT_CANDIDATE',reason='MATCHED_POD_SECONDARY_IP_AND_NODE_ENI')
