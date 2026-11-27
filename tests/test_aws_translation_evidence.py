import base64
import copy
import json
from types import SimpleNamespace
from pathlib import Path

import pytest
from backend.aws.snapshot import FORMAT, FORMAT_V2, load_aws_snapshot, sanitize_inventory, OPERATIONS
from backend.aws.egress_evidence import trace_internet_egress
from backend.iac.upload_snapshot import load_snapshot
from scripts.collect_aws_inventory import collect

ROOT = Path(__file__).resolve().parents[1]
SRC, DST = '10.0.1.10', '8.8.8.8'
# Synthetic configuration only; no addresses are contacted.
PUBLIC = '11.0.0.10'
NAT_PUBLIC = '11.0.0.11'
NAT_ENI = 'eni-aaaaaaaa'


def raw(d): return json.dumps(d).encode()


def fixture(nat=False):
    name = 'phase7_demo/public_nat_egress.json' if nat else 'phase62_demo/aws_static_tcp_example.json'
    d = json.loads((ROOT / 'samples/aws' / name).read_text())
    d['format'] = FORMAT_V2
    inv = d['inventory']
    if nat:
        g = inv['NatGateways'][0]
        g['NatGatewayAddresses'] = [dict(PrivateIp='10.0.2.30', PublicIp=NAT_PUBLIC, NetworkInterfaceId=NAT_ENI,
            AllocationId='eipalloc-aaaaaaaa', AssociationId='eipassoc-aaaaaaaa', IsPrimary=True, Status='succeeded')]
        inv['NetworkInterfaces'].append(dict(NetworkInterfaceId=NAT_ENI, VpcId=d['vpc_id'], SubnetId=g['SubnetId'],
            PrivateIpAddress='10.0.2.30', PrivateIpAddresses=[{'PrivateIpAddress':'10.0.2.30','Primary':True}],
            Groups=[], Status='in-use', InterfaceType='nat_gateway', RequesterManaged=True))
    else:
        eni = inv['NetworkInterfaces'][0]
        eni['Association'] = {'PublicIp':PUBLIC}
        eni['PrivateIpAddresses'][0].update(Primary=True, Association={'PublicIp':PUBLIC})
        inv['Reservations'][0]['Instances'][0]['PublicIpAddress'] = PUBLIC
    return d


def trace(d):
    r=trace_internet_egress(raw(d),SRC,DST)
    assert r['internet_reachability']=='UNKNOWN'
    assert r['session_status']==r['policy_status']==r['response_status']=='NOT_EVALUATED'
    assert r['live_observation'] is False
    return r


def test_direct_mapping():
    r=trace(fixture()); t=r['translation']
    assert r['status']=='EGRESS_ROUTE_CANDIDATE'
    assert t['state']=='ADDRESS_MAPPING_CANDIDATE'
    assert (t['translated_private_ip'],t['translated_public_ip'])==(SRC,PUBLIC)
    assert t['translated_source_port'] is None and t['runtime_translation_observed'] is False


def test_nat_mapping():
    r=trace(fixture(True)); t=r['translation']
    assert t['state']=='ADDRESS_MAPPING_CANDIDATE'
    assert (t['translated_private_ip'],t['translated_public_ip'])==('10.0.2.30',NAT_PUBLIC)
    assert t['translated_source_port'] is None


@pytest.mark.parametrize('case', ['missing','wrong_instance','wrong_top','not_primary','private_public','duplicate','carrier','nat_duplicate'])
def test_direct_unknown(case):
    d=fixture(); inv=d['inventory']; e=inv['NetworkInterfaces'][0]; a=e['PrivateIpAddresses'][0]
    if case=='missing': del a['Association']
    elif case=='wrong_instance': inv['Reservations'][0]['Instances'][0]['PublicIpAddress']='11.0.0.12'
    elif case=='wrong_top': e['Association']['PublicIp']='11.0.0.12'
    elif case=='not_primary': a['Primary']=False
    elif case=='private_public':
        e['Association']['PublicIp']=a['Association']['PublicIp']=inv['Reservations'][0]['Instances'][0]['PublicIpAddress']='10.1.1.1'
    elif case=='duplicate': inv['NetworkInterfaces'][1]['Association']={'PublicIp':PUBLIC}
    elif case=='carrier': a['Association']['CarrierIp']='11.0.0.12'
    elif case=='nat_duplicate':
        inv['NatGateways']=[dict(NatGatewayId='nat-aaaaaaaa',VpcId=d['vpc_id'],SubnetId=inv['Subnets'][1]['SubnetId'],State='available',ConnectivityType='public',NatGatewayAddresses=[dict(PublicIp=PUBLIC)])]
    t=trace(d)['translation']; assert t['state']=='UNKNOWN' and t['translated_public_ip'] is None


@pytest.mark.parametrize('case', ['multiple','missing','pending','no_primary','missing_eni','wrong_subnet','wrong_type','wrong_ip','wrong_public','no_alloc','duplicate','reserved','wrong_state'])
def test_nat_unknown(case):
    d=fixture(True); inv=d['inventory']; g=inv['NatGateways'][0]; a=g['NatGatewayAddresses'][0]; e=inv['NetworkInterfaces'][-1]
    if case=='multiple': g['NatGatewayAddresses'].append(copy.deepcopy(a))
    elif case=='missing': del g['NatGatewayAddresses']
    elif case=='pending': a['Status']='associating'
    elif case=='no_primary': a.pop('IsPrimary')
    elif case=='missing_eni': inv['NetworkInterfaces'].pop()
    elif case=='wrong_subnet': e['SubnetId']=inv['Subnets'][0]['SubnetId']
    elif case=='wrong_type': e['InterfaceType']='interface'
    elif case=='wrong_ip': a['PrivateIp']='10.0.2.31'
    elif case=='wrong_public': e['Association']={'PublicIp':'11.0.0.12'}
    elif case=='no_alloc': del a['AllocationId']
    elif case=='duplicate': inv['NetworkInterfaces'][1]['Association']={'PublicIp':NAT_PUBLIC}
    elif case=='reserved':
        a['PrivateIp']=e['PrivateIpAddress']=e['PrivateIpAddresses'][0]['PrivateIpAddress']='10.0.2.2'
    elif case=='wrong_state': e['Status']='available'
    t=trace(d)['translation']; assert t['state']=='UNKNOWN' and t['translated_public_ip'] is None


def test_v1_ignores_address_evidence():
    d=fixture(True); d['format']=FORMAT
    assert trace(d)['translation']['state']=='NOT_EVALUATED'
    assert load_aws_snapshot(raw(d))[1].startswith('sha256-aws-v1:')


def test_blocked_no_mapping():
    d=fixture(); d['inventory']['RouteTables'][0]['Routes'][1]['State']='blackhole'
    r=trace(d); assert r['status']=='BLOCKED' and r['translation'] is None


def test_v2_upload_and_distinct_identity():
    d=fixture(); r,ident,m=load_snapshot([{'name':'v2.json','content_base64':base64.b64encode(raw(d)).decode()}])
    assert ident.startswith('sha256-aws-v2:') and m['analysis_restricted']
    assert len(r)==len(load_aws_snapshot(raw(dict(d,format=FORMAT)))[0])


def test_collect_v2_opt_in_and_redaction():
    d=fixture(True); inv=d['inventory']; inv['NetworkInterfaces'][-1]['Association']={'PublicIp':NAT_PUBLIC,'IpOwnerId':'SECRET_OWNER','PublicDnsName':'SECRET_DNS'}
    inv['NatGateways'][0]['NatGatewayAddresses'][0]['FailureMessage']='SECRET_MESSAGE'
    calls=[]
    def run(cmd,**kw):
        calls.append(cmd); k,_=OPERATIONS[cmd[2]]; return SimpleNamespace(stdout=raw({k:inv[k]}))
    v2=collect(d['region'],d['vpc_id'],run=run,address_evidence=True)
    assert len(calls)==9 and b'SECRET' not in v2
    assert json.loads(v2)['format']==FORMAT_V2
    assert trace(json.loads(v2))['translation']['state']=='ADDRESS_MAPPING_CANDIDATE'
    v1=collect(d['region'],d['vpc_id'],run=run)
    assert json.loads(v1)['format']==FORMAT and b'NatGatewayAddresses' not in v1 and b'PublicIp' not in v1
