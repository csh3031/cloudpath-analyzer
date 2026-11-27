import json
from pathlib import Path

import pytest
from backend.aws.egress_session_evidence import analyze_internet_egress_session
from backend.aws.egress_evidence import trace_internet_egress
from test_aws_translation_evidence import fixture

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / 'samples/aws/phase7_demo'


def sample(name='public_nat_egress_policy_candidate.json'):
    return json.loads((SAMPLES/name).read_text())


def run(doc, sport=50000, dport=443, dst='8.8.8.8'):
    raw = json.dumps(doc).encode()
    r = analyze_internet_egress_session(raw, '10.0.1.10', dst, sport, dport)
    assert r['route'] == trace_internet_egress(raw, '10.0.1.10', dst)
    assert r['internet_reachability']=='UNKNOWN' and r['live_observation'] is False
    return r


def stage(r, key, name):
    return next(x for x in r[key] if x['stage']==name)


def test_nat_candidate():
    r=run(sample())
    assert r['request_status']=='CONDITIONAL_CANDIDATE'
    assert r['first_request_stop'] is None
    assert r['response_status']==r['session_status']=='UNKNOWN'
    assert [x['stage'] for x in r['request']]==['SOURCE_SG_EGRESS','SOURCE_NACL_EGRESS','SOURCE_ROUTE','NAT_SUBNET_INGRESS','NAT_ROUTE','NAT_SUBNET_EGRESS','ADDRESS_MAPPING']
    assert stage(r,'response','NAT_SUBNET_INGRESS_PORT_RANGE')['status']=='ALLOW_CANDIDATE'
    assert stage(r,'response','NAT_RETURN_ROUTE')['status']=='ALLOW_CANDIDATE'
    assert stage(r,'response','NAT_REVERSE_MAPPING')['status']=='CONDITIONAL'
    assert all(x['evaluation_mode']!='PREDICTED_PATH' for x in r['response'])


def test_original_sample_blocks():
    r=run(sample('public_nat_egress_v2.json'))
    assert r['first_request_stop']=='SOURCE_NACL_EGRESS' and r['session_status']=='BLOCKED'
    assert stage(r,'request','NAT_SUBNET_INGRESS')['evaluation_mode']=='INDEPENDENT_CHECK'


def test_direct_igw_candidate():
    d=fixture()
    for a in d['inventory']['NetworkAcls']:
        for rule in a['Entries']:
            if rule['RuleAction']=='allow': rule['CidrBlock']='0.0.0.0/0'
    r=run(d)
    assert r['request_status']=='CONDITIONAL_CANDIDATE'
    assert [x['stage'] for x in r['response']]==['IGW_RETURN_SCOPE','SOURCE_NACL_INGRESS','SOURCE_SG_INGRESS']


@pytest.mark.parametrize('sport,dport',[(0,443),(65536,443),(True,443),(50000,0),(50000,'443')])
def test_bad_ports(sport,dport):
    with pytest.raises(ValueError): run(sample(),sport,dport)


@pytest.mark.parametrize('dst',['invalid','10.0.2.10','224.0.0.1','2001:db8::1'])
def test_unsupported_scope(dst):
    r=run(sample(),dst=dst)
    assert r['session_status']=='UNKNOWN' and not r['response']


def test_missing_v2_mapping():
    d=sample(); d['format']='cloudpath-aws-inventory-v1'
    r=run(d)
    assert r['first_request_stop']=='ADDRESS_MAPPING' and r['session_status']=='UNKNOWN'


def test_sg_block():
    d=sample(); d['inventory']['SecurityGroups'][0]['IpPermissionsEgress']=[]
    r=run(d)
    assert r['first_request_stop']=='SOURCE_SG_EGRESS'
    assert r['session_status']=='BLOCKED'
    assert all(x['evaluation_mode']=='INDEPENDENT_CHECK' for x in r['request'][1:])


def test_source_route_blackhole():
    d=sample(); d['inventory']['RouteTables'][1]['Routes'][1]['State']='blackhole'
    r=run(d)
    assert r['first_request_stop']=='SOURCE_ROUTE' and r['session_status']=='BLOCKED'
    assert not r['response']


def test_nat_route_blackhole():
    d=sample(); d['inventory']['RouteTables'][0]['Routes'][1]['State']='blackhole'
    r=run(d)
    assert r['first_request_stop']=='NAT_ROUTE'
    assert stage(r,'request','NAT_SUBNET_EGRESS')['evaluation_mode']=='INDEPENDENT_CHECK'


def test_nat_route_unknown():
    d=sample(); d['inventory']['InternetGateways']=[]
    r=run(d)
    assert r['first_request_stop']=='NAT_ROUTE' and r['session_status']=='UNKNOWN'


def test_nat_missing():
    d=sample(); d['inventory']['NatGateways']=[]
    r=run(d)
    assert r['first_request_stop']=='SOURCE_ROUTE' and r['session_status']=='UNKNOWN'


@pytest.mark.parametrize('lo,hi,action,expected',[(1024,65535,'allow','ALLOW_CANDIDATE'),(1024,65535,'deny','BLOCKED'),(1024,2000,'deny','UNKNOWN'),(1024,2000,'allow','UNKNOWN')])
def test_nat_port_range(lo,hi,action,expected):
    d=sample(); acl=d['inventory']['NetworkAcls'][0]
    # This ACL applies to both subnets. Preserve client-side ingress via CIDR rule.
    acl['Entries']=[r for r in acl['Entries'] if r['Egress'] or r['RuleAction']=='deny']
    acl['Entries'].append(dict(RuleNumber=100,Protocol='6',RuleAction='allow',Egress=False,CidrBlock='10.0.0.0/16',PortRange={'From':1,'To':65535}))
    acl['Entries'].append(dict(RuleNumber=110,Protocol='6',RuleAction=action,Egress=False,CidrBlock='8.8.8.8/32',PortRange={'From':lo,'To':hi}))
    if action=='deny' and hi<65535:
        acl['Entries'].append(dict(RuleNumber=120,Protocol='6',RuleAction='allow',Egress=False,CidrBlock='8.8.8.8/32',PortRange={'From':1,'To':65535}))
    r=run(d); step=stage(r,'response','NAT_SUBNET_INGRESS_PORT_RANGE')
    assert step['status']==expected and step['translated_port'] is None
    assert r['session_status']=='UNKNOWN'


def test_reverse_local_blackhole():
    d=sample(); d['inventory']['RouteTables'][0]['Routes'][0]['State']='blackhole'
    r=run(d)
    assert stage(r,'response','NAT_RETURN_ROUTE')['status']=='BLOCKED'
    assert r['session_status']=='UNKNOWN'


def test_source_ingress_port():
    d=sample(); acl=d['inventory']['NetworkAcls'][0]
    acl['Entries'].append(dict(RuleNumber=90,Protocol='6',RuleAction='deny',Egress=False,CidrBlock='8.8.8.8/32',PortRange={'From':50000,'To':50000}))
    assert stage(run(d),'response','SOURCE_NACL_INGRESS')['status']=='BLOCKED'
    assert stage(run(d,sport=50001),'response','SOURCE_NACL_INGRESS')['status']=='ALLOW_CANDIDATE'
