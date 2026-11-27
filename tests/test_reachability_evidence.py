import json
from pathlib import Path
import pytest
from backend.aws.reachability_evidence import compare_reachability

DEMO = Path('samples/aws/phase63_demo')
INV = Path('samples/aws/phase62_demo/aws_static_tcp_example.json')


def compare(p=None, a=None, inv=INV, **scenario):
    p = json.loads((DEMO/'reachability_paths.json').read_text()) if p is None else p
    a = json.loads((DEMO/'reachability_analyses.json').read_text()) if a is None else a
    return compare_reachability(inv.read_bytes(), json.dumps(p).encode(), json.dumps(a).encode(),
                                **(dict(source_ip='10.0.1.10', destination_ip='10.0.2.10', source_port=50000, destination_port=443)|scenario))


def test_matching_candidate():
    r=compare()
    assert r['comparison']=='CONSISTENT_CANDIDATE' and r['cloudpath_predicted']=='UNKNOWN'
    assert r['cloudpath_conditional']=='REACHABLE' and r['live_observation'] is False
    assert r['time_gap_seconds']==60 and not r['reasons']


def test_discrepancy_candidate():
    a=json.loads((DEMO/'reachability_analyses.json').read_text())
    a['NetworkInsightsAnalyses'][0]['NetworkPathFound']=False
    assert compare(a=a)['comparison']=='DISCREPANCY_CANDIDATE'


@pytest.mark.parametrize('field,value,reason',[
    ('Source','i-abcdef12','SOURCE_RESOURCE_MISMATCH'),
    ('Destination','eni-abcdef12','DESTINATION_RESOURCE_MISMATCH'),
    ('Protocol','udp','PROTOCOL_MISMATCH'),
    ('DestinationIp','10.0.2.11','DESTINATIONIP_NOT_EXACT'),
    ('DestinationPort',80,'DESTINATION_PORT_NOT_EXACT'),
    ('FilterAtSource',{},'SOURCE_PORT_NOT_EXACT'),
    ('FilterAtDestination',{'SourceAddress':'10.0.1.10'},'UNSUPPORTED_PATH_FILTER'),
    ('NetworkInsightsPathArn','arn:aws:ec2:us-east-1:000000000000:network-insights-path/nip-12345678','ARN_SCOPE_UNCONFIRMED_OR_MISMATCH'),
])
def test_path_scope(field,value,reason):
    p=json.loads((DEMO/'reachability_paths.json').read_text())
    p['NetworkInsightsPaths'][0][field]=value
    r=compare(p=p)
    assert r['comparison']=='NOT_COMPARABLE' and reason in r['reasons']


@pytest.mark.parametrize('field,value,reason',[
    ('Status','running','ANALYSIS_NOT_SUCCEEDED'),
    ('Status','failed','ANALYSIS_NOT_SUCCEEDED'),
    ('StartDate','2026-11-25T12:00:00Z','COLLECTION_TIME_GAP'),
    ('FilterInArns',['arn:example'],'ANALYSIS_SCOPE_OR_WARNING_UNSUPPORTED'),
    ('WarningMessage','Incomplete analysis','ANALYSIS_SCOPE_OR_WARNING_UNSUPPORTED'),
])
def test_analysis_scope(field,value,reason):
    a=json.loads((DEMO/'reachability_analyses.json').read_text())
    a['NetworkInsightsAnalyses'][0][field]=value
    r=compare(a=a)
    assert r['comparison']=='NOT_COMPARABLE' and reason in r['reasons']
    if field=='Status': assert r['aws_network_path_found'] is None


def test_broad_source_port_range():
    p=json.loads((DEMO/'reachability_paths.json').read_text())
    p['NetworkInsightsPaths'][0]['FilterAtSource']['SourcePortRange']['FromPort']=1
    assert compare(p=p)['comparison']=='NOT_COMPARABLE'


@pytest.mark.parametrize('field,value', [('NetworkInsightsPathId','nip-87654321'),('NetworkPathFound','true'),('StartDate','2026-11-25T11:00:00')])
def test_malformed_or_unlinked(field,value):
    a=json.loads((DEMO/'reachability_analyses.json').read_text())
    a['NetworkInsightsAnalyses'][0][field]=value
    with pytest.raises(ValueError): compare(a=a)


def test_multiple_paths_rejected():
    p=json.loads((DEMO/'reachability_paths.json').read_text());p['NetworkInsightsPaths']*=2
    with pytest.raises(ValueError): compare(p=p)


def test_port_change_not_reusing_result():
    r=compare(destination_port=80)
    assert r['comparison']=='NOT_COMPARABLE' and r['cloudpath_predicted']=='BLOCKED'


def test_unresolved_local_scope():
    r=compare(inv=Path('samples/aws/phase62_demo/unknown_then_blocked.json'))
    assert r['comparison']=='NOT_COMPARABLE' and 'CLOUDPATH_SCOPE_UNRESOLVED' in r['reasons']
