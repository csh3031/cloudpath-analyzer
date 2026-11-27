from pathlib import Path
import pytest
from backend.aws.flow_log_evidence import correlate_flow_logs, parse_flow_logs, MAX_BYTES

INV=Path('samples/aws/phase62_demo/aws_static_tcp_example.json')
DEMO=Path('samples/aws/phase63_demo/flow_logs_v2.txt')
LINES=DEMO.read_bytes().splitlines()
ROW=LINES[1]


def run(raw=None, inv=INV, **kw):
    return correlate_flow_logs(inv.read_bytes(), DEMO.read_bytes() if raw is None else raw,
        **(dict(source_ip='10.0.1.10',destination_ip='10.0.2.10',source_port=50000,destination_port=443)|kw))


def change(row, i, val):
    cols=row.split(); cols[i]=str(val).encode(); return b' '.join(cols)


def test_demo_preserves_static_prediction():
    r=run()
    assert r['observation']=='ACCEPT_RECORDS' and r['matched_records']==4
    assert r['cloudpath_predicted']=='UNKNOWN' and r['cloudpath_conditional']=='REACHABLE'
    assert r['coverage_warnings']=={'SKIPDATA':1} and r['live_observation'] is False
    assert len(r['per_interface'])==4
    assert {x['direction'] for x in r['per_interface']}=={'request','response'}


def test_reject_not_causal():
    r=run(change(ROW,12,'REJECT'))
    assert r['observation']=='REJECT_RECORDS' and r['cloudpath_conditional']=='REACHABLE'


def test_mixed_records():
    assert run(ROW+b'\n'+change(ROW,12,'REJECT'))['observation']=='MIXED_RECORDS'


def test_empty_is_not_blocked():
    r=run(b'')
    assert r['observation']=='NO_MATCHING_RECORDS' and r['cloudpath_predicted']=='UNKNOWN'


def test_duplicate_not_packet_count():
    r=run(ROW+b'\n'+ROW)
    assert r['matched_records']==1 and r['duplicate_records']==1


@pytest.mark.parametrize('idx,value,reason',[(2,'eni-abcdef12','OUTSIDE_ENDPOINT_ENI'),(4,'10.0.2.11','TUPLE_OR_PROTOCOL_MISMATCH'),(5,50001,'TUPLE_OR_PROTOCOL_MISMATCH'),(6,80,'TUPLE_OR_PROTOCOL_MISMATCH'),(7,17,'TUPLE_OR_PROTOCOL_MISMATCH'),(11,1795604800,'PARTIAL_TIME_WINDOW')])
def test_excluded_rows(idx,value,reason):
    r=run(change(ROW,idx,value)); assert r['matched_records']==0 and r['ignored_records']=={reason:1}


def test_outside_time():
    row=change(change(ROW,10,1795605000),11,1795605010)
    assert run(row)['ignored_records']=={'OUTSIDE_TIME_WINDOW':1}


def test_nodata_and_skipdata():
    r=run(LINES[-1]+b'\n'+change(LINES[-1],13,'NODATA'))
    assert r['observation']=='NO_MATCHING_RECORDS' and r['coverage_warnings']=={'NODATA':1,'SKIPDATA':1}


def test_port_change_recomputes_static():
    r=run(destination_port=80)
    assert r['cloudpath_predicted']=='BLOCKED' and r['observation']=='NO_MATCHING_RECORDS'


def test_mixed_accounts():
    r=run(ROW+b'\n'+change(ROW,1,'111111111111'))
    assert r['observation']=='NOT_COMPARABLE' and 'LOG_ACCOUNT_UNCONFIRMED_OR_MIXED' in r['reasons']


def test_unknown_account():
    assert run(change(ROW,1,'-'))['observation']=='NOT_COMPARABLE'


def test_unsupported_endpoint():
    r=run(source_ip='10.0.1.99')
    assert r['observation']=='NOT_COMPARABLE' and r['matched_records']==0


@pytest.mark.parametrize('idx,value',[(0,3),(2,'invalid'),(3,'bad-ip'),(5,65536),(8,0),(10,1795604500),(12,'PASS'),(13,'ERROR')])
def test_invalid_record(idx,value):
    with pytest.raises(ValueError,match='line 1'): parse_flow_logs(change(ROW,idx,value))


@pytest.mark.parametrize('raw',[b'bad format',b'\xff',b'x'*(MAX_BYTES+1)])
def test_invalid_input(raw):
    with pytest.raises(ValueError): parse_flow_logs(raw)


def test_ipv6_excluded():
    r=run(change(change(ROW,3,'2001:db8::1'),4,'2001:db8::2'))
    assert r['matched_records']==0
