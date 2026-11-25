from dataclasses import replace
import pytest
from backend.models.infrastructure import InfrastructureResource
from backend.models.diagnostics import CommunicationScenario
from backend.analyzer.session_analyzer import analyze_session


def r(id, **a): return InfrastructureResource(id,'aws','network',id.split('.')[0][4:],id.split('.')[1],a)
def ref(id): return '${'+id+'.id}'
def rule(port, action='allow', n=100):
    return dict(rule_no=n, action=action, protocol='tcp', cidr_block='10.0.0.0/16', from_port=port,to_port=port)
def fixture():
    v=ref('aws_vpc.main'); a=ref('aws_subnet.a'); b=ref('aws_subnet.b')
    return [r('aws_vpc.main',cidr_block='10.0.0.0/16'),r('aws_subnet.a',vpc_id=v,cidr_block='10.0.1.0/24'),r('aws_subnet.b',vpc_id=v,cidr_block='10.0.2.0/24'),
        r('aws_instance.a',subnet_id=a,private_ip='10.0.1.10',vpc_security_group_ids=[ref('aws_security_group.a')]),
        r('aws_instance.b',subnet_id=b,private_ip='10.0.2.20',vpc_security_group_ids=[ref('aws_security_group.b')]),
        r('aws_security_group.a',vpc_id=v,egress=[dict(protocol='-1',from_port=0,to_port=0,cidr_blocks=['10.0.0.0/16'])]),
        r('aws_security_group.b',vpc_id=v,ingress=[dict(protocol='tcp',from_port=0,to_port=65535,cidr_blocks=['10.0.0.0/16'])]),
        r('aws_network_acl.a',vpc_id=v,subnet_ids=[a],egress=[rule(443),rule(5432,n=110)],ingress=[rule(49152)]),
        r('aws_network_acl.b',vpc_id=v,subnet_ids=[b],ingress=[rule(443)],egress=[rule(49152)])]
def scenario(**kw):
    return replace(CommunicationScenario('aws_subnet.a','10.0.2.20',source_resource='aws_instance.a',source_ip='10.0.1.10',destination_resource='aws_instance.b',destination_port=443,source_port=49152,assume_direct_private=True,complete_config=True,complete_nacl_config=True),**kw)
def run(rs=None,tracked=True,complete=True,**kw):
    return analyze_session(fixture() if rs is None else rs, scenario(**kw),complete_routing_config=complete,assume_tracked_response=tracked)
def req(o): return o['session_trace']['request']
def ret(o): return o['session_trace']['response']
def blocker(o): return next((s for s in req(o)['steps']+ret(o)['steps'] if s['id']==o['first_blocker_step']),None)
def test_reachable():
    o=run();assert o['predicted_connectivity']=='REACHABLE' and req(o)['status']==ret(o)['status']=='PASS' and o['first_blocker'] is None
    assert ret(o)['tuple']==dict(source_ip='10.0.2.20',destination_ip='10.0.1.10',source_port=443,destination_port=49152,protocol='tcp')
    assert ret(o)['forwarding']['hops'][0]['resource']=='aws_instance.b'
def test_request_nacl_block():
    o=run(destination_port=5432);assert o['predicted_connectivity']=='BLOCKED' and blocker(o)['stage']=='NACL_INGRESS';assert ret(o)['conditional'] and ret(o)['status']=='UNKNOWN' and ret(o)['hypothetical_status']=='PASS'
def test_return_egress_block():
    rs=fixture();rs[-1].attributes['egress']=[];o=run(rs);assert req(o)['status']=='PASS' and ret(o)['status']=='BLOCKED' and blocker(o)['stage']=='NACL_EGRESS' and blocker(o)['id'].startswith('RET')
def test_return_ingress_block():
    rs=fixture();rs[-2].attributes['ingress']=[];o=run(rs);assert blocker(o)['stage']=='NACL_INGRESS' and blocker(o)['id'].startswith('RET')
def test_multiple_blocks():
    rs=fixture();rs[5].attributes['egress']=[];rs[-1].attributes['ingress']=[];rs[-1].attributes['egress']=[];o=run(rs);assert blocker(o)['stage']=='SG_EGRESS';assert len(o['conditional_blockers'])>=2
    assert all(i in {f['id'] for f in o['findings']} for i in [o['first_blocker'],*o['conditional_blockers']])
def test_no_source_port():
    o=run(source_port=None);assert req(o)['status']=='PASS' and ret(o)['status']=='UNKNOWN' and o['predicted_connectivity']=='UNKNOWN'
def test_no_source_port_request_block(): assert run(source_port=None,destination_port=5432)['predicted_connectivity']=='BLOCKED'
def test_other_source_port():
    o=run(source_port=49153);assert blocker(o)['stage']=='NACL_EGRESS' and blocker(o)['id'].startswith('RET')
def test_unasserted_tracking(): assert run(tracked=False)['predicted_connectivity']=='UNKNOWN'
def test_reverse_sg_explicit():
    rs=fixture();rs[5].attributes['ingress']=rs[5].attributes['egress'];rs[6].attributes['egress']=rs[6].attributes['ingress'];assert run(rs,tracked=False)['predicted_connectivity']=='REACHABLE'
@pytest.mark.parametrize('kw',[dict(complete=False),dict(complete_config=False),dict(assume_direct_private=False),dict(destination_ip='10.0.2.99'),dict(request_type='aws_api'),dict(complete_nacl_config=False)])
def test_unknown(kw):
    o=run(**kw);assert o['predicted_connectivity']=='UNKNOWN' and o['first_blocker'] is None

def test_same_subnet():
    rs=fixture();rs[4].attributes.update(subnet_id=ref('aws_subnet.a'),private_ip='10.0.1.20');o=run(rs,destination_ip='10.0.1.20');assert o['predicted_connectivity']=='REACHABLE'
    assert all(s['status']=='PASS' for s in req(o)['steps']+ret(o)['steps'])
def test_early_unknown_later_block():
    rs=fixture();rs[5].attributes['egress']=[dict(protocol='tcp',from_port=443,to_port=443,cidr_blocks=['${var.cidr}'])];rs[-1].attributes['ingress']=[];o=run(rs);assert o['predicted_connectivity']=='UNKNOWN' and o['first_blocker'] is None and o['conditional_blockers']
def test_findings_unique_and_coverage():
    o=run();ids=[f['id'] for f in o['findings']];assert len(ids)==len(set(ids));assert all(s['finding_id'] in ids for s in req(o)['steps']+ret(o)['steps']);assert sum(o['coverage'][k] for k in ('evaluated','unknown','not_evaluated'))==len(o['coverage']['checks'])
def test_hcl_demo():
    from backend.iac.terraform_parser import parse_terraform
    rs=parse_terraform('samples/terraform/session_demo.tf');assert run(rs)['predicted_connectivity']=='REACHABLE';assert run(rs,destination_port=5432)['predicted_connectivity']=='BLOCKED';assert run(rs,source_port=49153)['predicted_connectivity']=='BLOCKED'
