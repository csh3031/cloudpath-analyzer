import pytest
from backend.models.infrastructure import InfrastructureResource
from backend.models.diagnostics import CommunicationScenario
from backend.analyzer.network_acl_analyzer import evaluate_network_acls, NETWORK_ACL_CHECK
from backend.analyzer.security_group_analyzer import SECURITY_GROUP_CHECK
from backend.analyzer.communication_analyzer import analyze_communication


def r(id,**a): return InfrastructureResource(id,'aws','network',id.split('.')[0][4:],id.split('.')[-1],a)
def ref(id,attr='id'): return '${'+id+'.'+attr+'}'
def rule(n=100,action='allow',cidr='10.0.0.0/16',protocol='tcp',lo=443,hi=443):
    return dict(rule_no=n,action=action,cidr_block=cidr,protocol=protocol,from_port=lo,to_port=hi)
def fixture():
    v=ref('aws_vpc.main'); a=ref('aws_subnet.a'); b=ref('aws_subnet.b')
    return [r('aws_vpc.main',cidr_block='10.0.0.0/16'),r('aws_subnet.a',vpc_id=v,cidr_block='10.0.1.0/24'),r('aws_subnet.b',vpc_id=v,cidr_block='10.0.2.0/24'),r('aws_instance.a',subnet_id=a,private_ip='10.0.1.10'),r('aws_instance.b',subnet_id=b,private_ip='10.0.2.20'),r('aws_network_acl.a',vpc_id=v,subnet_ids=[a],egress=[rule()]),r('aws_network_acl.b',vpc_id=v,subnet_ids=[b],ingress=[rule()])]
def scenario(**kw):
    return CommunicationScenario(**(dict(source_subnet='aws_subnet.a',source_resource='aws_instance.a',source_ip='10.0.1.10',destination_resource='aws_instance.b',destination_ip='10.0.2.20',destination_port=443,assume_direct_private=True,complete_nacl_config=True)|kw))
def statuses(rs,**kw): return [o.status for o in evaluate_network_acls(rs,scenario(**kw))]
def test_allow(): assert statuses(fixture())==['PASS','PASS']
def test_priority():
    rs=fixture();rs[-1].attributes['ingress']=[rule(200),rule(100,'deny')]; assert statuses(rs)==['PASS','BLOCKED']
def test_later_deny():
    rs=fixture();rs[-1].attributes['ingress']=[rule(200,'deny'),rule(100)]; assert statuses(rs)==['PASS','PASS']
def test_nonmatching_first():
    rs=fixture();rs[-1].attributes['ingress']=[rule(100,'deny','192.0.2.0/24'),rule(200)]; assert statuses(rs)==['PASS','PASS']
@pytest.mark.parametrize('port',[0,80,442,444,65535])
def test_implicit_deny(port): assert statuses(fixture(),destination_port=port)==['BLOCKED','BLOCKED']
def test_range():
    rs=fixture();rs[-1].attributes['ingress']=[rule(lo=400,hi=500)];assert statuses(rs)==['PASS','PASS']
def test_udp(): assert statuses(fixture(),protocol='udp')==['BLOCKED','BLOCKED']
def test_all_protocol():
    rs=fixture();rs[-1].attributes['ingress']=[rule(protocol=-1,lo=0,hi=0)];assert statuses(rs,destination_port=80)==['BLOCKED','PASS']
def test_unresolved_earlier():
    rs=fixture();rs[-1].attributes['ingress']=[rule(100,cidr='${var.cidr}'),rule(200)];assert statuses(rs)==['PASS','UNKNOWN']
def test_unresolved_later():
    rs=fixture();rs[-1].attributes['ingress']=[rule(100),rule(200,cidr='${var.cidr}')];assert statuses(rs)==['PASS','PASS']
def test_unresolved_number():
    rs=fixture();rs[-1].attributes['ingress']=[rule('${var.number}'),rule(200)];assert statuses(rs)==['PASS','UNKNOWN']
def test_duplicate_number():
    rs=fixture();rs[-1].attributes['ingress']=[rule(),rule(action='deny')];assert statuses(rs)==['PASS','UNKNOWN']
def test_partial_config(): assert statuses(fixture(),complete_nacl_config=False)==['UNKNOWN','UNKNOWN']
def test_direct_required(): assert statuses(fixture(),assume_direct_private=False)==['UNKNOWN','UNKNOWN']
def test_same_subnet():
    rs=fixture();rs[4].attributes.update(subnet_id=ref('aws_subnet.a'),private_ip='10.0.1.20');o=evaluate_network_acls(rs,scenario(destination_ip='10.0.1.20',complete_nacl_config=False));assert all(x.status=='PASS' and x.evidence[0]['applicable'] is False for x in o)
def test_bad_ip(): assert statuses(fixture(),destination_ip='10.0.3.20')==['UNKNOWN','UNKNOWN']
def test_address_conflict(): assert statuses(fixture(),destination_ip='10.0.2.99')==['UNKNOWN','UNKNOWN']
def test_missing_default(): assert statuses(fixture()[:-1])==['PASS','UNKNOWN']
def test_assumed_default(): assert statuses(fixture()[:-1],assume_unmodified_default_nacl=True)==['PASS','PASS']
def test_managed_default():
    rs=fixture()[:-1];rs.append(r('aws_default_network_acl.main',default_network_acl_id=ref('aws_vpc.main','default_network_acl_id'),ingress=[rule(action='deny')]));assert statuses(rs,assume_unmodified_default_nacl=True)==['PASS','BLOCKED']
def test_standalone():
    rs=fixture();a=rs[-1].attributes;a.pop('subnet_ids');a.pop('ingress');rs.extend([r('aws_network_acl_association.b',subnet_id=ref('aws_subnet.b'),network_acl_id=ref('aws_network_acl.b')),r('aws_network_acl_rule.b',network_acl_id=ref('aws_network_acl.b'),rule_number=100,rule_action='allow',protocol='6',cidr_block='10.0.1.0/24',from_port=443,to_port=443)]);assert statuses(rs)==['PASS','PASS']
def test_conflicting_association():
    rs=fixture();rs.append(r('aws_network_acl_association.b',subnet_id=ref('aws_subnet.b'),network_acl_id=ref('aws_network_acl.a')));assert statuses(rs)==['PASS','UNKNOWN']
def test_mixed_rules():
    rs=fixture();rs.append(r('aws_network_acl_rule.b',network_acl_id=ref('aws_network_acl.b'),rule_number=200,rule_action='allow'));assert statuses(rs)==['PASS','UNKNOWN']
def test_ipv6():
    rs=fixture();rs[1].attributes['ipv6_cidr_block']='2001:db8:1::/64';rs[2].attributes['ipv6_cidr_block']='2001:db8:2::/64'
    for a in (rs[-2].attributes['egress'][0],rs[-1].attributes['ingress'][0]): a.pop('cidr_block');a['ipv6_cidr_block']='2001:db8::/32'
    assert statuses(rs,source_ip='2001:db8:1::10',destination_ip='2001:db8:2::20')==['PASS','PASS']
def test_evidence():
    rs=fixture();rs[-1].attributes['ingress']=[rule(200),rule(100,'deny')];o=evaluate_network_acls(rs,scenario())[1];assert o.evidence[-1]['rule_number']==100 and o.evidence[-1]['action']=='deny'
def test_orchestrator():
    rs=fixture();rs[-1].attributes['ingress']=[rule(action='deny')];result=analyze_communication(rs,scenario(),[SECURITY_GROUP_CHECK,NETWORK_ACL_CHECK]);assert [f['status'] for f in result['findings'] if f['check']=='network_acl']==['PASS','BLOCKED'];assert result['forwarding']['hops']==[] and result['coverage']['checks']['return_path']['state']=='NOT_EVALUATED'
def test_hcl_demo():
    from backend.iac.terraform_parser import parse_terraform
    rs=parse_terraform('samples/terraform/network_acl_demo.tf');assert statuses(rs)==['PASS','PASS'];assert statuses(rs,destination_port=5432)==['PASS','BLOCKED']
