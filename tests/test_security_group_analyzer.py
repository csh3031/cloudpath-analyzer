import pytest
from backend.models.infrastructure import InfrastructureResource
from backend.models.diagnostics import CommunicationScenario
from backend.analyzer.security_group_analyzer import evaluate_security_groups, SECURITY_GROUP_CHECK
from backend.analyzer.communication_analyzer import analyze_communication


def r(id, **attrs):
    return InfrastructureResource(id, 'aws', 'security', id.split('.')[0][4:], id.split('.')[-1], attrs)


def ref(id): return '${' + id + '.id}'


def rule(cidr='10.0.0.0/16', protocol='tcp', low=443, high=443):
    return dict(protocol=protocol, from_port=low, to_port=high, cidr_blocks=[cidr])


def fixture():
    vpc = ref('aws_vpc.main')
    subnet = ref('aws_subnet.main')
    return [r('aws_vpc.main', cidr_block='10.0.0.0/16'), r('aws_subnet.main', vpc_id=vpc,cidr_block='10.0.1.0/24'),
            r('aws_instance.a', subnet_id=subnet, private_ip='10.0.1.10',vpc_security_group_ids=[ref('aws_security_group.a')]),
            r('aws_instance.b', subnet_id=subnet, private_ip='10.0.1.20',vpc_security_group_ids=[ref('aws_security_group.b')]),
            r('aws_security_group.a',vpc_id=vpc,egress=[rule()]), r('aws_security_group.b',vpc_id=vpc,ingress=[rule()])]


def scenario(**kw):
    args=dict(source_subnet='aws_subnet.main',source_resource='aws_instance.a',source_ip='10.0.1.10',destination_resource='aws_instance.b',destination_ip='10.0.1.20',destination_port=443,complete_config=True)
    return CommunicationScenario(**(args | kw))


def statuses(resources, **kw): return [x.status for x in evaluate_security_groups(resources,scenario(**kw))]


def test_inline(): assert statuses(fixture()) == ['PASS','PASS']
@pytest.mark.parametrize('p',[1,442,444,65535])
def test_ports(p): assert statuses(fixture(),destination_port=p)==['BLOCKED','BLOCKED']
def test_wrong_proto(): assert statuses(fixture(),protocol='udp')==['BLOCKED','BLOCKED']
def test_all_proto():
    rs=fixture(); rs[-1].attributes['ingress']=[rule(protocol='-1',low=0,high=0)]
    assert statuses(rs,destination_port=999)==['BLOCKED','PASS']
def test_partial_config(): assert statuses(fixture(),destination_port=80,complete_config=False)==['UNKNOWN','UNKNOWN']
def test_multi_sg_union():
    rs=fixture(); rs[-1].attributes['ingress']=[]; rs[3].attributes['vpc_security_group_ids'].append(ref('aws_security_group.c')); rs.append(r('aws_security_group.c',ingress=[rule()]))
    assert statuses(rs)==['PASS','PASS']
def test_unknown_cidr():
    rs=fixture(); rs[-1].attributes['ingress']=[rule('${var.cidr}')]; assert statuses(rs)==['PASS','UNKNOWN']
def test_missing_attachment():
    rs=fixture(); rs[3].attributes.pop('vpc_security_group_ids'); assert statuses(rs)==['PASS','UNKNOWN']
def test_unknown_source_ip(): assert statuses(fixture(),source_ip=None)==['PASS','UNKNOWN']
def test_invalid_ip(): assert statuses(fixture(),source_ip='bad')==['UNKNOWN','UNKNOWN']
def test_address_conflict(): assert statuses(fixture(),source_ip='10.0.1.99')==['UNKNOWN','UNKNOWN']
def test_modern_rule():
    rs=fixture(); rs[-1].attributes.pop('ingress'); rs.append(r('aws_vpc_security_group_ingress_rule.b',security_group_id=ref('aws_security_group.b'),ip_protocol='tcp',from_port=443,to_port=443,cidr_ipv4='10.0.1.0/24'))
    assert statuses(rs)==['PASS','PASS']
def test_legacy_rule():
    rs=fixture(); rs[-1].attributes.pop('ingress'); rs.append(r('aws_security_group_rule.b',security_group_id=ref('aws_security_group.b'),type='ingress',**rule()))
    assert statuses(rs)==['PASS','PASS']
def test_mixed_conflict():
    rs=fixture(); rs.append(r('aws_vpc_security_group_ingress_rule.b',security_group_id=ref('aws_security_group.b'),ip_protocol='tcp',from_port=443,to_port=443,cidr_ipv4='10.0.1.0/24'))
    assert statuses(rs)==['PASS','UNKNOWN']
def test_sg_ref():
    rs=fixture(); rs[-1].attributes['ingress']=[dict(protocol='tcp',from_port=443,to_port=443,security_groups=[ref('aws_security_group.a')])]
    assert statuses(rs)==['PASS','UNKNOWN']; assert statuses(rs,assume_direct_private=True)==['PASS','PASS']
def test_sg_ref_not_transitive():
    rs=fixture(); rs[-1].attributes['ingress']=[dict(protocol='tcp',from_port=443,to_port=443,security_groups=[ref('aws_security_group.c')])]
    assert statuses(rs,assume_direct_private=True)==['PASS','UNKNOWN']
    rs.append(r('aws_security_group.c',vpc_id=ref('aws_vpc.main')))
    assert statuses(rs,assume_direct_private=True)==['PASS','BLOCKED']
def test_prefix_list():
    rs=fixture(); rs[-1].attributes['ingress']=[dict(protocol='tcp',from_port=443,to_port=443,prefix_list_ids=['pl-123'])]
    assert statuses(rs)==['PASS','UNKNOWN']
def test_dynamic_rule():
    rs=fixture(); rs[-1].attributes['dynamic']={}; assert statuses(rs)==['PASS','UNKNOWN']
def test_ipv6():
    rs=fixture(); rs[2].attributes.pop('private_ip'); rs[3].attributes.pop('private_ip'); rs[-2].attributes['egress']=[dict(protocol='tcp',from_port=443,to_port=443,ipv6_cidr_blocks=['2001:db8::/32'])]; rs[-1].attributes['ingress']=rs[-2].attributes['egress']
    assert statuses(rs,source_ip='2001:db8::1',destination_ip='2001:db8::2')==['PASS','PASS']
def test_no_route_continues_and_no_false_reachable():
    rs=fixture(); result=analyze_communication(rs,scenario(destination_port=80),[SECURITY_GROUP_CHECK]); sg=[f for f in result['findings'] if f['check']=='security_group']
    assert len(sg)==2 and all(f['status']=='BLOCKED' and f['evaluation_mode']=='CONDITIONAL_CHECK' for f in sg)
    assert result['predicted_connectivity'] in ('UNKNOWN','BLOCKED') and result['forwarding']['hops']==[]
def test_unknown_coverage():
    result=analyze_communication(fixture(),scenario(source_ip=None),[SECURITY_GROUP_CHECK]); assert result['coverage']['checks']['security_group']['state']=='UNKNOWN'
def test_evidence():
    obs=evaluate_security_groups(fixture(),scenario()); assert obs[0].evidence[0]['rule']=='aws_security_group.a.egress[0]' and obs[0].evidence[0]['match']=='MATCH'


def test_hcl_demo():
    from backend.iac.terraform_parser import parse_terraform
    rs = parse_terraform('samples/terraform/security_group_demo.tf')
    opts=dict(source_subnet='aws_subnet.sg_demo',source_resource='aws_instance.web',source_ip='10.20.1.10',destination_resource='aws_instance.db',destination_ip='10.20.1.20',assume_direct_private=True)
    assert statuses(rs, **opts, destination_port=3306)==['PASS','PASS']
    assert statuses(rs, **opts, destination_port=5432)==['PASS','BLOCKED']
