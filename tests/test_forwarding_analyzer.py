from dataclasses import replace
import pytest
from backend.models.infrastructure import InfrastructureResource
from backend.models.diagnostics import CommunicationScenario
from backend.analyzer.forwarding_analyzer import trace_forwarding
from backend.analyzer.communication_analyzer import analyze_communication
from backend.analyzer.network_acl_analyzer import NETWORK_ACL_CHECK


def ref(r): return '${'+r+'.id}'
def r(id, **a): return InfrastructureResource(id,'aws','network',id.split('.')[0][4:],id.split('.')[1],a)
def fixture():
    v=ref('aws_vpc.main')
    return [r('aws_vpc.main',cidr_block='10.0.0.0/16'),r('aws_subnet.a',vpc_id=v,cidr_block='10.0.1.0/24'),r('aws_subnet.b',vpc_id=v,cidr_block='10.0.2.0/24'),r('aws_instance.a',subnet_id=ref('aws_subnet.a'),private_ip='10.0.1.10'),r('aws_instance.b',subnet_id=ref('aws_subnet.b'),private_ip='10.0.2.20')]
def scenario(**kw):
    return replace(CommunicationScenario('aws_subnet.a','10.0.2.20',source_resource='aws_instance.a',source_ip='10.0.1.10',destination_resource='aws_instance.b',destination_port=443,assume_direct_private=True),**kw)
def run(rs=None, **kw): return trace_forwarding(fixture() if rs is None else rs,scenario(**kw),complete_routing_config=True)
def stages(o): return [h['stage'] for h in o['hops']]
def table(rs, subnet, **route):
    name='aws_route_table.'+subnet
    rs.extend([r(name,vpc_id=ref('aws_vpc.main'),route=[dict(cidr_block='0.0.0.0/0',**route)]),r('aws_route_table_association.'+subnet,subnet_id=ref('aws_subnet.'+subnet),route_table_id=ref(name))])
def external(rs): return run(rs,destination_resource=None,destination_ip='203.0.113.10',assume_direct_private=False)
def test_local():
    o=run(); assert o['status']=='REACHED_DESTINATION' and o['path_complete']; assert stages(o)==['SOURCE_ENDPOINT','ROUTE_LOOKUP','VPC_LOCAL','DESTINATION_ENDPOINT']; assert o['packet_stopped'] is None
    assert [h['sequence'] for h in o['hops']]==[1,2,3,4]
def test_same_subnet():
    rs=fixture();rs[4].attributes.update(subnet_id=ref('aws_subnet.a'),private_ip='10.0.1.20');o=run(rs,destination_ip='10.0.1.20');assert stages(o)==['SOURCE_ENDPOINT','SAME_SUBNET','DESTINATION_ENDPOINT'];assert not o['route_lookups']
@pytest.mark.parametrize('changes',[{'source_ip':'10.0.1.99'},{'source_subnet':'aws_subnet.b'},{'destination_ip':'10.0.2.99'},{'destination_resource':'aws_instance.missing'},{'destination_resource':None},{'destination_ip':'2001:db8::1'},{'assume_direct_private':False}])
def test_unresolved(changes): assert run(**changes)['status']=='UNKNOWN'
def test_missing_explicit_ip():
    rs=fixture();rs[4].attributes.pop('private_ip');assert run(rs)['status']=='UNKNOWN'
def test_incomplete_inventory(): assert trace_forwarding(fixture(),scenario())['status']=='UNKNOWN'
def test_secondary_cidr():
    rs=fixture()+[r('aws_vpc_ipv4_cidr_block_association.more',vpc_id=ref('aws_vpc.main'))];assert run(rs)['status']=='UNKNOWN'
def test_unresolved_association():
    rs=fixture()+[r('aws_route_table_association.x',subnet_id='${var.subnet}',route_table_id=ref('aws_route_table.x'))];assert run(rs)['status']=='UNKNOWN'
def test_missing_route(): assert external(fixture())['status']=='NO_ROUTE'
def test_igw():
    rs=fixture()+[r('aws_internet_gateway.main',vpc_id=ref('aws_vpc.main'))];table(rs,'a',gateway_id=ref('aws_internet_gateway.main'));o=external(rs);assert o['status']=='PARTIAL' and stages(o)[-1]=='INTERNET_GATEWAY' and not o['path_complete']
def test_wrong_igw():
    rs=fixture()+[r('aws_internet_gateway.main',vpc_id=ref('aws_vpc.other'))];table(rs,'a',gateway_id=ref('aws_internet_gateway.main'));assert external(rs)['status']=='UNKNOWN'
def nat_fixture():
    rs=fixture()+[r('aws_nat_gateway.main',subnet_id=ref('aws_subnet.b')),r('aws_internet_gateway.main',vpc_id=ref('aws_vpc.main'))];table(rs,'a',nat_gateway_id=ref('aws_nat_gateway.main'));return rs
def test_nat_igw():
    rs=nat_fixture();table(rs,'b',gateway_id=ref('aws_internet_gateway.main'));o=external(rs);assert o['status']=='PARTIAL' and stages(o)==['SOURCE_ENDPOINT','ROUTE_LOOKUP','NAT_GATEWAY','ROUTE_LOOKUP','INTERNET_GATEWAY'];assert len(o['route_lookups'])==2
    assert all(not h['translation_verified'] for h in o['hops'] if h['stage'] in ('NAT_GATEWAY','INTERNET_GATEWAY'))
def test_nat_no_route(): assert external(nat_fixture())['status']=='NO_ROUTE'
def test_nat_loop():
    rs=nat_fixture();table(rs,'b',nat_gateway_id=ref('aws_nat_gateway.main'));assert external(rs)['status']=='LOOP_DETECTED'
def test_more_specific_unsupported():
    rs=fixture();table(rs,'a',gateway_id='local');rs[-2].attributes['route'].append(dict(cidr_block='10.0.2.0/24',network_interface_id=ref('aws_network_interface.middle')));assert run(rs)['status']=='UNKNOWN'
def test_policy_separation():
    o=analyze_communication(fixture(),scenario(),[NETWORK_ACL_CHECK],trace=True,complete_routing_config=True);assert o['forwarding']['path_complete'];assert o['predicted_connectivity']=='UNKNOWN';assert o['first_blocker'] is None;assert o['coverage']['checks']['return_path']['state']=='NOT_EVALUATED';assert o['coverage']['checks']['forwarding_candidate']['state']=='EVALUATED'
def test_legacy(): assert analyze_communication(fixture(),scenario())['forwarding']['hops']==[]
def test_hcl_demo():
    from backend.iac.terraform_parser import parse_terraform
    rs=parse_terraform('samples/terraform/network_acl_demo.tf');assert run(rs)['status']=='REACHED_DESTINATION'

def test_conditional_blocker_preserved():
    rs=fixture();v=ref('aws_vpc.main');rs.extend([r('aws_network_acl.a',vpc_id=v,subnet_ids=[ref('aws_subnet.a')],egress=[dict(rule_no=100,action='allow',protocol='tcp',cidr_block='10.0.2.0/24',from_port=443,to_port=443)]),r('aws_network_acl.b',vpc_id=v,subnet_ids=[ref('aws_subnet.b')],ingress=[])])
    o=analyze_communication(rs,scenario(complete_nacl_config=True),[NETWORK_ACL_CHECK],trace=True,complete_routing_config=True)
    assert o['forwarding']['path_complete'] and o['predicted_connectivity']=='UNKNOWN' and o['first_blocker'] is None
    assert len(o['conditional_blockers'])==1
    assert next(f for f in o['findings'] if f['id']==o['conditional_blockers'][0])['status']=='BLOCKED'
