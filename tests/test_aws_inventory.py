import base64, copy, json, subprocess
from types import SimpleNamespace
from pathlib import Path
import pytest
from backend.aws.snapshot import FORMAT, OPERATIONS, load_aws_snapshot, sanitize_inventory
from backend.iac.upload_snapshot import load_snapshot
from scripts.collect_aws_inventory import collect
from scripts.serve_cloudpath import AnalysisApp

V='vpc-12345678'; S='subnet-12345678'; G='sg-12345678'; E='eni-12345678'; I='i-12345678'; T='rtb-12345678'; A='acl-12345678'; GW='igw-12345678'
def fixture():
    return {'format':FORMAT,'region':'ap-northeast-2','vpc_id':V,'collected_at':'2026-11-25T11:00:00+00:00','inventory':{
      'Vpcs':[{'VpcId':V,'CidrBlock':'10.0.0.0/16','State':'available','Tags':[{'Key':'secret','Value':'DO_NOT_COPY'}]}],
      'Subnets':[{'SubnetId':S,'VpcId':V,'CidrBlock':'10.0.1.0/24','AvailabilityZone':'ap-northeast-2a','State':'available'}],
      'RouteTables':[{'RouteTableId':T,'VpcId':V,'Associations':[{'RouteTableAssociationId':'rtbassoc-12345678','Main':True,'AssociationState':{'State':'associated'}}],'Routes':[{'DestinationCidrBlock':'10.0.0.0/16','GatewayId':'local','State':'active'},{'DestinationCidrBlock':'0.0.0.0/0','GatewayId':GW,'State':'active'}]}],
      'InternetGateways':[{'InternetGatewayId':GW,'Attachments':[{'VpcId':V,'State':'available'}]}], 'NatGateways':[],
      'SecurityGroups':[{'GroupId':G,'VpcId':V,'IpPermissions':[{'IpProtocol':'tcp','FromPort':443,'ToPort':443,'IpRanges':[{'CidrIp':'10.0.0.0/16','Description':'DO_NOT_COPY'}]}],'IpPermissionsEgress':[]}],
      'NetworkAcls':[{'NetworkAclId':A,'VpcId':V,'Associations':[{'SubnetId':S,'NetworkAclAssociationId':'aclassoc-12345678'}],'Entries':[{'RuleNumber':100,'Protocol':'6','RuleAction':'allow','Egress':False,'CidrBlock':'10.0.0.0/16','PortRange':{'From':443,'To':443}}]}],
      'Reservations':[{'OwnerId':'DO_NOT_COPY','Instances':[{'InstanceId':I,'VpcId':V,'SubnetId':S,'PrivateIpAddress':'10.0.1.10','State':{'Name':'running'},'SecurityGroups':[{'GroupId':G}],'NetworkInterfaces':[{'NetworkInterfaceId':E}]}]}],
      'NetworkInterfaces':[{'NetworkInterfaceId':E,'VpcId':V,'SubnetId':S,'PrivateIpAddress':'10.0.1.10','PrivateIpAddresses':[{'PrivateIpAddress':'10.0.1.10'}],'Groups':[{'GroupId':G}],'Attachment':{'InstanceId':I,'DeviceIndex':0},'Status':'in-use','InterfaceType':'interface','RequesterManaged':False}]}}
def raw(d):return json.dumps(d).encode()
def index(d):return {r.id:r for r in load_aws_snapshot(raw(d))[0]}
def test_mapping():
    d=fixture();i=index(d);assert len(i)==9
    assert i['aws_security_group.'+G].attributes['ingress'][0]['from_port']==443
    assert i['aws_network_acl.'+A].attributes['ingress'][0]['rule_no']==100
    assert i['aws_network_interface.'+E].attributes['instance_id']=='${aws_instance.'+I+'.id}'
    assert i['aws_route_table.'+T].attributes['route'][1]['gateway_id']=='${aws_internet_gateway.'+GW+'.id}'
def test_scrub():assert 'DO_NOT_COPY' not in json.dumps(sanitize_inventory(fixture()['inventory']))
def test_upload_and_restricted():
    d=fixture();r,ident,s=load_snapshot([{'name':'inventory.json','content_base64':base64.b64encode(raw(d)).decode()}]);assert ident.startswith('sha256-aws-v1:') and s['analysis_restricted'];app=AnalysisApp(r,ident,s)
    assert b'AWS' in app.html
    with pytest.raises(ValueError,match='restricted'):app.analyze({})
def test_no_implicit_table():
    d=fixture();d['inventory']['RouteTables'][0]['Associations']=[];app=AnalysisApp(*load_aws_snapshot(raw(d)))
    import re
    match=re.search(rb'<script[^>]*id="graph-data"[^>]*>(.*?)</script>',app.html,re.S)
    if not match:
        match=re.search(rb'<script[^>]*type="application/json"[^>]*>(.*?)</script>',app.html,re.S)
    payload=json.loads(match.group(1));assert not any(n.get('synthetic') for n in payload['network_graph']['nodes'])
def test_blackhole():
    d=fixture();d['inventory']['RouteTables'][0]['Routes'][1]['State']='blackhole';r=index(d)['aws_route_table.'+T].attributes['route'][1];assert 'gateway_id' not in r and r['observed_state']=='blackhole'
@pytest.mark.parametrize('case',['missing_group','other_vpc','duplicate','bad_cidr','bad_id','bad_time'])
def test_invalid(case):
    d=fixture();inv=d['inventory']
    if case=='missing_group':del inv['NatGateways']
    elif case=='other_vpc':inv['Subnets'][0]['VpcId']='vpc-87654321'
    elif case=='duplicate':inv['Subnets'].append(copy.deepcopy(inv['Subnets'][0]))
    elif case=='bad_cidr':inv['Subnets'][0]['CidrBlock']='bad'
    elif case=='bad_id':inv['Subnets'][0]['SubnetId']='subnet-x'
    else:d['collected_at']='2026-01-01'
    with pytest.raises(ValueError):load_aws_snapshot(raw(d))
def test_cli_collect():
    calls=[];d=fixture()
    def run(cmd,**kw):
        calls.append(cmd);key,filter_name=OPERATIONS[cmd[2]];assert f'Name={filter_name},Values={V}' in cmd;assert '--no-paginate' not in cmd;assert kw['check'];return SimpleNamespace(stdout=raw({key:d['inventory'][key]}))
    out=collect('ap-northeast-2',V,'lab',run=run);assert len(calls)==9 and b'DO_NOT_COPY' not in out;assert all(c[2].startswith('describe-') for c in calls);assert load_aws_snapshot(out)[2]['analysis_restricted']
def test_cli_fail_closed():
    def run(cmd,**kw):raise subprocess.CalledProcessError(1,cmd,stderr=b'SECRET')
    with pytest.raises(ValueError,match='describe-vpcs failed') as e:collect('ap-northeast-2',V,run=run)
    assert 'SECRET' not in str(e.value)
def test_cli_incomplete():
    def run(cmd,**kw):return SimpleNamespace(stdout=raw({'Vpcs':[],'NextToken':'token'}))
    with pytest.raises(ValueError,match='Incomplete'):collect('ap-northeast-2',V,run=run)

def test_core_arn_redacted():
    inv=fixture()['inventory'];inv['RouteTables'][0]['Routes'][1]['CoreNetworkArn']='arn:aws:networkmanager::123456789012:core-network/core-network-12345678'
    assert '123456789012' not in json.dumps(sanitize_inventory(inv))
