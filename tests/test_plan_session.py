import copy, json
import pytest
from backend.iac.plan_adapter import load_plan, UNKNOWN
from scripts.serve_cloudpath import AnalysisApp
from test_plan_adapter import row, raw
from test_web_analysis import payload


def fixture():
    def acl(cidr, port):
        return dict(rule_no=100,protocol='tcp',action='allow',cidr_block=cidr,from_port=port,to_port=port)
    def sg(cidr, lo, hi):
        return dict(protocol='tcp',cidr_blocks=[cidr],from_port=lo,to_port=hi)
    rows=[row('aws_vpc','main',{'id':'vpc-demo','cidr_block':'10.0.0.0/16'}),
          row('aws_route_table','main',{'id':'rtb-demo','vpc_id':'vpc-demo','route':[{'cidr_block':'10.0.0.0/16','gateway_id':'local'}]})]
    for side,other,ip,n in [('a','b','10.0.1.10',1),('b','a','10.0.2.20',2)]:
        own=f'10.0.{n}.0/24';peer=f'10.0.{3-n}.0/24'
        rows.extend([row('aws_subnet',side,{'id':'subnet-'+side,'vpc_id':'vpc-demo','cidr_block':own}),
                     row('aws_route_table_association',side,{'id':'rtbassoc-'+side,'subnet_id':'subnet-'+side,'route_table_id':'rtb-demo'}),
                     row('aws_instance',side,{'id':'i-'+side,'subnet_id':'subnet-'+side,'private_ip':ip,'vpc_security_group_ids':['sg-'+side]}),
                     row('aws_security_group',side,{'id':'sg-'+side,'vpc_id':'vpc-demo','ingress':[sg(peer,0,65535)],'egress':[sg(peer,0,65535)]}),
                     row('aws_network_acl',side,{'id':'acl-'+side,'vpc_id':'vpc-demo','subnet_ids':['subnet-'+side], 'ingress':[acl(peer,49152 if side=='a' else 443)],'egress':[acl(peer,443 if side=='a' else 49152), *([dict(acl(peer,5432),rule_no=200)] if side=='a' else [])]})])
    return dict(format_version='1.2',complete=True,errored=False,planned_values={'root_module':{'resources':rows}},resource_changes=[dict(address=r['address'],mode='managed',change={'actions':['no-op'],'after_unknown':{},'after_sensitive':{}}) for r in rows],configuration={'provider_config':{'aws':{'full_name':'registry.terraform.io/hashicorp/aws'}},'root_module':{'resources':[{'address':r['address'],'mode':'managed','provider_config_key':'aws'} for r in rows]}})


def get(d,address):return next(r for r in d['planned_values']['root_module']['resources'] if r['address']==address)['values']
def change(d,address):return next(r for r in d['resource_changes'] if r['address']==address)['change']
def app(d):return AnalysisApp(*load_plan(raw(d)))

@pytest.mark.parametrize('kw,verdict,first', [({},'REACHABLE',None),({'destination_port':5432},'BLOCKED','REQ04'),({'source_port':49153},'BLOCKED','RET02'),({'complete_routing_config':False},'UNKNOWN',None)])
def test_known_plan_sessions(kw,verdict,first):
    a=app(fixture()); assert not a.snapshot['analysis_restricted'],a.snapshot
    r=a.analyze(payload(a,**kw));assert (r['predicted_connectivity'],r['first_blocker_step'])==(verdict,first);assert r['input_type']=='TERRAFORM_PLAN_JSON'

@pytest.mark.parametrize('case',['missing_sg','unknown_nacl','missing_route','alias','unsupported_route','duplicate_assoc','incomplete','module','missing_provider','other_region'])
def test_conservative_gate(case):
    d=fixture()
    if case=='missing_sg':get(d,'aws_instance.a')['vpc_security_group_ids']=[]
    elif case=='unknown_nacl':change(d,'aws_network_acl.a')['after_unknown']={'ingress':True}
    elif case=='missing_route':get(d,'aws_route_table.main')['route']=[]
    elif case=='alias':d['configuration']['provider_config']['aws']['alias']='other'
    elif case=='unsupported_route':get(d,'aws_route_table.main')['route'].append({'cidr_block':'10.0.2.0/24','gateway_id':'local'})
    elif case=='duplicate_assoc':get(d,'aws_route_table_association.b')['subnet_id']='subnet-a'
    elif case=='incomplete':d['complete']=False
    elif case=='module':d['configuration']['root_module']['module_calls']={'x':{}}
    elif case=='missing_provider':del d['configuration']
    elif case=='other_region':get(d,'aws_instance.a')['region']='us-east-1';get(d,'aws_instance.b')['region']='us-west-2'
    rs,i,s=load_plan(raw(d));assert s['analysis_restricted'];assert s['warnings']


def test_unknown_reference_hint_not_link():
    d=fixture();change(d,'aws_subnet.a')['after_unknown']={'vpc_id':True}
    cfg=next(c for c in d['configuration']['root_module']['resources'] if c['address']=='aws_subnet.a')
    cfg['expressions']={'vpc_id':{'references':['aws_vpc.main.id','var.secret','aws_vpc.main']}}
    rs,i,s=load_plan(raw(d));assert s['analysis_restricted'];assert next(r for r in rs if r.id=='aws_subnet.a').attributes['vpc_id']==UNKNOWN
    assert s['expression_reference_hints']==[dict(source='aws_subnet.a',field='vpc_id',target='aws_vpc.main',kind='EXPRESSION_REFERENCE_HINT')]
    assert 'var.secret' not in repr(s)
