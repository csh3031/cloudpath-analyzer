import base64
import json
import pytest
from backend.iac.plan_adapter import load_plan, UNKNOWN
from backend.iac.upload_snapshot import load_snapshot
from scripts.serve_cloudpath import AnalysisApp
from test_web_analysis import payload


def row(t,n,v,mod=''):
    return dict(address=mod+t+'.'+n, type=t, name=n, mode='managed',provider_name='registry.terraform.io/hashicorp/aws',values=v,sensitive_values={})


def fixture():
    rows=[row('aws_vpc','main',{'id':'vpc-abc','cidr_block':'10.0.0.0/16'}),row('aws_subnet','a',{'id':'subnet-abc','vpc_id':'vpc-abc','cidr_block':'10.0.1.0/24'},'module.network.'),row('aws_instance','a',{'id':'i-abc','subnet_id':'subnet-abc','private_ip':'10.0.1.10','user_data':'NEVER_SHOW_THIS','vpc_security_group_ids':['sg-abc']},'module.compute.'),row('aws_security_group','a',{'id':'sg-abc','vpc_id':'vpc-abc','ingress':[],'egress':[]})]
    return dict(format_version='1.2',complete=True,errored=False,planned_values={'root_module':{'resources':[rows[0],rows[3]],'child_modules':[{'address':'module.network','resources':[rows[1]]},{'address':'module.compute','resources':[rows[2]]}]}},resource_changes=[dict(address=r['address'],mode='managed',change={'actions':['no-op'],'after_unknown':{},'after_sensitive':{}}) for r in rows])


def raw(d):return json.dumps(d).encode()
def entry(name,d):return {'name':name,'content_base64':base64.b64encode(raw(d)).decode()}
def test_module_mapping_and_no_secret():
    rs,identity,s=load_plan(raw(fixture()));idx={r.name:r for r in rs};sub=idx['module.network.aws_subnet.a'];i=idx['module.compute.aws_instance.a'];assert i.attributes['subnet_id']=='${'+sub.id+'.id}';assert sub.attributes['vpc_id']=='${aws_vpc.main.id}';assert len(rs)==4 and s['analysis_restricted'] and identity.startswith('sha256-plan-v1:');assert 'NEVER_SHOW_THIS' not in repr(rs)

def test_known_id_graph_and_no_invented_main():
    rs,identity,s=load_plan(raw(fixture()));app=AnalysisApp(rs,identity,s);assert len(app.endpoints)==1;html=app.html.decode();g=json.loads(html.split('id="graph-data">')[1].split('</script>')[0]);assert not any(n.get('synthetic') for n in g['network_graph']['nodes']);assert len(g['reference_graph']['edges'])>=3;assert 'NEVER_SHOW_THIS' not in html;assert 'Resolved ID relationships' in html
    with pytest.raises(ValueError,match='restricted'):app.analyze(payload(app))

def test_unknown_and_sensitive_mask():
    d=fixture();d['resource_changes'][1]['change']['after_unknown']={'vpc_id':True};d['resource_changes'][2]['change']['after_sensitive']={'private_ip':True};rs,_,s=load_plan(raw(d));idx={r.name:r for r in rs};assert idx['module.network.aws_subnet.a'].attributes['vpc_id']==UNKNOWN;assert idx['module.compute.aws_instance.a'].attributes['private_ip']==UNKNOWN;assert '10.0.1.10' not in repr(rs);assert s['analysis_restricted']

def test_unknown_not_inferred_from_expression_refs():
    d=fixture();d['resource_changes'][1]['change']['after_unknown']={'vpc_id':True};d['configuration']={'root_module':{'expressions':{'vpc_id':{'references':['aws_vpc.main.id']}}}};rs,_,_=load_plan(raw(d));assert next(r for r in rs if r.resource_type=='subnet').attributes['vpc_id']==UNKNOWN

def test_deleted_not_in_planned_values():
    d=fixture();d['resource_changes'].append(dict(address='aws_instance.deleted',mode='managed',change={'actions':['delete']}));rs,_,_=load_plan(raw(d));assert len(rs)==4

@pytest.mark.parametrize('d',[{}, {'format_version':'2.0','planned_values':{},'resource_changes':[]},{'format_version':'1.2','values':{}},{**fixture(),'errored':True}])
def test_reject_invalid_plan(d):
    with pytest.raises(ValueError):load_plan(raw(d))

def test_upload_dispatch_and_mixed_rejection():
    e=entry('plan.json',fixture());rs,identity,s=load_snapshot([e]);assert s['input_type']=='TERRAFORM_PLAN_JSON' and len(rs)==4
    with pytest.raises(ValueError):load_snapshot([e,entry('main.tf',{})])
    with pytest.raises(ValueError):load_snapshot([e,entry('another.json',fixture())])

def test_identity_changes():
    d=fixture();a=load_plan(raw(d))[1];d['complete']=False;b=load_plan(raw(d))[1];assert a!=b

def test_duplicate_native_id_not_guessed():
    d=fixture();d['planned_values']['root_module']['resources'][1]['values']['id']='vpc-abc';rs,_,s=load_plan(raw(d));assert next(r for r in rs if r.resource_type=='subnet').attributes['vpc_id']==UNKNOWN;assert 'Ambiguous AWS resource IDs' in s['warnings']
