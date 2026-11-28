import copy
import json
from pathlib import Path
import pytest
from backend.aws.iam_inventory import register_iam_inventory, MAX_BYTES

D=Path(__file__).resolve().parents[1]/'samples/aws/phase7_demo'
def raw(x): return json.dumps(x).encode()
def base(): return json.loads((D/'iam_inventory_observed.json').read_bytes())
def overlay(): return json.loads((D/'iam_overlay_detach.json').read_bytes())
def run(b=None,o=None): return register_iam_inventory(raw(base() if b is None else b),None if o is None else raw(o))
def codes(r): return {i['code'] for i in r['issues']}

def test_observed():
    r=run(); assert r['registration_status']=='REGISTERED_CANDIDATE' and r['counts']==dict(identities=1,policies=1,attachments=1)
    assert r['authorization_status']=='NOT_EVALUATED' and r['api_status']=='UNKNOWN' and not r['live_observation']
    assert r['effective_completeness']=='NOT_ATTESTED' and r['effective']['policies'][0]['origin']=='OBSERVED'

@pytest.mark.parametrize('layer,source',[('planned','TERRAFORM'),('hypothetical','MANUAL')])
def test_other_layers(layer,source):
    r=register_iam_inventory((D/f'iam_inventory_{layer}.json').read_bytes()); assert r['base_source']==source
    assert r['registration_status']=='UNRESOLVED_REFERENCES_OR_EVIDENCE' and 'COLLECTION_INCOMPLETE' in codes(r)
    assert r['effective']['identities'][0]['origin']==layer.upper()

def test_detach():
    b=base(); orig=copy.deepcopy(b); r=run(b,overlay()); assert b==orig
    assert r['counts']['attachments']==0 and r['effective_mode']=='WHAT_IF' and run(b)['counts']['attachments']==1
    assert r['effective']['policies'][0]['origin']=='OBSERVED' and r['api_status']=='UNKNOWN'

def test_modify_policy():
    b=base(); o=overlay(); p=copy.deepcopy(b['policies'][0]); p['document']['Statement'][0]['Effect']='Deny'
    o['operations']=[dict(operation='UPSERT',collection='policies',key=p['ref'],record=p)]
    r=run(b,o); assert r['effective']['policies'][0]['origin']=='HYPOTHETICAL'
    assert r['effective']['policies'][0]['record']['document']['Statement'][0]['Effect']=='Deny'
    assert b['policies'][0]['document']['Statement'][0]['Effect']=='Allow' and r['authorization_status']=='NOT_EVALUATED'

@pytest.mark.parametrize('collection,code',[('identities','IDENTITY_REFERENCE_UNRESOLVED'),('policies','POLICY_REFERENCE_UNRESOLVED')])
def test_missing_ref(collection,code):
    b=base(); b[collection]=[]; assert code in codes(run(b))

@pytest.mark.parametrize('collection',['identities','policies','attachments'])
def test_duplicate(collection):
    b=base(); b[collection]*=2
    with pytest.raises(ValueError,match='Duplicate'): run(b)

@pytest.mark.parametrize('collection',['identities','policies','attachments'])
def test_incomplete(collection):
    b=base(); b['complete'][collection]=False; assert 'COLLECTION_INCOMPLETE' in codes(run(b))

@pytest.mark.parametrize('field,value',[('account_id','bad'),('source','MANUAL'),('layer','EFFECTIVE'),('registered_at','2026-11-28T05:00:20'),('schema','wrong'),('complete',{})])
def test_bad_base(field,value):
    b=base(); b[field]=value
    with pytest.raises(ValueError): run(b)

@pytest.mark.parametrize('field,value',[('base_identity','wrong'),('account_id','999999999999'),('schema','wrong'),('registered_at','yesterday')])
def test_bad_overlay(field,value):
    o=overlay(); o[field]=value
    with pytest.raises(ValueError): run(o=o)

def test_overlay_duplicate():
    o=overlay(); o['operations']*=2
    with pytest.raises(ValueError,match='Duplicate'): run(o=o)

def test_overlay_invalid_delete():
    o=overlay(); o['operations'][0]['key'][2]='arn:aws:iam::123456789012:policy/other'
    with pytest.raises(ValueError,match='deletion'): run(o=o)

def test_overlay_invalid_upsert():
    o=overlay(); o['operations'][0].update(operation='UPSERT',record=base()['policies'][0])
    with pytest.raises(ValueError): run(o=o)

def test_overlay_no_cascade():
    b=base(); o=overlay(); o['operations']=[dict(operation='DELETE',collection='identities',key=b['identities'][0]['arn'],record=None)]
    r=run(b,o); assert r['counts']['attachments']==1 and 'IDENTITY_REFERENCE_UNRESOLVED' in codes(r)

@pytest.mark.parametrize('field,value,code',[('document',None,'POLICY_DOCUMENT_UNRESOLVED'),('default_version','v3','MANAGED_DEFAULT_VERSION_UNCONFIRMED'),('policy_id',None,'MANAGED_POLICY_ID_UNRESOLVED')])
def test_policy_unresolved(field,value,code):
    b=base(); b['policies'][0][field]=value; assert code in codes(run(b))

def test_identity_unresolved():
    b=base(); b['identities'][0]['unique_id']=None; assert 'IDENTITY_UNIQUE_ID_UNRESOLVED' in codes(run(b))

def test_group_registration():
    b=base(); b['identities'].append(dict(arn='arn:aws:iam::123456789012:group/demo',kind='GROUP',unique_id='AGPASYNTHETIC1234'))
    assert run(b)['counts']['identities']==2

def test_inline_registration():
    b=base(); role=b['identities'][0]['arn']; ref='inline:'+role+'#demo'; p=dict(ref=ref,kind='INLINE',owner_arn=role,policy_id=None,default_version=None,document_version=None,document={})
    b['policies'].append(p); b['attachments'].append(dict(identity_arn=role,policy_ref=ref,kind='IDENTITY_POLICY'))
    assert run(b)['counts']['policies']==2
    p['owner_arn']='arn:aws:iam::123456789012:role/other'
    with pytest.raises(ValueError): run(b)

def test_boundary_registration():
    b=base(); a=copy.deepcopy(b['attachments'][0]); a['kind']='PERMISSIONS_BOUNDARY'; b['attachments'].append(a)
    assert run(b)['counts']['attachments']==2 and run(b)['authorization_status']=='NOT_EVALUATED'
    a=copy.deepcopy(a); a['policy_ref']='arn:aws:iam::123456789012:policy/other'; b['attachments'].append(a)
    assert 'MULTIPLE_BOUNDARIES' in codes(run(b))

def test_aws_managed():
    b=base(); b['policies'][0]['ref']=b['attachments'][0]['policy_ref']='arn:aws:iam::aws:policy/demo'; assert not run(b)['issues']

@pytest.mark.parametrize('raw_input',[b'{"schema":1,"schema":2}',b'{"x":NaN}',b'\xff',b' '* (MAX_BYTES+1)])
def test_invalid_json(raw_input):
    with pytest.raises(ValueError): register_iam_inventory(raw_input)

def test_no_credentials_field():
    b=base(); b['access_key']='example'
    with pytest.raises(ValueError): run(b)

def test_cross_account():
    b=base(); b['identities'][0]['arn']='arn:aws:iam::999999999999:role/demo'
    with pytest.raises(ValueError): run(b)

def test_canonical_digest():
    b=base(); r=run(b); assert r['base_identity']==register_iam_inventory(json.dumps(b,sort_keys=True,indent=4).encode())['base_identity']
