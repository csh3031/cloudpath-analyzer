import pytest
from backend.aws.policy_evidence import evaluate_observed_policy
from test_aws_forwarding_evidence import pair, SRC, DST, D, explicit
from test_aws_inventory import raw, A, G, S


def setup():
    d=pair(); inv=d['inventory']; sg=inv['SecurityGroups'][0]
    sg['IpPermissionsEgress']=[dict(IpProtocol='-1',IpRanges=[dict(CidrIp='0.0.0.0/0')])]
    a=inv['NetworkAcls'][0];a['Associations'].append(dict(SubnetId=D,NetworkAclAssociationId='aclassoc-87654321'))
    a['Entries']=[dict(RuleNumber=100,Protocol='6',RuleAction='allow',Egress=e,CidrBlock='10.0.0.0/16',PortRange={'From':1,'To':65535}) for e in (True,False)]
    a['Entries'] += [dict(RuleNumber=32767,Protocol='-1',RuleAction='deny',Egress=e,CidrBlock='0.0.0.0/0') for e in (True,False)]
    return d


def run(d,sp=50000,dp=443):
    r=evaluate_observed_policy(raw(d),SRC,DST,sp,dp)
    assert r['session_status']=='NOT_EVALUATED' and r['live_observation'] is False
    assert r['response']['conditional'] and all(c['independent'] for c in r['request']['checks']+r['response']['checks'])
    return r


def statuses(r,direction):return [c['status'] for c in r[direction]['checks']]


def test_allow_and_conditional():
    r=run(setup());assert statuses(r,'request')==['ALLOW_CANDIDATE']*4
    assert statuses(r,'response')==['CONDITIONAL','ALLOW_CANDIDATE','ALLOW_CANDIDATE','CONDITIONAL']
    assert r['response']['destination_port']==50000

@pytest.mark.parametrize('port',[0,65536,-1,True,'443',None])
def test_bad_port(port):
    with pytest.raises(ValueError):run(setup(),dp=port)

@pytest.mark.parametrize('field,idx',[('IpPermissionsEgress',0),('IpPermissions',3)])
def test_sg_no_match(field,idx):
    d=setup();d['inventory']['SecurityGroups'][0][field]=[]
    assert statuses(run(d),'request')[idx]=='BLOCKED'

@pytest.mark.parametrize('field,value',[('UserIdGroupPairs',[{'GroupId':G}]),('PrefixListIds',[{'PrefixListId':'pl-12345678'}])])
def test_sg_unresolved(field,value):
    d=setup();d['inventory']['SecurityGroups'][0]['IpPermissions']=[dict(IpProtocol='tcp',FromPort=443,ToPort=443,**{field:value})]
    assert statuses(run(d),'request')[3]=='UNKNOWN'


def test_sg_allow_union():
    d=setup();d['inventory']['SecurityGroups'][0]['IpPermissions'].insert(0,dict(IpProtocol='tcp',FromPort=443,ToPort=443,UserIdGroupPairs=[{'GroupId':G}]))
    assert statuses(run(d),'request')[3]=='ALLOW_CANDIDATE'


def test_acl_ascending_deny():
    d=setup();d['inventory']['NetworkAcls'][0]['Entries'].append(dict(RuleNumber=50,Protocol='6',RuleAction='deny',Egress=True,CidrBlock='10.0.0.0/16',PortRange={'From':443,'To':443}))
    r=run(d);assert statuses(r,'request')[1]=='BLOCKED' and r['request']['checks'][1]['rule_number']==50
    assert statuses(r,'response')[1]=='ALLOW_CANDIDATE'


def test_acl_reply_ephemeral_denied():
    d=setup();d['inventory']['NetworkAcls'][0]['Entries'][0]['PortRange']={'From':443,'To':443}
    r=run(d);assert statuses(r,'request')==['ALLOW_CANDIDATE']*4
    assert statuses(r,'response')[1]=='BLOCKED' and r['response']['checks'][1]['rule_number']==32767

@pytest.mark.parametrize('case',['missing','ambiguous','missing_id'])
def test_acl_association(case):
    d=setup();a=d['inventory']['NetworkAcls'][0]
    if case=='missing':a['Associations']=a['Associations'][1:]
    elif case=='ambiguous':a['Associations'].append(dict(a['Associations'][0]))
    else:del a['Associations'][0]['NetworkAclAssociationId']
    assert statuses(run(d),'request')[1]=='UNKNOWN'


def test_acl_missing_default():
    d=setup();d['inventory']['NetworkAcls'][0]['Entries']=[]
    assert statuses(run(d),'request')[1:3]==['UNKNOWN','UNKNOWN']


def test_acl_ambiguous_first_rule():
    d=setup();d['inventory']['NetworkAcls'][0]['Entries'].append(dict(RuleNumber=50,Protocol='6',RuleAction='deny',Egress=True,CidrBlock='10.0.0.0/16'))
    assert statuses(run(d),'request')[1]=='UNKNOWN'


def test_forwarding_block_preserves_independent_checks():
    d=setup();t=explicit(d,S);t['Routes'][0]['State']='blackhole'
    r=run(d);assert r['forwarding']['request']['status']=='BLOCKED'
    assert statuses(r,'request')==['ALLOW_CANDIDATE']*4


def test_invalid_endpoint_not_evaluated():
    d=setup();d['inventory']['Reservations'][0]['Instances'][0]['State']['Name']='stopped'
    assert statuses(run(d),'request')==['NOT_EVALUATED']*4
