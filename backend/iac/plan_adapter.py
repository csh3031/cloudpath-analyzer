"""Read Terraform show -json planned values, never execute Terraform.

V1 intentionally exposes a partial topology when relationships are unresolved.
V2 enables a strictly bounded known-value direct-session subset.
"""
import hashlib
import json
import re
from backend.models.infrastructure import InfrastructureResource

# Keep only network fields consumed by current analyzers. Never retain raw plan,
# outputs, variables, user_data, tags, credentials or provider configuration.
KINDS = {
 'aws_vpc': ('network','vpc','cidr_block'),
 'aws_subnet': ('network','subnet','vpc_id cidr_block availability_zone'),
 'aws_instance': ('compute','instance','subnet_id private_ip vpc_security_group_ids network_interface primary_network_interface network_interface_id security_groups'),
 'aws_network_interface': ('network','network_interface','subnet_id private_ip private_ips security_groups'),
 'aws_route_table': ('network','route_table','vpc_id route propagating_vgws'),
 'aws_route_table_association': ('network','route_table_association','subnet_id route_table_id gateway_id'),
 'aws_main_route_table_association': ('network','main_route_table_association','vpc_id route_table_id'),
 'aws_route': ('network','route','route_table_id destination_cidr_block destination_ipv6_cidr_block destination_prefix_list_id gateway_id nat_gateway_id transit_gateway_id vpc_peering_connection_id network_interface_id instance_id egress_only_gateway_id local_gateway_id carrier_gateway_id core_network_arn vpc_endpoint_id'),
 'aws_internet_gateway': ('network','internet_gateway','vpc_id'),
 'aws_nat_gateway': ('network','nat_gateway','subnet_id connectivity_type'),
 'aws_security_group': ('security','security_group','vpc_id ingress egress'),
 'aws_network_acl': ('security','network_acl','vpc_id subnet_ids ingress egress'),
 'aws_network_acl_association': ('security','aws_network_acl_association','subnet_id network_acl_id'),
 'aws_network_acl_rule': ('security','aws_network_acl_rule','network_acl_id rule_number egress protocol rule_action cidr_block ipv6_cidr_block from_port to_port icmp_type icmp_code'),
 'aws_security_group_rule': ('security','aws_security_group_rule','security_group_id type protocol from_port to_port cidr_blocks ipv6_cidr_blocks source_security_group_id self prefix_list_ids'),
 'aws_vpc_security_group_ingress_rule': ('security','aws_vpc_security_group_ingress_rule','security_group_id ip_protocol from_port to_port cidr_ipv4 cidr_ipv6 referenced_security_group_id prefix_list_id'),
 'aws_vpc_security_group_egress_rule': ('security','aws_vpc_security_group_egress_rule','security_group_id ip_protocol from_port to_port cidr_ipv4 cidr_ipv6 referenced_security_group_id prefix_list_id'),
}
RULE_FIELDS = set('protocol ip_protocol from_port to_port cidr_blocks ipv6_cidr_blocks cidr_ipv4 cidr_ipv6 cidr_block ipv6_cidr_block security_groups source_security_group_id referenced_security_group_id self prefix_list_ids prefix_list_id rule_no rule_number action icmp_type icmp_code gateway_id nat_gateway_id transit_gateway_id vpc_peering_connection_id network_interface_id instance_id egress_only_gateway_id local_gateway_id carrier_gateway_id core_network_arn vpc_endpoint_id destination_prefix_list_id'.split())
REF_FIELDS = set('vpc_id subnet_id subnet_ids route_table_id gateway_id nat_gateway_id vpc_security_group_ids security_groups source_security_group_id referenced_security_group_id security_group_id network_acl_id network_interface_id instance_id transit_gateway_id vpc_peering_connection_id egress_only_gateway_id local_gateway_id carrier_gateway_id core_network_arn vpc_endpoint_id'.split())
UNKNOWN = '__CLOUDPATH_PLAN_UNRESOLVED__'


def _has_mask(mask):
    if mask is True: return True
    if isinstance(mask, dict): return any(_has_mask(v) for v in mask.values())
    if isinstance(mask, list): return any(_has_mask(v) for v in mask)
    return False


def _mask_at(mask, key):
    return True if mask is True else mask.get(key,False) if isinstance(mask,dict) else False


def _object(value):
    if not isinstance(value,dict): raise ValueError('Invalid Terraform plan structure')
    return value


def _array(value):
    if not isinstance(value,list): raise ValueError('Invalid Terraform plan structure')
    return value


def _mask_valid(value):
    return type(value) is bool or isinstance(value,dict) and all(_mask_valid(v) for v in value.values()) or isinstance(value,list) and all(_mask_valid(v) for v in value)


def _read(raw):
    def no_duplicates(pairs):
        result={}
        for k,v in pairs:
            if k in result: raise ValueError('Duplicate JSON key')
            result[k]=v
        return result
    try:
        return _object(json.loads(raw,object_pairs_hook=no_duplicates,parse_constant=lambda x: (_ for _ in ()).throw(ValueError('Non-finite JSON number'))))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError('Invalid Terraform Plan JSON') from exc


def load_plan(raw, name='plan.json', max_resources=300):
    doc=_read(raw)
    version=doc.get('format_version')
    if not isinstance(version,str) or not re.fullmatch(r'1\.\d+',version):
        raise ValueError('Only Terraform Plan JSON format 1.x supported')
    if 'planned_values' not in doc or 'resource_changes' not in doc:
        raise ValueError('Expected terraform show -json plan output, not state or arbitrary JSON')
    if doc.get('errored') is True: raise ValueError('Errored Terraform plan')
    reasons=set()
    if doc.get('complete') is not True: reasons.add('Plan completeness not confirmed')
    if doc.get('deferred_changes') or doc.get('action_invocations'): reasons.add('Deferred changes or action invocations not modeled')
    changes={}
    for row in _array(doc['resource_changes']):
        row=_object(row)
        if row.get('mode')!='managed' or row.get('deposed'): continue
        address=row.get('address')
        if not isinstance(address,str) or address in changes: raise ValueError('Duplicate or invalid plan change address')
        c=_object(row.get('change'))
        for k in ('after_unknown','after_sensitive'):
            if k in c and not _mask_valid(c[k]): raise ValueError('Invalid plan mask')
        changes[address]=c
    rows=[]
    def walk(module, depth=0):
        if depth>40: raise ValueError('Plan module nesting exceeds limit')
        for row in _array(_object(module).get('resources',[])):
            row=_object(row)
            if row.get('mode')!='managed': continue
            rows.append(row)
            if len(rows)>max_resources: raise ValueError('Resource limit: 300 instances')
        for child in _array(module.get('child_modules',[])): walk(child,depth+1)
    walk(_object(doc['planned_values']).get('root_module',{}))
    if not rows: raise ValueError('No planned managed resources found')
    ids={}; aws_ids={}; duplicates=set(); parsed=[]
    for row in rows:
        address,kind,rname=row.get('address'),row.get('type'),row.get('name')
        if not all(isinstance(x,str) and 0<len(x)<=1000 for x in (address,kind,rname)) or not re.fullmatch(r'[A-Za-z_][\w-]*',kind) or not re.fullmatch(r'[A-Za-z_][\w-]*',rname): raise ValueError('Invalid plan resource address')
        if address in ids: raise ValueError('Duplicate planned resource address')
        if row.get('provider_name')!='registry.terraform.io/hashicorp/aws' or not kind.startswith('aws_'):
            reasons.add('Non-AWS or unsupported provider resource omitted');continue
        c=changes.get(address)
        if c is None: reasons.add('Missing resource change metadata')
        elif c.get('actions') not in (['no-op'],['create'],['update'],['delete','create'],['create','delete']):
            reasons.add('Unsupported change action')
            if c.get('actions')==['delete']: continue
        # Simple IDs preserve compatibility; complex addresses receive deterministic IDs.
        rid=address if address==f'{kind}.{rname}' else f'{kind}.cpplan_{hashlib.sha256(address.encode()).hexdigest()[:24]}'
        if rid in ids.values(): raise ValueError('Normalized ID collision')
        ids[address]=rid
        values=_object(row.get('values',{})); sensitive=row.get('sensitive_values',{})
        if not _mask_valid(sensitive): raise ValueError('Invalid sensitive mask')
        unknown=(c or {}).get('after_unknown',{}); cs=(c or {}).get('after_sensitive',{})
        native_id=values.get('id')
        if isinstance(native_id,str) and native_id and not any(_has_mask(_mask_at(m,'id')) for m in (unknown,cs,sensitive)):
            if native_id in aws_ids: duplicates.add(native_id)
            aws_ids[native_id]=rid
        parsed.append((row,rid,values,unknown,cs,sensitive))
    if not parsed: raise ValueError('No AWS managed resources found')
    for x in duplicates: aws_ids.pop(x,None)
    if duplicates: reasons.add('Ambiguous AWS resource IDs')
    if set(changes)-{r.get('address') for r in rows}:
        for addr in set(changes)-{r.get('address') for r in rows}:
            if changes[addr].get('actions')!=['delete']: reasons.add('Managed change absent from planned values')
    resources=[]
    def normalize(value,key):
        if isinstance(value,str):
            if '${' in value or '%{' in value:
                reasons.add('Unresolved or expression-like planned value'); return UNKNOWN
            if key in REF_FIELDS:
                if key=='gateway_id' and value=='local':return value
                if value in aws_ids:return '${'+aws_ids[value]+'.id}'
                reasons.add('Unresolved external or planned AWS ID');return UNKNOWN
            return value
        if isinstance(value,list):return [normalize(v,key) for v in value]
        if isinstance(value,dict):return {k:normalize(v,k) for k,v in value.items() if k in RULE_FIELDS and v is not None and v!=''}
        if value is None or type(value) in (bool,int,float):return value
        raise ValueError('Invalid planned attribute')
    for row,rid,values,unknown,cs,sensitive in parsed:
        kind=row['type']; category,typ,fields=KINDS.get(kind,('unknown',kind,''))
        if kind not in KINDS: reasons.add('Unsupported AWS resource type present')
        attrs={}
        for key in fields.split():
            if any(_has_mask(_mask_at(m,key)) for m in (unknown,cs,sensitive)):
                reasons.add('Unknown or sensitive network attribute omitted');attrs[key]=UNKNOWN;continue
            if key in values and values[key] is not None and values[key]!='':
                # Empty optional attachment blocks should not signal configured ENIs.
                if key in ('network_interface','primary_network_interface','security_groups','propagating_vgws') and values[key]==[]:continue
                attrs[key]=normalize(values[key],key)
        if kind=='aws_instance' and any(k in attrs for k in ('network_interface','primary_network_interface','network_interface_id','security_groups')): reasons.add('Explicit network interface attachment not modeled')
        # Keep original Terraform address as a display name, not a parser key.
        resources.append(InfrastructureResource(rid,'aws',category,typ,row['address'],attrs))
    idx={r.id:r for r in resources}
    def deref(value): return value[2:-4] if isinstance(value,str) and value.startswith('${') and value.endswith('.id}') else None
    # Existing VPCs must not silently inherit an assumed default route table/ACL.
    from backend.analyzer.routing_analyzer import find_route_table
    for s in resources:
        if s.resource_type!='subnet':continue
        v=idx.get(deref(s.attributes.get('vpc_id')))
        if not v:reasons.add('Subnet VPC unresolved');continue
        table=find_route_table(resources,s.id)
        if not table or table.startswith('implicit_main:'):reasons.add('Explicit route table coverage required for Plan analysis')
        # Check explicit known ACL membership without assuming default ACL rules.
        attached=any(r.id.startswith('aws_network_acl.') and '${'+s.id+'.id}' in (r.attributes.get('subnet_ids') if isinstance(r.attributes.get('subnet_ids'),list) else []) or r.id.startswith('aws_network_acl_association.') and r.attributes.get('subnet_id')=='${'+s.id+'.id}' for r in resources)
        if not attached:reasons.add('Explicit NACL coverage required for Plan analysis')
    from backend.iac.plan_validation import validate_direct_plan, reference_hints
    validation,local_tables=validate_direct_plan(doc,parsed,resources)
    reasons.update(validation)
    restricted=bool(reasons)
    hints=reference_hints(doc,parsed,REF_FIELDS)
    identity='sha256-plan-v1:'+hashlib.sha256(raw).hexdigest()
    return resources,identity,{'files':[{'name':name,'bytes':len(raw)}], 'resource_count':len(resources),
        'analysis_restricted':restricted,'warnings':sorted(reasons),'input_type':'TERRAFORM_PLAN_JSON',
        'relationship_source':'RESOLVED_PLANNED_IDS_NOT_HCL_EXPRESSIONS',
        'plan_session_scope':'DIRECT_KNOWN_IPV4_INLINE_POLICIES' if not restricted else 'TOPOLOGY_ONLY',
        'expression_reference_hints':hints}
