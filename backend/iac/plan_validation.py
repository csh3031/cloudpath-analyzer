"""Conservative semantic eligibility for planned direct IPv4 sessions.

Expression references are hints, never substitutes for planned IDs. This
validator deliberately accepts only a small known-value, single-VPC subset.
"""
from ipaddress import ip_address, ip_network
from backend.analyzer.network_acl_analyzer import ref, association, collect_rules
from backend.analyzer.forwarding_analyzer import _endpoint

TYPES = {'aws_vpc','aws_subnet','aws_instance','aws_route_table',
         'aws_route_table_association','aws_security_group','aws_network_acl'}


def reference_hints(doc, parsed, ref_fields):
    """Root unindexed declarations only; metadata does not enter graph edges."""
    root = doc.get('configuration', {})
    root = root.get('root_module', {}) if isinstance(root, dict) else {}
    configs = root.get('resources', []) if isinstance(root, dict) else []
    if not isinstance(configs,list): return []
    known = {r['address'] for r, *_ in parsed}
    hints = []
    for c in configs:
        if not isinstance(c,dict) or c.get('address') not in known: continue
        address = c['address']
        if '[' in address or address.startswith('module.'): continue
        expr = c.get('expressions')
        if not isinstance(expr,dict): continue
        for field,e in expr.items():
            if field not in ref_fields or not isinstance(e,dict): continue
            refs = e.get('references',[])
            if not isinstance(refs,list): continue
            targets = sorted({x[:-3] for x in refs if isinstance(x,str) and x.endswith('.id') and x[:-3] in known})
            for target in targets:
                item = {'source':address,'field':field,'target':target,'kind':'EXPRESSION_REFERENCE_HINT'}
                if item not in hints: hints.append(item)
                if len(hints)>=300: return hints
    return hints


def validate_direct_plan(doc, parsed, resources):
    """Return eligibility issues; do not mutate any input on rejection."""
    reasons=set()
    def bad(s): reasons.add(s)
    idx={r.id:r for r in resources}
    kinds={r.id:r.id.split('.')[0] for r in resources}
    def lookup(v,kind):
        r=idx.get(ref(v)); return r if r and kinds[r.id]==kind else None
    def network(v):
        try:
            n=ip_network(v,strict=True);return n if isinstance(v,str) and n.version==4 else None
        except (ValueError,TypeError):return None
    def port(n):return type(n) is int and 0<=n<=65535
    if any(k not in TYPES for k in kinds.values()):bad('Plan session v2 supports only direct EC2, VPC, subnet, inline SG/NACL and explicit route associations')
    if doc.get('complete') is not True:bad('Complete plan required')
    config=doc.get('configuration',{})
    providers=config.get('provider_config',{}) if isinstance(config,dict) else {}
    root=config.get('root_module',{}) if isinstance(config,dict) else {}
    configs=root.get('resources',[]) if isinstance(root,dict) else []
    if not isinstance(configs,list):configs=[]
    cfg={c.get('address'):c for c in configs if isinstance(c,dict) and isinstance(c.get('address'),str)}
    if not isinstance(providers,dict) or len(providers)!=1:
        bad('One explicit AWS provider configuration required')
        provider_key=None
    else:
        provider_key,p=next(iter(providers.items()))
        if not isinstance(p,dict) or p.get('full_name')!='registry.terraform.io/hashicorp/aws' or p.get('alias') or p.get('module_address'):
            bad('Provider identity/alias not supported')
    if len(cfg)!=len(configs):bad('Duplicate or invalid configuration addresses')
    if any(c.get('mode')=='data' for c in configs if isinstance(c,dict)) or (isinstance(root,dict) and root.get('module_calls')):
        bad('Module/data provider semantics not certified for session analysis')
    regions=set()
    for row,rid,values,unknown,cs,sensitive in parsed:
        c=cfg.get(row['address'],{})
        if row['address']!=rid or not c or c.get('provider_config_key')!=provider_key or c.get('count_expression') or c.get('for_each_expression'):
            bad('Root unindexed resources with a common provider required')
        from backend.iac.plan_adapter import _has_mask, _mask_at
        guarded = ('region','ipv6_cidr_block','ipv6_cidr_blocks','assign_generated_ipv6_cidr_block',
                   'secondary_private_ips','ipv6_addresses','network_interface','primary_network_interface','network_interface_id')
        if any(_has_mask(_mask_at(m,k)) for m in (unknown,cs,sensitive) for k in guarded):
            bad('Unresolved or sensitive region/address/interface attribute')
        if values.get('region'):regions.add(str(values['region']))
        if row['type']=='aws_route_table' and isinstance(values.get('route'),list):
            for route in values['route']:
                if not isinstance(route,dict) or any(v not in (None,'',[],False) for k,v in route.items() if k not in ('cidr_block','gateway_id')):
                    bad('Unmodeled explicit route fields')
        if values.get('ipv6_cidr_block') or values.get('ipv6_cidr_blocks') or values.get('assign_generated_ipv6_cidr_block'):
            bad('IPv6 configuration outside initial session scope')
        # Computed network interfaces or explicit attachments are not certified.
        if row['type']=='aws_instance' and any(values.get(k) for k in ('network_interface','primary_network_interface','network_interface_id','secondary_private_ips','ipv6_addresses')):
            bad('Additional interface or address configuration not supported')
    if len(regions)>1:bad('Multiple regions not supported')
    vpcs=[r for r in resources if kinds[r.id]=='aws_vpc']
    vpc=vpcs[0] if len(vpcs)==1 else None
    vn=network(vpc.attributes.get('cidr_block')) if vpc else None
    if not vn:bad('Exactly one known IPv4 VPC required')
    subs=[r for r in resources if kinds[r.id]=='aws_subnet']
    nets=[]; ips=set(); local_tables=[]
    for r in resources:
        a=r.attributes;k=kinds[r.id]
        if k in ('aws_subnet','aws_security_group','aws_network_acl','aws_route_table') and (not vpc or lookup(a.get('vpc_id'),'aws_vpc')!=vpc):bad('VPC membership missing or inconsistent')
        if k=='aws_subnet':
            n=network(a.get('cidr_block'))
            if not n or not vn or not n.subnet_of(vn) or any(n.overlaps(o) for o in nets):bad('Subnet CIDR missing, overlapping or outside VPC')
            if n:nets.append(n)
        elif k=='aws_instance':
            try:ip=ip_address(a.get('private_ip')) if isinstance(a.get('private_ip'),str) else None
            except ValueError:ip=None
            if not ip or ip in ips or not _endpoint(idx,r.id,ip):bad('Endpoint private address missing, duplicate or invalid')
            if ip:ips.add(ip)
            gs=a.get('vpc_security_group_ids')
            if not isinstance(gs,list) or not gs or any(not lookup(g,'aws_security_group') for g in gs):bad('Explicit SG membership required')
        elif k=='aws_route_table':
            # A known explicit local route may be deduplicated against the HCL engine's implicit local route.
            routes=a.get('route')
            if (not isinstance(routes,list) or len(routes)!=1 or not vn or routes[0]!={'cidr_block':str(vn),'gateway_id':'local'} or a.get('propagating_vgws')):
                bad('Explicit single IPv4 local route required; other route shapes not certified')
            else:local_tables.append(r)
        elif k=='aws_route_table_association':
            if not lookup(a.get('subnet_id'),'aws_subnet') or not lookup(a.get('route_table_id'),'aws_route_table') or a.get('gateway_id'):bad('Invalid route association')
        elif k in ('aws_security_group','aws_network_acl'):
            for direction in ('ingress','egress'):
                rows=a.get(direction)
                if not isinstance(rows,list):bad('Explicit known inbound/outbound policy lists required');continue
                for rule in rows:
                    if not isinstance(rule,dict):bad('Invalid inline rule');continue
                    p=str(rule.get('protocol')).lower()
                    if p not in ('tcp','udp','6','17','-1') or not port(rule.get('from_port')) or not port(rule.get('to_port')) or rule['from_port']>rule['to_port']:
                        bad('Unsupported or incomplete rule protocol/ports')
                    if k=='aws_security_group':
                        # First subset: IPv4 CIDR policies, no SG refs, prefix lists or self rules.
                        cidrs=rule.get('cidr_blocks')
                        if not isinstance(cidrs,list) or not cidrs or any(not network(x) for x in cidrs) or any(rule.get(x) for x in ('ipv6_cidr_blocks','security_groups','self','prefix_list_ids','source_security_group_id','referenced_security_group_id')):
                            bad('Only explicit IPv4 CIDR SG rules certified')
                    else:
                        if not network(rule.get('cidr_block')) or rule.get('ipv6_cidr_block') or rule.get('action') not in ('allow','deny') or type(rule.get('rule_no')) is not int or not 1<=rule['rule_no']<=32766:
                            bad('Invalid or unsupported inline NACL rule')
                if k=='aws_network_acl' and collect_rules(resources,r,direction)[1]:bad('NACL rule conflicts')
    for s in subs:
        linked=[r for r in resources if kinds[r.id]=='aws_route_table_association' and ref(r.attributes.get('subnet_id'))==s.id]
        if len(linked)!=1:bad('Exactly one explicit route association per subnet required')
        if vpc:
            acl,err=association(resources,s,vpc)
            if err or not acl:bad('Exactly one explicit NACL per subnet required')
    if len(ips)<2:bad('At least two explicit IPv4 endpoints required')
    return sorted(reasons),local_tables
