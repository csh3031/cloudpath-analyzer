"""Presentation-only, allowlisted configuration rule details (not evaluation)."""
import re
from ipaddress import ip_network

SG = {'security_group', 'default_security_group'}
ACL = {'network_acl', 'default_network_acl'}
ROUTE = {'route_table', 'default_route_table'}
UNKNOWN = '미확정 / 미지원 값'
CIDR = {'cidr_block','ipv6_cidr_block','cidr_ipv4','cidr_ipv6','destination_cidr_block','destination_ipv6_cidr_block'}
CIDRS = {'cidr_blocks','ipv6_cidr_blocks'}
REF = {'gateway_id','nat_gateway_id','transit_gateway_id','vpc_peering_connection_id','network_interface_id','instance_id','egress_only_gateway_id','local_gateway_id','carrier_gateway_id','vpc_endpoint_id','source_security_group_id','referenced_security_group_id','prefix_list_id','destination_prefix_list_id'}
REFS = {'security_groups','prefix_list_ids','observed_target_ids'}
NUM = {'from_port','to_port','rule_no','rule_number','icmp_type','icmp_code'}
ENUM = {'action':{'allow','deny'},'rule_action':{'allow','deny'},'observed_state':{'active','blackhole'},'observed_origin':{'CreateRouteTable','CreateRoute','EnableVgwRoutePropagation'}}
FIELDS = CIDR | CIDRS | REF | REFS | NUM | set(ENUM) | {'protocol','ip_protocol','self'}


def safe_ref(value, known):
    if not isinstance(value,str): return UNKNOWN
    if value == 'local': return value
    if value in known: return value
    if value.startswith('${') and value.endswith('.id}') and value[2:-4] in known: return value[2:-4]
    if re.fullmatch(r'(?:sg|pl|igw|nat|tgw|pcx|eni|i|eigw|lgw|cagw|vpce|vgw)-[0-9a-fA-F]+',value): return value
    return UNKNOWN


def safe_cidr(value):
    try: return str(ip_network(value, strict=False)) if isinstance(value,str) and '/' in value else UNKNOWN
    except ValueError: return UNKNOWN


def sanitize_rule(row, known):
    if not isinstance(row,dict): return {'state':UNKNOWN}
    out={}
    for key in sorted(FIELDS & row.keys()):
        v=row[key]
        if v is None: continue
        if key in CIDR: out[key]=safe_cidr(v)
        elif key in CIDRS: out[key]=[safe_cidr(x) for x in v] if isinstance(v,list) else UNKNOWN
        elif key in REF: out[key]=safe_ref(v,known)
        elif key in REFS: out[key]=[safe_ref(x,known) for x in v] if isinstance(v,list) else UNKNOWN
        elif key in NUM: out[key]=v if type(v) is int and -1<=v<=65535 else UNKNOWN
        elif key in ENUM: out[key]=v if isinstance(v,str) and v in ENUM[key] else UNKNOWN
        elif key=='self': out[key]=v if type(v) is bool else UNKNOWN
        else:
            valid=type(v) in (str,int) and (str(v).lower() in {'tcp','udp','icmp','icmpv6','all','-1'} or (str(v).isdigit() and len(str(v))<=3 and int(v)<=255))
            out[key]=str(v) if valid else UNKNOWN
    return out or {'state':UNKNOWN}


def build_policy_display(resources):
    resources=list(resources); known={r.id for r in resources}; result={}; aliases={}
    for r in resources:
        a=r.attributes
        if not isinstance(a,dict) or r.resource_type not in SG|ACL|ROUTE: continue
        keys=('route',) if r.resource_type in ROUTE else ('ingress','egress')
        data={'kind':r.resource_type,'sections':{},'warnings':[]}
        for key in keys:
            rows=a.get(key)
            data['sections'][key]={'presence':'defined' if isinstance(rows,list) else 'unconfirmed','rows':[
                {'source':f'{r.id}.{key}[{i}]','fields':sanitize_rule(row,known)} for i,row in enumerate(rows or [])] if isinstance(rows,list) else []}
        if any(k in a for k in ('dynamic','count','for_each')): data['warnings'].append('동적 구성: 실제 규칙 수 및 값 미확정')
        result[r.id]=data
        if isinstance(a.get('id'),str): aliases.setdefault(a['id'],[]).append(r.id)
    modern={'aws_vpc_security_group_ingress_rule':'ingress','aws_vpc_security_group_egress_rule':'egress'}
    for r in resources:
        a=r.attributes; t=r.resource_type
        if not isinstance(a,dict): continue
        if t in modern or t=='aws_security_group_rule': key='security_group_id'; d=modern.get(t,a.get('type')); types=SG
        elif t=='aws_network_acl_rule': key='network_acl_id'; d='egress' if a.get('egress') is True else 'ingress' if a.get('egress',False) is False else None; types=ACL
        elif t=='route': key='route_table_id'; d='route'; types=ROUTE
        else: continue
        val=a.get(key); target=safe_ref(val,known)
        if target not in result and isinstance(val,str) and len(aliases.get(val,[]))==1: target=aliases[val][0]
        if target not in result or result[target]['kind'] not in types:
            for p in result.values():
                if p['kind'] in types and '소속 미확정 별도 규칙 존재' not in p['warnings']: p['warnings'].append('소속 미확정 별도 규칙 존재')
            continue
        p=result[target]
        if not isinstance(d,str) or d not in p['sections'] or any(k in a for k in ('dynamic','count','for_each')):
            p['warnings'].append('별도 규칙의 방향 또는 인스턴스 미확정'); continue
        section=p['sections'][d]
        if section['presence']=='defined' and 'Inline/별도 규칙 혼용: 유효 정책은 별도 확인' not in p['warnings']: p['warnings'].append('Inline/별도 규칙 혼용: 유효 정책은 별도 확인')
        section['rows'].append({'source':r.id,'fields':sanitize_rule(a,known)})
    for p in result.values():
        if p['kind'] in ACL:
            for s in p['sections'].values():
                s['rows'].sort(key=lambda row: (row['fields'].get('rule_no',row['fields'].get('rule_number')) if type(row['fields'].get('rule_no',row['fields'].get('rule_number'))) is int else 99999))
    return result
