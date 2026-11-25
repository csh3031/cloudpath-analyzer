"""Conditional static subnet-boundary ACL evaluation for direct TCP/UDP flows.
No AWS calls, forwarding inference, or stateful response assumptions.
"""
import re
from ipaddress import ip_network, ip_address
from backend.models.diagnostics import PolicyCheck, PolicyObservation

ACL_TYPES = {'aws_network_acl', 'aws_default_network_acl'}

def kind(r): return r.id.split('.')[0]
def dynamic(a): return any(k in a for k in ('count', 'for_each', 'dynamic'))
def ref(v, attr='id'):
    if not isinstance(v, str): return None
    if v.startswith('${') and v.endswith('}'): v = v[2:-1].strip()
    m = re.fullmatch(r'(aws_[\w-]+\.[\w-]+)\.' + re.escape(attr), v)
    return m.group(1) if m else None

def number(v, lo, hi):
    return v if type(v) is int and lo <= v <= hi else None

def protocol(v):
    if type(v) not in (int, str): return None
    s = str(v).lower()
    if s in ('tcp','udp','icmp','icmpv6'): return {'tcp':6,'udp':17,'icmp':1,'icmpv6':58}[s]
    if re.fullmatch(r'-1|[0-9]{1,3}',s):
        n = int(s); return n if -1 <= n <= 255 else None
    return None

def addr(v):
    try: return ip_address(v) if isinstance(v,str) else None
    except ValueError: return None

def net(v):
    try: return ip_network(v, strict=False) if isinstance(v,str) else None
    except ValueError: return None

def endpoint(index, rid, address):
    r = index.get(rid)
    if not r or kind(r) not in ('aws_instance','aws_network_interface') or dynamic(r.attributes): return None
    a = r.attributes
    if kind(r)=='aws_instance' and any(k in a for k in ('network_interface','primary_network_interface')): return None
    subnet = index.get(ref(a.get('subnet_id')))
    if not subnet or kind(subnet)!='aws_subnet' or dynamic(subnet.attributes): return None
    vpc = index.get(ref(subnet.attributes.get('vpc_id')))
    if not vpc or kind(vpc)!='aws_vpc' or dynamic(vpc.attributes): return None
    if address is None: return None
    cidr = net(subnet.attributes.get('cidr_block' if address.version==4 else 'ipv6_cidr_block'))
    if cidr is None or address not in cidr: return None
    if 'private_ip' in a and address.version==4 and addr(a['private_ip']) != address: return None
    for key in ('private_ips','ipv6_addresses'):
        if key in a and (key=='private_ips')==(address.version==4):
            vals=a[key]
            if not isinstance(vals,list) or address not in [addr(v) for v in vals]: return None
    return subnet, vpc

def association(resources, subnet, vpc):
    """Return ACL, or implicit default marker, or reason for uncertainty."""
    candidates=[]; defaults=[]; uncertain=False
    for r in resources:
        a=r.attributes; t=kind(r)
        if t in ACL_TYPES:
            owner=ref(a.get('vpc_id')) if t=='aws_network_acl' else ref(a.get('default_network_acl_id'),'default_network_acl_id')
            if owner is None or (owner==vpc.id and dynamic(a)): uncertain=True
            if t=='aws_default_network_acl' and owner==vpc.id: defaults.append(r)
            if 'subnet_ids' not in a: continue
            values=a['subnet_ids']
            if not isinstance(values,list):
                if owner in (None,vpc.id): uncertain=True
                continue
            refs=[ref(x) for x in values]
            if None in refs and owner in (None,vpc.id): uncertain=True
            if subnet.id in refs:
                if dynamic(a) or owner!=vpc.id: uncertain=True
                candidates.append((r.id,'inline'))
        elif t=='aws_network_acl_association':
            s=ref(a.get('subnet_id')); acl=ref(a.get('network_acl_id'))
            if s is None: uncertain=True
            elif s==subnet.id:
                if acl is None or dynamic(a): uncertain=True
                candidates.append((acl,'standalone'))
    if uncertain or len(candidates)>1 or len(defaults)>1: return None,'association unresolved or conflicting'
    index={r.id:r for r in resources}
    if candidates:
        acl=index.get(candidates[0][0])
        if not acl or kind(acl) not in ACL_TYPES or dynamic(acl.attributes): return None,'ACL missing or dynamic'
        owner=ref(acl.attributes.get('vpc_id')) if kind(acl)=='aws_network_acl' else ref(acl.attributes.get('default_network_acl_id'),'default_network_acl_id')
        if owner!=vpc.id: return None,'ACL VPC mismatch or unresolved'
        if candidates[0][1]=='standalone' and 'subnet_ids' in acl.attributes: return None,'mixed association management'
        return acl,None
    if defaults:
        if dynamic(defaults[0].attributes): return None,'dynamic default ACL'
        return defaults[0],None
    return None,'implicit_default'

def collect_rules(resources, acl, direction):
    a=acl.attributes; rows=[]; invalid=False; standalone=False
    inline=a.get(direction,[])
    if not isinstance(inline,list): return [],True
    for i,row in enumerate(inline):
        if not isinstance(row,dict): invalid=True; continue
        rows.append((f'{acl.id}.{direction}[{i}]',row.get('rule_no'),row.get('action'),row))
    for r in resources:
        if kind(r)!='aws_network_acl_rule': continue
        a2=r.attributes; target=ref(a2.get('network_acl_id'))
        if target is None: invalid=True; continue
        if target!=acl.id: continue
        standalone=True
        egress=a2.get('egress',False)
        if type(egress) is not bool or dynamic(a2): invalid=True; continue
        if egress!=(direction=='egress'): continue
        rows.append((r.id,a2.get('rule_number'),a2.get('rule_action'),a2))
    if standalone and (kind(acl)=='aws_default_network_acl' or 'ingress' in a or 'egress' in a): invalid=True
    nums=[number(row[1],1,32766) for row in rows]
    if None in nums or len(set(nums))!=len(nums): invalid=True
    return sorted(rows,key=lambda x:x[1]) if not invalid else [],invalid

def matches(rule, peer, wanted, dst_port):
    p=protocol(rule.get('protocol'))
    if p is not None and p not in (-1,wanted): return False
    cidrs=[rule[k] for k in ('cidr_block','ipv6_cidr_block') if k in rule and rule[k] not in (None,'')]
    if len(cidrs)!=1: return None
    n=net(cidrs[0])
    if n is not None and peer not in n: return False
    if p is None or n is None: return None
    if p==-1: return True
    lo,hi=number(rule.get('from_port'),0,65535),number(rule.get('to_port'),0,65535)
    if lo is None or hi is None or lo>hi: return None
    return lo<=dst_port<=hi

def evaluate_network_acls(resources, scenario):
    index={r.id:r for r in resources}; src_ip=addr(scenario.source_ip); dst_ip=addr(scenario.destination_ip)
    src=endpoint(index,scenario.source_resource,src_ip); dst=endpoint(index,scenario.destination_resource,dst_ip)
    p=protocol(scenario.protocol); port=number(scenario.destination_port,0,65535)
    assumptions=('초기 요청 방향의 정적 NACL 검사입니다. 응답 방향은 미검증입니다.',
                 '직접 동일 VPC 통신 및 입력 주소가 해당 인터페이스의 주소라고 가정합니다.')
    def obs(status,direction,reason,subnet=None,evidence=()):
        return PolicyObservation(status,f'{direction.upper()}: {reason}',subnet,tuple(evidence),assumptions)
    if (len(index)!=len(resources) or not scenario.assume_direct_private or not src or not dst or
        src[0].id!=scenario.source_subnet or src[1].id!=dst[1].id or src_ip.version!=dst_ip.version or
        p not in (6,17) or port is None or src_ip==dst_ip or
        any(kind(r)=='aws_network_interface_attachment' for r in resources)):
        return [obs('UNKNOWN',d,'직접 동일 VPC 통신 또는 주소/서브넷/인터페이스 정보 미확정') for d in ('egress','ingress')]
    if src[0].id==dst[0].id:
        return [obs('PASS',d,'동일 서브넷 직접 통신: NACL 경계 검사 비적용',src[0].id,
                    [{'direction':d,'applicable':False,'match':'NOT_APPLICABLE'}]) for d in ('egress','ingress')]
    result=[]
    for d,side,peer in [('egress',src,dst_ip),('ingress',dst,src_ip)]:
        subnet,vpc=side
        acl,error=association(resources,subnet,vpc)
        ev=[{'direction':d,'subnet':subnet.id,'acl':acl.id if acl else None,'applicable':True}]
        if not scenario.complete_nacl_config:
            result.append(obs('UNKNOWN',d,'NACL 규칙 및 연결의 완전성 미확인',subnet.id,ev)); continue
        if error=='implicit_default' and scenario.assume_unmodified_default_nacl and src_ip.version==4:
            ev[0].update({'acl':'implicit_default','match':'MATCH','rule_number':100,'action':'allow','assumed':True})
            result.append(obs('PASS',d,'변경되지 않은 IPv4 기본 NACL 가정에 따른 허용',subnet.id,ev)); continue
        if error:
            ev[0]['reason']=error
            result.append(obs('UNKNOWN',d,'NACL 연결 또는 기본 정책 미확정',subnet.id,ev)); continue
        rows,invalid=collect_rules(resources,acl,d)
        if invalid:
            result.append(obs('UNKNOWN',d,'규칙 번호/방향/관리 방식이 미확정 또는 충돌',subnet.id,ev)); continue
        for rule_id,num,action,rule in rows:
            m=matches(rule,peer,p,port)
            ev.append({'direction':d,'acl':acl.id,'rule':rule_id,'rule_number':num,'action':action,
                       'match':'MATCH' if m is True else 'NO_MATCH' if m is False else 'UNKNOWN'})
            if m is False: continue
            if m is None or action not in ('allow','deny'):
                result.append(obs('UNKNOWN',d,'선행 일치 가능 규칙의 판정 미확정',subnet.id,ev)); break
            result.append(obs('PASS' if action=='allow' else 'BLOCKED',d,f'첫 일치 규칙 {num}: {action}',subnet.id,ev)); break
        else:
            ev.append({'direction':d,'acl':acl.id,'rule_number':'*','action':'deny','match':'MATCH'})
            result.append(obs('BLOCKED',d,'일치 규칙 없음: 암묵적 기본 거부',subnet.id,ev))
    return result

NETWORK_ACL_CHECK=PolicyCheck('network_acl',evaluate_network_acls,evaluation_mode='CONDITIONAL_CHECK')
