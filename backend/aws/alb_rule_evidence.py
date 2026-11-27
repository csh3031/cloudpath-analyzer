"""Bounded offline ALB rule selection; no target or runtime verdict."""
import hashlib
import json
import re
from backend.aws.load_balancer_evidence import inspect_load_balancer, _arn, _id
from backend.aws.peering_evidence import _timestamp, _load
from backend.iac.plan_adapter import _read

FORMAT = 'cloudpath-alb-rules-v1'
HOST = re.compile(r'[A-Za-z0-9.-]{1,253}')
PATH = re.compile(r'/[A-Za-z0-9._~/-]{0,511}')
RULE_ID = re.compile(r'[0-9a-f]{16}')


def _condition(c, host, path):
    if not isinstance(c, dict):
        return 'UNKNOWN'
    field = c.get('Field')
    config_key = {'host-header':'HostHeaderConfig', 'path-pattern':'PathPatternConfig'}.get(field) if isinstance(field,str) else None
    if config_key is None or set(c)-{'Field','Values',config_key}:
        return 'UNKNOWN'
    config = c.get(config_key)
    if config_key in c and (not isinstance(config,dict) or set(config)!={'Values'}):
        return 'UNKNOWN'
    values = config['Values'] if config is not None else c.get('Values')
    if 'Values' in c and c['Values'] != values:
        return 'UNKNOWN'
    allowed = r'[A-Za-z0-9.*?-]{1,128}' if field=='host-header' else r'/[A-Za-z0-9._~/*?-]{0,127}'
    if not isinstance(values,list) or not 1<=len(values)<=3 or any(not isinstance(v,str) or not re.fullmatch(allowed,v) or v.count('*')+v.count('?')>5 for v in values):
        return 'UNKNOWN'
    # Use a bounded glob matcher; never interpret input as regular expressions.
    def matches(pattern, text):
        if field=='host-header': pattern,text=pattern.lower(),text.lower()
        reachable={0}
        for token in pattern:
            if token=='*': reachable=set(range(min(reachable),len(text)+1)) if reachable else set()
            else: reachable={i+1 for i in reachable if i<len(text) and (token=='?' or token==text[i])}
        return len(text) in reachable
    return 'MATCH' if any(matches(v,host if field=='host-header' else path) for v in values) else 'NO_MATCH'


def inspect_alb_rule(inventory_raw, elbv2_raw, rules_raw, load_balancer_id, listener_port, host, path):
    base=inspect_load_balancer(inventory_raw,elbv2_raw,load_balancer_id,listener_port)
    result=dict(analysis_type='STATIC_AWS_ALB_RULE_SELECTION',input_identity=base['input_identity'],
                elbv2_input_identity=base['elbv2_input_identity'],rules_input_identity='sha256-alb-rules-v1:'+hashlib.sha256(rules_raw).hexdigest(),
                load_balancer_id=load_balancer_id, listener=base['listener'], selected_rule=None, evaluated_rules=[],
                selected_target_groups=[], rule_selection='UNKNOWN', action_type=None, target_selection='NOT_EVALUATED',
                target_health='NOT_EVALUATED',policy_status='NOT_EVALUATED',session_status='UNKNOWN',live_observation=False,
                limitations=['Offline snapshots; completeness asserted, authenticity and simultaneous state unverified.',
                             'Host name and canonical ASCII path only; no request transmission or URI normalization.',
                             'Value matching only; unsupported earlier conditions cannot be skipped unless another condition is false.',
                             'Transforms, authentication, redirect/fixed-response execution and target selection are not evaluated.',
                             'No DNS, TLS, target health, network policy or application verification.'])
    def finish(reason,status='UNKNOWN'):
        return dict(result,status=status,reason=reason)
    if not isinstance(host,str) or not HOST.fullmatch(host) or any(not label or label.startswith('-') or label.endswith('-') or len(label)>63 for label in host.split('.')):
        return finish('UNSUPPORTED_HOST_INPUT')
    if not isinstance(path,str) or not PATH.fullmatch(path) or '//' in path or any(s in ('.','..') for s in path.split('/')):
        return finish('UNSUPPORTED_PATH_INPUT')
    result['scenario']={'host':host,'path':path}
    if not base['listener'] or base['load_balancer']['type']!='application':
        return finish('ALB_LISTENER_UNCONFIRMED')
    # The prior inspector has verified LB and listener identity before evaluating default actions.
    doc=_read(elbv2_raw); rules=_read(rules_raw)
    if set(rules)!={'format','collected_at','ListenerArn','complete','Rules'} or rules['format']!=FORMAT:
        raise ValueError('Expected dated ALB rules wrapper')
    if rules['complete'] is not True: return finish('RULE_SET_INCOMPLETE')
    _,meta,_=_load(inventory_raw)
    timestamps=[_timestamp(x) for x in (rules['collected_at'],doc['collected_at'],meta['collected_at'])]
    if (max(timestamps)-min(timestamps)).total_seconds()>300: return finish('SNAPSHOT_TIME_GAP')
    la=rules['ListenerArn']; _arn(la,'listener')
    listeners=[l for l in doc['Listeners'] if l['ListenerArn']==la and _id(la)==base['listener']['id'] and _id(l['LoadBalancerArn'])==load_balancer_id and l['Port']==listener_port]
    if len(listeners)!=1: return finish('RULE_LISTENER_MISMATCH')
    rows=rules['Rules']
    if not isinstance(rows,list) or not 1<=len(rows)<=300: return finish('RULE_SET_INVALID')
    ordered=[]; defaults=[]; ids=set(); priorities=set()
    prefix=la.replace(':listener/',':listener-rule/',1)+'/'
    for row in rows:
        if not isinstance(row,dict): return finish('RULE_SET_INVALID')
        arn=row.get('RuleArn'); priority=row.get('Priority'); default=row.get('IsDefault'); conditions=row.get('Conditions'); actions=row.get('Actions')
        if not isinstance(arn,str) or not arn.startswith(prefix) or not RULE_ID.fullmatch(arn[len(prefix):]) or arn in ids or type(default) is not bool or not isinstance(conditions,list) or len(conditions)>5 or not isinstance(actions,list) or not actions:
            return finish('RULE_SET_INVALID')
        ids.add(arn)
        if default:
            if priority!='default' or conditions or row.get('Transforms') or actions!=listeners[0]['DefaultActions']: return finish('DEFAULT_RULE_CONFLICT')
            defaults.append(row)
        else:
            if not isinstance(priority,str) or not re.fullmatch(r'[1-9][0-9]{0,4}',priority) or int(priority)>50000 or int(priority) in priorities or not conditions: return finish('RULE_PRIORITY_OR_CONDITIONS_INVALID')
            priorities.add(int(priority)); ordered.append((int(priority),row))
    if len(defaults)!=1: return finish('DEFAULT_RULE_UNCONFIRMED')
    selected=defaults[0]
    for priority,row in sorted(ordered):
        states=[_condition(c,host,path) for c in row['Conditions']]
        fields=[c.get('Field') for c in row['Conditions'] if isinstance(c,dict)]
        if any(fields.count(f)>1 for f in ('host-header','path-pattern')):
            states=['UNKNOWN']
        state='NO_MATCH' if 'NO_MATCH' in states else 'UNKNOWN' if 'UNKNOWN' in states else 'MATCH'
        result['evaluated_rules'].append({'rule_id':_id(row['RuleArn']),'priority':priority,'status':state,'condition_statuses':states})
        if state=='UNKNOWN': return finish('EARLIER_RULE_UNRESOLVED')
        if state=='MATCH': selected=row; break
    result['selected_rule']={'id':_id(selected['RuleArn']),'priority':selected['Priority'],'is_default':selected['IsDefault']}
    result['rule_selection']='RULE_MATCH_CANDIDATE'
    if selected.get('Transforms') or set(selected)-{'RuleArn','Priority','IsDefault','Conditions','Actions','Transforms'}:
        return finish('RULE_TRANSFORM_OR_FIELDS_UNSUPPORTED')
    actions=selected['Actions']
    if len(actions)!=1 or not isinstance(actions[0],dict): return finish('RULE_ACTION_CHAIN_UNSUPPORTED')
    action=actions[0]; kind=action.get('Type'); result['action_type']=kind if kind in ('forward','redirect','fixed-response') else None
    if kind!='forward': return finish('RULE_ACTION_NOT_FORWARD')
    # Reuse existing forward validation with selected action in a temporary copy.
    listeners[0]['DefaultActions']=actions
    selected_config=inspect_load_balancer(inventory_raw,json.dumps(doc).encode(),load_balancer_id,listener_port)
    if selected_config['status']!='DEFAULT_FORWARD_CONFIG_CANDIDATE': return finish(selected_config['reason'])
    result['selected_target_groups']=selected_config['default_target_groups']
    return finish('OBSERVED_MATCHED_RULE_FORWARD_CONFIGURATION','RULE_FORWARD_CONFIG_CANDIDATE')
