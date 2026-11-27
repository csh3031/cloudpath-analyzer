"""Local-only static IaC analysis web application. No AWS or Terraform execution."""
import argparse
import json
import secrets
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit
import base64

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.analyzer.forwarding_analyzer import _endpoint, _ip
from backend.analyzer.session_analyzer import analyze_session
from backend.iac.upload_snapshot import validate_files, load_snapshot, MAX_BODY, MAX_BYTES, MAX_FILES
from backend.models.diagnostics import CommunicationScenario
from backend.analyzer.graph_analyzer import analyze_graphs
from backend.output.topology_html import build_resource_display, render_topology_html

FLAGS = ('complete_config', 'complete_nacl_config', 'complete_routing_config',
         'assume_direct_private', 'assume_tracked_response', 'assume_unmodified_default_nacl')
FIELDS = {'source', 'destination', 'protocol', 'source_port', 'destination_port', 'input_identity', *FLAGS}

class AnalysisApp:
    def __init__(self, resources, identity, snapshot=None, *, aws_raw=None):
        self.resources = resources
        self.identity = identity
        self.snapshot = snapshot or {"files":[], "resource_count":len(resources), "analysis_restricted":False, "warnings":[]}
        self._aws_raw = None
        if aws_raw is not None:
            from backend.aws.snapshot import load_aws_snapshot
            if self.snapshot.get('input_type') != 'AWS_INVENTORY_JSON' or not isinstance(aws_raw, bytes) or load_aws_snapshot(aws_raw)[1] != identity:
                raise ValueError('AWS inventory identity mismatch')
            self._aws_raw = aws_raw
        self.token = secrets.token_urlsafe(32)
        index = {r.id:r for r in resources}
        if len(index) != len(resources):
            raise ValueError('Duplicate Terraform resource IDs')
        self.endpoints = []
        for r in resources:
            a = r.attributes
            values = a.get('private_ips', [])
            if not isinstance(values, list):
                continue
            for raw in [a.get('private_ip'), *values]:
                ip = _ip(raw)
                if ip is None:
                    continue
                context = _endpoint(index, r.id, ip)
                if context:
                    item = {'resource':r.id, 'ip':str(ip), 'subnet':context[1].id, 'vpc':context[2].id}
                    if item not in self.endpoints:
                        self.endpoints.append(item)
        self.endpoints.sort(key=lambda x:(x['resource'], x['ip']))
        if self._aws_raw is not None:
            self.endpoints = [e for e in self.endpoints if e['resource'].startswith('aws_instance.')]
            self.snapshot = {**self.snapshot, 'aws_static_session_available': True, 'aws_egress_available': True}
        with tempfile.TemporaryDirectory() as tmp:
            graphs = analyze_graphs(resources)
            if self.snapshot.get('input_type') in ('TERRAFORM_PLAN_JSON','AWS_INVENTORY_JSON'):
                # HCL analyzer may synthesize an implicit main table; never assert it for Plan.
                network = graphs['network_graph']
                synthetic = {n['id'] for n in network['nodes'] if n.get('synthetic')}
                network['nodes'] = [n for n in network['nodes'] if n['id'] not in synthetic]
                network['edges'] = [e for e in network['edges'] if e['source'] not in synthetic and e['target'] not in synthetic]
                network['route_rules'] = [r for r in network['route_rules'] if r['route_table'] not in synthetic]
                graphs['reference_graph']['metadata']['note'] = 'Resolved ID relationships, not Terraform expression dependencies'
                if self.snapshot.get('input_type') == 'AWS_INVENTORY_JSON':
                    network['metadata']['note'] = 'AWS configuration inventory; not a packet trace or verified live state'

            p = render_topology_html(graphs, Path(tmp)/'index.html',
                resource_display=build_resource_display(resources), input_identity=identity)
            self.html = p.read_bytes()

    def context(self):
        return {'input_identity':self.identity, 'endpoints':self.endpoints, 'token':self.token, 'snapshot':self.snapshot}

    def analyze(self, data):
        if self.snapshot["analysis_restricted"]:
            raise ValueError("Unresolved or inventory-only configuration: session analysis restricted")
        if not isinstance(data, dict) or set(data) != FIELDS:
            raise ValueError('Invalid analysis fields')
        if data['input_identity'] != self.identity:
            raise ValueError('Input identity mismatch; reload page')
        for key in ('source', 'destination'):
            if type(data[key]) is not int or not 0 <= data[key] < len(self.endpoints):
                raise ValueError('Invalid endpoint selection')
        a, b = self.endpoints[data['source']], self.endpoints[data['destination']]
        if a['resource'] == b['resource'] or a['ip'] == b['ip']:
            raise ValueError('Select distinct endpoints and addresses')
        if data['protocol'] not in ('tcp','udp'):
            raise ValueError('Unsupported protocol')
        for key in ('source_port','destination_port'):
            if type(data[key]) is not int or not 1 <= data[key] <= 65535:
                raise ValueError('Ports must be integers 1..65535')
        if any(type(data[k]) is not bool for k in FLAGS):
            raise ValueError('Assumptions must be booleans')
        scenario = CommunicationScenario(source_subnet=a['subnet'], source_resource=a['resource'],
            source_ip=a['ip'], destination_resource=b['resource'], destination_ip=b['ip'],
            protocol=data['protocol'], source_port=data['source_port'], destination_port=data['destination_port'],
            **{k:data[k] for k in FLAGS if k not in ('complete_routing_config','assume_tracked_response')})
        resources = self.resources
        if self.snapshot.get('input_type')=='TERRAFORM_PLAN_JSON':
            # Validated Plan contains an explicit local route. The legacy HCL
            # router already inserts that route; preserve the display model.
            from dataclasses import replace
            resources = [replace(r, attributes={**r.attributes, 'route': []})
                         if r.resource_type=='route_table' else r for r in resources]
        result = analyze_session(resources, scenario, complete_routing_config=data['complete_routing_config'],
                                 assume_tracked_response=data['assume_tracked_response'])
        result['input_identity'] = self.identity
        if self.snapshot.get('input_type')=='TERRAFORM_PLAN_JSON':
            result['input_type']='TERRAFORM_PLAN_JSON'
            result['plan_session_scope']=self.snapshot.get('plan_session_scope')
            result['session_trace']['limitations'].append('Plan prediction only; known planned values and explicit completeness assumptions, not deployed AWS state.')
        return result

    def analyze_aws(self, data):
        if self._aws_raw is None:
            raise ValueError('AWS snapshot required')
        if not isinstance(data, dict) or set(data) != {'source','destination','protocol','source_port','destination_port','input_identity'}:
            raise ValueError('Invalid AWS analysis fields')
        if data['input_identity'] != self.identity or data['protocol'] != 'tcp':
            raise ValueError('AWS identity mismatch or unsupported protocol')
        for k in ('source','destination'):
            if type(data[k]) is not int or not 0 <= data[k] < len(self.endpoints):
                raise ValueError('Invalid endpoint selection')
        a,b = (self.endpoints[data[k]] for k in ('source','destination'))
        if a['resource'] == b['resource'] or a['ip'] == b['ip']:
            raise ValueError('Select distinct endpoints')
        for k in ('source_port','destination_port'):
            if type(data[k]) is not int or not 1 <= data[k] <= 65535:
                raise ValueError('Invalid TCP port')
        from backend.aws.session_evidence import analyze_observed_session
        result = analyze_observed_session(self._aws_raw,a['ip'],b['ip'],data['source_port'],data['destination_port'])
        if result['input_identity'] != self.identity:
            raise ValueError('Result identity mismatch')
        # Resource inspection, not synthetic packet edges. Only known graph IDs.
        known = {r.id for r in self.resources}
        endpoints = result['evidence']['forwarding']['endpoints']
        for f in result['findings']:
            e = f['evidence']; stage = f['stage']; ids = []
            src,dst = ('source','destination') if f['direction']=='request' else ('destination','source')
            def add_endpoint(key, fields):
                ep = endpoints[key]
                for field, prefix in fields:
                    if ep.get(field): ids.append(prefix+ep[field])
            if stage == 'ENDPOINT_SCOPE':
                for key in (src,dst):
                    add_endpoint(key, [('instance_id','aws_instance.'), ('eni_id','aws_network_interface.'), ('subnet_id','aws_subnet.')])
            elif stage == 'ROUTE_LOOKUP':
                rid = (e.get('route_lookup') or {}).get('route_table_id')
                if rid: ids.append('aws_route_table.'+rid)
                add_endpoint(src, [('subnet_id','aws_subnet.')])
            elif '_SG_' in stage:
                key = src if stage.startswith('SOURCE') else dst
                ep = endpoints[key]
                ids += ['aws_security_group.'+g for g in ep.get('security_group_ids', [])]
                add_endpoint(key, [('eni_id','aws_network_interface.'), ('instance_id','aws_instance.')])
            elif e.get('acl_id'):
                ids.append('aws_network_acl.'+e['acl_id'])
                add_endpoint(src if stage.startswith('SOURCE') else dst, [('subnet_id','aws_subnet.')])
            f['web_resource_ids'] = sorted(set(ids) & known)
        return result


    def analyze_aws_egress(self, data):
        from ipaddress import IPv4Address
        from backend.aws.egress_session_evidence import analyze_internet_egress_session
        if self._aws_raw is None:
            raise ValueError('AWS snapshot required')
        fields = {'source','destination_ip','protocol','source_port','destination_port','input_identity'}
        if not isinstance(data, dict) or set(data) != fields or data['input_identity'] != self.identity or data['protocol'] != 'tcp':
            raise ValueError('Invalid egress request')
        if type(data['source']) is not int or not 0 <= data['source'] < len(self.endpoints):
            raise ValueError('Invalid endpoint selection')
        dst = data['destination_ip']
        if not isinstance(dst, str) or str(IPv4Address(dst)) != dst:
            raise ValueError('Expected IPv4 address')
        for k in ('source_port','destination_port'):
            if type(data[k]) is not int or not 1 <= data[k] <= 65535:
                raise ValueError('Invalid TCP port')
        result = analyze_internet_egress_session(self._aws_raw,self.endpoints[data['source']]['ip'],dst,data['source_port'],data['destination_port'])
        if result['input_identity'] != self.identity:
            raise ValueError('Result identity mismatch')
        return result

    def compare_aws_evidence(self, data):
        """Compare uploaded evidence against the current server snapshot and TCP tuple."""
        if not isinstance(data, dict) or set(data) != {'scenario', 'files'}:
            raise ValueError('Invalid evidence request')
        scenario, files = data['scenario'], data['files']
        if not isinstance(files, dict) or not files or set(files) - {'paths','analyses','logs'}:
            raise ValueError('Invalid evidence file roles')
        if ('paths' in files) != ('analyses' in files):
            raise ValueError('Reachability requires both path and analysis JSON')
        decoded = {}
        total = 0
        for role, value in files.items():
            if not isinstance(value, str) or len(value) > ((MAX_BYTES+2)//3)*4:
                raise ValueError('Evidence exceeds size limit')
            raw = base64.b64decode(value, validate=True)
            total += len(raw)
            if not raw or total > MAX_BYTES:
                raise ValueError('Evidence files must be nonempty, combined maximum 5 MiB')
            decoded[role] = raw
        static = self.analyze_aws(scenario)
        sc = static['scenario']
        args = (sc['source_ip'], sc['destination_ip'], sc['source_port'], sc['destination_port'])
        result = dict(analysis_type='AWS_EXTERNAL_EVIDENCE_COMPARISON', input_identity=self.identity,
                      scenario=sc, cloudpath_predicted=static['predicted_connectivity'],
                      cloudpath_conditional=static['conditional_connectivity'],
                      reachability=None, flow_logs=None, live_observation=False)
        if 'paths' in decoded:
            from backend.aws.reachability_evidence import compare_reachability
            result['reachability'] = compare_reachability(self._aws_raw, decoded['paths'], decoded['analyses'], *args)
        if 'logs' in decoded:
            from backend.aws.flow_log_evidence import correlate_flow_logs
            result['flow_logs'] = correlate_flow_logs(self._aws_raw, decoded['logs'], *args)
        for item in (result['reachability'], result['flow_logs']):
            if item is not None and (item['input_identity'] != self.identity or item['scenario'] != sc or
                    item['cloudpath_predicted'] != result['cloudpath_predicted'] or
                    item['cloudpath_conditional'] != result['cloudpath_conditional']):
                raise ValueError('Evidence comparison mismatch')
        return result


def load_web_app(files):
    resources, identity, snapshot = load_snapshot(files)
    raw = validate_files(files, allow_plan=True)[0][1] if snapshot.get('input_type') == 'AWS_INVENTORY_JSON' else None
    return AnalysisApp(resources, identity, snapshot, aws_raw=raw)


def create_server(app, port=8001):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)
        def reply(self, status, data, mime='application/json; charset=utf-8'):
            if not isinstance(data, bytes):
                data = json.dumps(data, ensure_ascii=False).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(data)
        def host_ok(self):
            p = self.server.server_port
            return self.headers.get('Host') in (f'127.0.0.1:{p}', f'localhost:{p}')
        def do_GET(self):
            if not self.host_ok():
                return self.reply(403, {'error':'Invalid Host'})
            if urlsplit(self.path).path == '/':
                return self.reply(200, app.html, 'text/html; charset=utf-8')
            if urlsplit(self.path).path == '/peering':
                return self.reply(200, (ROOT/'frontend/static/peering_viewer.html').read_bytes(), 'text/html; charset=utf-8')
            if urlsplit(self.path).path == '/tgw':
                return self.reply(200, (ROOT/'frontend/static/tgw_viewer.html').read_bytes(), 'text/html; charset=utf-8')
            if urlsplit(self.path).path == '/api/context':
                return self.reply(200, app.context())
            return self.reply(404, {'error':'Not found'})
        def do_POST(self):
            nonlocal app
            if not self.host_ok() or self.headers.get('Origin') != 'http://' + self.headers.get('Host','') or not secrets.compare_digest(self.headers.get('X-CloudPath-Token',''),app.token):
                return self.reply(403, {'error':'Local origin/token required'})
            path = urlsplit(self.path).path
            if path not in ('/api/analyze', '/api/aws-analyze', '/api/aws-egress', '/api/aws-evidence', '/api/upload', '/api/aws-peering', '/api/aws-tgw'):
                return self.reply(404, {'error':'Not found'})
            try:
                length = int(self.headers.get('Content-Length','0'))
                limit = MAX_BODY if path in ('/api/upload','/api/aws-evidence','/api/aws-peering','/api/aws-tgw') else 16384
                if not 0 < length <= limit or self.headers.get_content_type() != 'application/json' or self.headers.get('Transfer-Encoding'):
                    raise ValueError('JSON body required within size limit')
                body = json.loads(self.rfile.read(length))
                if path == '/api/upload':
                    if not isinstance(body, dict) or set(body) != {'input_identity','files'} or body['input_identity'] != app.identity:
                        raise ValueError('Stale input; reload the page')
                    # Commit only after successful parsing, indexing and rendering.
                    candidate = load_web_app(body['files'])
                    app = candidate
                    result = app.context()
                elif path == '/api/aws-analyze':
                    result = app.analyze_aws(body)
                elif path == '/api/aws-egress':
                    result = app.analyze_aws_egress(body)
                elif path == '/api/aws-peering':
                    from backend.aws.peering_web import analyze_peering_upload
                    result = analyze_peering_upload(body, app.identity)
                elif path == '/api/aws-tgw':
                    from backend.aws.tgw_web import analyze_tgw_upload
                    result = analyze_tgw_upload(body, app.identity)
                elif path == '/api/aws-evidence':
                    result = app.compare_aws_evidence(body)
                else:
                    result = app.analyze(body)
            except (ValueError, TypeError, UnicodeError, TimeoutError) as exc:
                if path == '/api/upload':
                    return self.reply(400, {'error':str(exc) if isinstance(exc, ValueError) else 'Invalid upload'})
                if path == '/api/aws-evidence':
                    return self.reply(400, {'error':'Invalid evidence format, size, current input or TCP scenario; verify file roles.'})
                return self.reply(400, {'error':'Invalid request, input identity, endpoint, port or assumption'})
            except Exception:
                return self.reply(500, {'error':'Analysis failed; no result generated'})
            return self.reply(200, result)
    return HTTPServer(('127.0.0.1', port), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--terraform', action='append', help='Root .tf files (repeat) or a single Plan or AWS inventory .json')
    parser.add_argument('--port', type=int, default=8001)
    args = parser.parse_args()
    paths = [Path(p).resolve() for p in (args.terraform or [ROOT/'samples/terraform/session_demo.tf'])]
    if len(paths)>MAX_FILES or any(p.suffix not in ('.tf','.json') or not p.is_file() for p in paths) or sum(p.stat().st_size for p in paths)>MAX_BYTES:
        parser.error('Select 1..50 .tf files or one Plan or AWS inventory .json, total <=5 MiB')
    try:
        app = load_web_app([{'name':p.name,'content_base64':base64.b64encode(p.read_bytes()).decode('ascii')} for p in paths])
    except ValueError as exc:
        parser.error(str(exc))
    with create_server(app,args.port) as server:
        print(f'[OK] CloudPath local UI: http://localhost:{server.server_port}/ | endpoints={len(app.endpoints)}',flush=True)
        print('[INFO] Input snapshot replaceable via local upload; not persisted. No deployment or AWS API calls.',flush=True)
        try: server.serve_forever()
        except KeyboardInterrupt: pass

if __name__ == '__main__': main()
