"""Bounded, local root-module input snapshot. Never run Terraform or read referenced files."""
import base64
import binascii
import re
import tempfile
from pathlib import Path

MAX_FILES = 50
MAX_BYTES = 5 * 1024 * 1024
MAX_RESOURCES = 300
MAX_BODY = 8 * 1024 * 1024


def validate_files(files, *, allow_plan=False):
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError('Select 1..50 root .tf files')
    seen, result, total = set(), [], 0
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {'name', 'content_base64'}:
            raise ValueError('Invalid file entry')
        name, content = entry['name'], entry['content_base64']
        if (not isinstance(name, str) or not 1 <= len(name) <= 180 or not (name.endswith('.tf') or (allow_plan and name.endswith('.json')))
                or '/' in name or '\\' in name or ':' in name or any(ord(c)<32 or ord(c)==127 for c in name)):
            raise ValueError('Only root .tf filenames (or one Plan .json) accepted; no paths')
        if name.casefold() in seen:
            raise ValueError('Duplicate filename')
        seen.add(name.casefold())
        if name.lower() == 'override.tf' or name.lower().endswith('_override.tf'):
            raise ValueError('Terraform override files are not supported')
        if not isinstance(content, str) or len(content) > (MAX_BYTES+2)//3*4:
            raise ValueError('Invalid file content or size limit')
        try:
            raw = base64.b64decode(content, validate=True)
            raw.decode('utf-8')
        except (binascii.Error, UnicodeError) as exc:
            raise ValueError('Invalid base64 or UTF-8') from exc
        total += len(raw)
        if total > MAX_BYTES:
            raise ValueError('Total file size exceeds 5 MiB')
        result.append((name, raw))
    if allow_plan and any(n.endswith('.json') for n,_ in result) and len(result)!=1:
        raise ValueError('Select exactly one Plan JSON, without .tf files')
    return result


def inspect_document(doc):
    """Conservative gate: show partial graphs, prohibit session verdicts for unresolved expansion."""
    reasons = set()
    for key in ('module', 'data', 'moved', 'removed', 'import', 'ephemeral'):
        if doc.get(key):
            reasons.add(f'Unsupported root block: {key}')
    def walk(v):
        if isinstance(v, dict):
            for key, child in v.items():
                if str(key).strip('"') in ('count', 'for_each', 'dynamic'):
                    reasons.add('Unexpanded count / for_each / dynamic block')
                walk(child)
        elif isinstance(v, list):
            for x in v: walk(x)
        elif isinstance(v, str) and ('${' in v or '%{' in v):
            # Only simple, unindexed resource references are understood by current analyzers.
            if not re.fullmatch(r'\$\{\s*aws_[A-Za-z0-9_]+\.[\w-]+(?:\.[\w-]+)*\s*\}', v.strip('"')):
                reasons.add('Unresolved Terraform expression (variables, locals, functions or indexed references)')
    walk(doc.get('resource', []))
    return sorted(reasons)


def load_snapshot(files):
    items = validate_files(files, allow_plan=True)
    if items[0][0].endswith('.json'):
        from backend.iac.plan_adapter import load_plan, _read
        from backend.aws.snapshot import FORMAT, load_aws_snapshot
        doc = _read(items[0][1])
        if isinstance(doc.get('analysis_type'), str) and doc['analysis_type'].startswith('STATIC_'):
            raise ValueError('Saved analysis result JSON: use Packet Trace result import; configuration unchanged')
        if doc.get('format') == FORMAT:
            return load_aws_snapshot(items[0][1], items[0][0], MAX_RESOURCES)
        return load_plan(items[0][1], items[0][0], MAX_RESOURCES)
    from backend.iac.terraform_parser import parse_terraform
    from backend.iac.input_identity import input_identity
    import hcl2
    resources, reasons = [], set()
    with tempfile.TemporaryDirectory(prefix='cloudpath-input-') as tmp:
        paths = []
        for i, (name, raw) in enumerate(items):
            # Use generated names only; user names are never filesystem paths.
            p = Path(tmp) / f'{i}.tf'
            p.write_bytes(raw)
            try:
                with p.open(encoding='utf-8') as f: doc = hcl2.load(f)
                reasons.update(inspect_document(doc))
                resources.extend(parse_terraform(p))
            except Exception as exc:
                # Do not echo HCL content or parser exception (may contain secrets).
                raise ValueError(f'HCL parsing failed in {name}') from exc
            if len(resources) > MAX_RESOURCES:
                raise ValueError('Resource limit: 300 declarations')
            paths.append(p)
        identity = input_identity(paths)
    if not resources:
        raise ValueError('No resource declarations found')
    ids = {r.id for r in resources}
    if len(ids) != len(resources):
        raise ValueError('Duplicate Terraform resource IDs')
    from backend.analyzer.reference_graph_analyzer import analyze_reference_graph
    refs = analyze_reference_graph(resources)
    if refs['external_inputs'] or any(x.get('code') == 'UNRESOLVED_RESOURCE_REFERENCE' for x in refs['issues']):
        reasons.add('Unresolved external or missing resource reference')
    if any(r.provider != 'aws' for r in resources):
        reasons.add('Non-AWS resource declarations are outside current analysis scope')
    if any('provider' in r.attributes for r in resources):
        reasons.add('Explicit resource provider selection is not modeled')
    return resources, identity, {'files':[{'name':n,'bytes':len(b)} for n,b in items],
        'resource_count':len(resources), 'analysis_restricted':bool(reasons), 'warnings':sorted(reasons)}
