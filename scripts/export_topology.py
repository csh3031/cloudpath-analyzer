"""Export deployment-free Terraform infrastructure topology to interactive HTML."""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.iac.terraform_parser import parse_terraform
from backend.iac.input_identity import input_identity
from backend.analyzer.graph_analyzer import analyze_graphs
from backend.output.topology_html import build_resource_display, render_topology_html


def main():
    parser = argparse.ArgumentParser(description="CloudPath Analyzer Phase 3-2 HTML exporter")
    parser.add_argument("--terraform", action="append", help="Terraform HCL file (repeatable)")
    parser.add_argument("--output", default="outputs/topology.html", help="Generated offline HTML file")
    parser.add_argument("--trace", action="append", default=[], help="Phase 4-4 JSON to embed (repeatable; review sensitive data before sharing HTML)")
    args = parser.parse_args()
    terraform = [Path(p) for p in (args.terraform or ["samples/terraform/main.tf"])]
    terraform = [p if p.is_absolute() else PROJECT_ROOT / p for p in terraform]
    target = Path(args.output)
    if not target.is_absolute():
        target = PROJECT_ROOT / target

    identity = input_identity(terraform)
    resources = [r for path in terraform for r in parse_terraform(path)]
    if input_identity(terraform) != identity:
        parser.error("Terraform inputs changed while reading")
    if len({r.id for r in resources}) != len(resources):
        parser.error("duplicate Terraform resource addresses")
    graphs = analyze_graphs(resources)
    display = build_resource_display(resources)
    traces = []
    for raw in args.trace:
        path = Path(raw)
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        if path.stat().st_size > 5 * 1024 * 1024:
            parser.error(f"Trace exceeds 5 MiB: {path}")
        traces.append({"name": path.name, "result": json.loads(path.read_text(encoding="utf-8"))})
    result = render_topology_html(graphs, target, resource_display=display, packet_traces=traces, input_identity=identity)
    print(f"[OK] HTML topology generated: {result}")
    for name, graph in graphs.items():
        print(f"  {name}: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges, {len(graph.get('issues', []))} issues")
    print("Note: configuration links are NOT packet paths; unresolved Terraform values remain unresolved.")


if __name__ == "__main__":
    main()

