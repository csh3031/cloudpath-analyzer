"""Phase 3-2: offline graph rendering with safe, limited resource display metadata."""

import json
from ipaddress import ip_address
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "frontend" / "static" / "topology_viewer.html"

# Display-only. Never blindly include all Terraform attributes (may contain secrets).
DISPLAY_FIELDS = ("cidr_block", "availability_zone")


def build_resource_display(resources) -> dict[str, dict]:
    """Expose only presentation-safe fields; unresolved Terraform expressions stay unresolved.

    This does not resolve variables/modules and never modifies the routing model.
    """
    output = {}
    for resource in resources:
        attributes = resource.attributes
        if not isinstance(attributes, dict):
            continue
        display = {
            field: attributes[field]
            for field in DISPLAY_FIELDS
            if isinstance(attributes.get(field), str)
        }
        # Explicit presentation allowlist; never serialize arbitrary attributes or policy contents.
        if resource.resource_type in ("instance", "network_interface", "nat_gateway"):
            def known_ip(value):
                if not isinstance(value, str):
                    return None
                try:
                    return str(ip_address(value))
                except ValueError:
                    return None
            private_ip = known_ip(attributes.get("private_ip"))
            if private_ip:
                display["private_ip"] = private_ip
            values = attributes.get("private_ips")
            if isinstance(values, list):
                ips = list(dict.fromkeys(ip for value in values if (ip := known_ip(value))))
                if ips:
                    display["private_ips"] = ips
        enums = {
            "observed_state": {"available", "pending", "running", "stopping", "stopped", "shutting-down", "terminated", "in-use", "attaching", "detaching", "detached", "failed", "deleting", "deleted"},
            "connectivity_type": {"public", "private"},
            "observed_interface_type": {"interface", "nat_gateway", "load_balancer", "network_load_balancer", "vpc_endpoint", "lambda", "efa", "trunk", "branch"},
        }
        for field, allowed in enums.items():
            value = attributes.get(field)
            if isinstance(value, str) and value in allowed:
                display[field] = value
        if resource.resource_type in ("security_group", "network_acl"):
            for direction in ("ingress", "egress"):
                rules = attributes.get(direction)
                if isinstance(rules, list) and all(isinstance(rule, dict) for rule in rules):
                    display[direction + "_inline_count"] = len(rules)
        if display:
            output[resource.id] = display
    return output


def render_topology_html(
    graphs: dict,
    output_path: str | Path,
    template_path: str | Path | None = None,
    *,
    resource_display: dict[str, dict] | None = None,
    packet_traces: list[dict] | None = None,
    input_identity: str | None = None,
) -> Path:
    """Serialize pre-deployment configuration graphs into a self-contained viewer.

    Backwards-compatible with Phase 3-1 callers that only pass (graphs, path).
    A graph edge is a configuration relationship, not a traversed packet hop.
    """
    for key in ("network_graph", "reference_graph"):
        graph = graphs.get(key)
        if not isinstance(graph, dict):
            raise ValueError(f"Missing graph: {key}")
        if not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list):
            raise ValueError(f"Invalid nodes/edges in: {key}")

    payload_data = {
        "network_graph": graphs["network_graph"],
        "reference_graph": graphs["reference_graph"],
        "resource_display": resource_display or {},
        "packet_traces": packet_traces or [],
        "input_identity": input_identity,
    }
    template = Path(template_path) if template_path is not None else TEMPLATE
    html = template.read_text(encoding="utf-8")
    marker = "__CLOUDPATH_GRAPH_DATA__"
    if html.count(marker) != 1:
        raise ValueError("HTML template requires exactly one graph data placeholder")

    # Prevent closing the JSON script tag using malicious labels/values.
    payload = json.dumps(payload_data, ensure_ascii=False, separators=(",", ":"))
    payload = (payload.replace("&", "\\u0026")
                      .replace("<", "\\u003c")
                      .replace(">", "\\u003e")
                      .replace("\u2028", "\\u2028")
                      .replace("\u2029", "\\u2029"))
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(html.replace(marker, payload), encoding="utf-8")
    return target

