"""Phase 3-2: offline graph rendering with safe, limited resource display metadata."""

import json
import re
from ipaddress import ip_address
from pathlib import Path
from backend.output.policy_display import build_policy_display

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "frontend" / "static" / "topology_viewer.html"

# Display-only. Never blindly include all Terraform attributes (may contain secrets).
DISPLAY_FIELDS = ("cidr_block", "availability_zone")


def build_resource_display(resources) -> dict[str, dict]:
    """Expose only presentation-safe fields; unresolved Terraform expressions stay unresolved.

    This does not resolve variables/modules and never modifies the routing model.
    """
    resources = list(resources)
    policies = build_policy_display(resources)
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
        # Observed attachment facts are display-only. An allocation ID is required
        # before a public address can be labelled EIP; absence is not proof of auto-assignment.
        if resource.resource_type == "network_interface":
            device = attributes.get("observed_device_index")
            if type(device) is int and 0 <= device <= 255:
                display["device_index"] = device
            if type(attributes.get("requester_managed")) is bool:
                display["requester_managed"] = attributes["requester_managed"]
            associations = attributes.get("observed_address_associations")
            if isinstance(associations, list):
                rows = []
                for item in associations:
                    if not isinstance(item, dict) or not isinstance(item.get("association"), dict):
                        continue
                    a = item["association"]
                    private, public = known_ip(item.get("private_ip")), known_ip(a.get("PublicIp"))
                    if not private or not public:
                        continue
                    allocation = a.get("AllocationId")
                    row = {"private_ip": private, "public_ip": public, "kind": "PUBLIC_IP_TYPE_UNKNOWN"}
                    if isinstance(allocation, str) and re.fullmatch(r"eipalloc-[0-9a-f]{8,17}", allocation):
                        row.update(kind="EIP_ASSOCIATION", allocation_id=allocation)
                    if row not in rows:
                        rows.append(row)
                # Keep conflicting evidence visible, not an invented single mapping.
                display["public_addresses"] = rows
        if resource.resource_type == "nat_gateway":
            addresses = attributes.get("observed_nat_addresses")
            if isinstance(addresses, list):
                rows = []
                for item in addresses:
                    if not isinstance(item, dict):
                        continue
                    eni = item.get("NetworkInterfaceId")
                    if not isinstance(eni, str) or not re.fullmatch(r"eni-[0-9a-f]{8,17}", eni):
                        continue
                    row = {"eni_id": "aws_network_interface." + eni}
                    for source, dest in (("PrivateIp", "private_ip"), ("PublicIp", "public_ip")):
                        if value := known_ip(item.get(source)):
                            row[dest] = value
                    alloc = item.get("AllocationId")
                    if isinstance(alloc, str) and re.fullmatch(r"eipalloc-[0-9a-f]{8,17}", alloc):
                        row["allocation_id"] = alloc
                    if item.get("Status") == "succeeded":
                        row["associated"] = True
                    if row not in rows:
                        rows.append(row)
                display["nat_addresses"] = rows
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
        if resource.id in policies:
            display["policy_details"] = policies[resource.id]
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

