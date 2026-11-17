"""AWS 가상 인프라의 구성·배치·정책 연결 그래프 (Phase 2-5).

이 그래프는 topology/configuration graph이지 packet forwarding graph가 아니다.
모든 edges의 packet_traversable=False. 데이터가 불충분할 때
없는 리소스·연결을 추론해 만들어내지 않는다.
"""

from typing import Any, Sequence

from backend.analyzer.routing_analyzer import find_route_table, get_reference


VISIBLE_TYPES = {
    "vpc", "subnet", "route_table", "default_route_table", "internet_gateway",
    "nat_gateway", "instance", "network_interface", "security_group",
    "network_acl",
}

# 자원 속성에서 부모가 되는 리소스를 식별할 수 있는 경우에만 연결한다.
PARENT_RELATIONS = {
    "subnet": ("vpc_id", {"vpc"}, "contains", "structure"),
    "route_table": ("vpc_id", {"vpc"}, "contains", "structure"),
    "default_route_table": ("default_route_table_id", {"vpc"}, "contains", "structure"),
    "internet_gateway": ("vpc_id", {"vpc"}, "attached_to", "attachment"),
    "nat_gateway": ("subnet_id", {"subnet"}, "contains", "structure"),
    "instance": ("subnet_id", {"subnet"}, "contains", "structure"),
    "network_interface": ("subnet_id", {"subnet"}, "contains", "structure"),
    "security_group": ("vpc_id", {"vpc"}, "contains", "structure"),
    "network_acl": ("vpc_id", {"vpc"}, "contains", "structure"),
}

TARGET_KEYS = (
    "gateway_id", "nat_gateway_id", "transit_gateway_id",
    "vpc_peering_connection_id", "network_interface_id", "instance_id",
    "egress_only_gateway_id", "local_gateway_id", "carrier_gateway_id",
    "vpc_endpoint_id", "target",
)


def _issue(code: str, reason: str, **fields) -> dict:
    return {"status": "UNKNOWN", "code": code, "reason": reason, **fields}


def analyze_network_graph(resources: Sequence[Any]) -> dict:
    """배치/연결/정책 적용 관계를 생성한다. 실제 패킷 홉을 만들지 않는다."""
    index = {r.id: r for r in resources}
    nodes: dict[str, dict] = {}
    edges: dict[tuple[str, str, str, str], dict] = {}
    issues: list[dict] = []
    route_rules: list[dict] = []

    if len(index) != len(resources):
        issues.append(_issue("DUPLICATE_RESOURCE_ID", "동일한 리소스 ID가 중복되었습니다."))

    for res in sorted(index.values(), key=lambda item: item.id):
        if res.resource_type not in VISIBLE_TYPES:
            continue
        nodes[res.id] = {
            "id": res.id,
            "resource_type": "route_table" if res.resource_type == "default_route_table" else res.resource_type,
            "original_resource_type": res.resource_type,
            "name": res.name,
            "provider": res.provider,
            "synthetic": False,
        }

    def add_edge(source: str, target: str, relation: str, kind: str, **extra):
        if source not in nodes or target not in nodes:
            issues.append(_issue(
                "UNRESOLVED_TOPOLOGY_LINK",
                "연결 양쪽의 리소스를 확인할 수 없어 표시하지 않았습니다.",
                source=source, target=target, relation=relation,
            ))
            return
        key = (source, target, relation, kind)
        if key not in edges:
            edges[key] = {
                "source": source,
                "target": target,
                "relation": relation,
                "kind": kind,
                "packet_traversable": False,
                **extra,
            }

    def resolve_parent(res, attr: str, expected: set[str]) -> str | None:
        raw = res.attributes.get(attr)
        if raw is None:
            return None
        ref = get_reference(raw)
        if not ref or ref not in index:
            issues.append(_issue(
                "UNRESOLVED_PARENT_REFERENCE",
                "부모 리소스 참조가 없거나 해석되지 않습니다.",
                resource=res.id, attribute=attr,
            ))
            return None
        if index[ref].resource_type not in expected:
            issues.append(_issue(
                "WRONG_PARENT_TYPE",
                "참조한 부모 리소스의 유형이 올바르지 않습니다.",
                resource=res.id, parent=ref, attribute=attr,
            ))
            return None
        return ref

    # 1. 네트워크 구조와 구성 리소스의 배치만 연결한다.
    for res in sorted(index.values(), key=lambda r: r.id):
        if res.id not in nodes or res.resource_type not in PARENT_RELATIONS:
            continue
        attr, expected, relation, kind = PARENT_RELATIONS[res.resource_type]
        parent = resolve_parent(res, attr, expected)
        if parent:
            add_edge(parent, res.id, relation, kind)

    # 2. Subnet에 적용되는 Route Table은 routing_analyzer와 같은 선택 규칙 사용.
    for subnet in sorted(
        (r for r in index.values() if r.resource_type == "subnet"),
        key=lambda r: r.id,
    ):
        vpc = get_reference(subnet.attributes.get("vpc_id"))
        if not vpc or vpc not in index or index[vpc].resource_type != "vpc":
            continue
        table_id = find_route_table(resources, subnet.id)
        if not table_id:
            issues.append(_issue(
                "UNRESOLVED_ROUTE_TABLE_SELECTION",
                "적용 Route Table을 결정하지 못했습니다.", subnet=subnet.id,
            ))
            continue
        if table_id.startswith("implicit_main:"):
            expected_id = f"implicit_main:{vpc}"
            if table_id != expected_id:
                issues.append(_issue("CROSS_VPC_ROUTE_TABLE", "다른 VPC의 기본 테이블을 참조합니다.", subnet=subnet.id))
                continue
            if table_id not in nodes:
                nodes[table_id] = {
                    "id": table_id,
                    "resource_type": "route_table",
                    "original_resource_type": "implicit_main_route_table",
                    "name": "AWS 기본 Main Route Table (가상)",
                    "provider": "aws",
                    "synthetic": True,
                }
                add_edge(vpc, table_id, "contains", "structure", inferred=True)
            provenance = "implicit_main"
        elif table_id in index and index[table_id].resource_type in {"route_table", "default_route_table"}:
            table = index[table_id]
            table_vpc_attr = "default_route_table_id" if table.resource_type == "default_route_table" else "vpc_id"
            table_vpc = get_reference(table.attributes.get(table_vpc_attr))
            if table_vpc != vpc:
                issues.append(_issue(
                    "CROSS_VPC_ROUTE_TABLE",
                    "Subnet과 Route Table이 동일 VPC에 속하는지 확인할 수 없습니다.",
                    subnet=subnet.id, route_table=table_id,
                ))
                continue
            explicit = any(
                r.resource_type == "route_table_association"
                and get_reference(r.attributes.get("subnet_id")) == subnet.id
                for r in resources
            )
            provenance = "explicit" if explicit else (
                "managed_default" if table.resource_type == "default_route_table" else "main_override"
            )
        else:
            issues.append(_issue(
                "UNRESOLVED_ROUTE_TABLE",
                "Route Table 리소스를 찾지 못했습니다.",
                subnet=subnet.id, route_table=table_id,
            ))
            continue
        add_edge(subnet.id, table_id, "uses_route_table", "routing_configuration", selection=provenance)

    # 3. 보안그룹 참조는 정책 적용 관계이지 패킷 전송 홉이 아니다.
    for res in sorted(index.values(), key=lambda r: r.id):
        if res.resource_type not in {"instance", "network_interface"}:
            continue
        for field in ("vpc_security_group_ids", "security_groups"):
            raw_ids = res.attributes.get(field, []) or []
            if not isinstance(raw_ids, list):
                raw_ids = [raw_ids]
            for value in raw_ids:
                sg_id = get_reference(value)
                if sg_id and sg_id in index and index[sg_id].resource_type == "security_group":
                    add_edge(sg_id, res.id, "applies_to", "policy_attachment")
                else:
                    issues.append(_issue(
                        "UNRESOLVED_SECURITY_GROUP",
                        "Security Group 적용 관계를 확인할 수 없습니다.",
                        resource=res.id, attribute=field,
                    ))

    # 4. 라우팅 규칙은 별도 데이터로 보존한다. Route Table -> Gateway 연결선을
    #    실제 패킷 이동선으로 만들지 않는다.
    def record_route(table_id: str, source: str, route: dict):
        destination = route.get("cidr_block") or route.get("destination_cidr_block")
        destinations_other = [k for k in ("destination_prefix_list_id", "ipv6_cidr_block", "destination_ipv6_cidr_block") if route.get(k)]
        targets = [(key, route[key]) for key in TARGET_KEYS if route.get(key) is not None]
        status = "RESOLVED"
        target = None
        target_kind = targets[0][0] if len(targets) == 1 else None
        if len(targets) != 1 or (destination is None and not destinations_other):
            status = "UNKNOWN"
        elif target_kind == "target" and targets[0][1] == "local":
            target = "local"
        elif target_kind == "gateway_id" and targets[0][1] == "local":
            target = "local"
        else:
            target = get_reference(targets[0][1])
            if target not in index:
                status = "UNKNOWN"
        if destination is None:
            status = "UNKNOWN"  # IPv4 이외 경로는 추후 단계에서 해석
        record = {
            "route_table": table_id,
            "source": source,
            "destination": destination,
            "target": target,
            "target_kind": target_kind,
            "status": status,
            "packet_traversable": False,
        }
        route_rules.append(record)
        if status == "UNKNOWN":
            issues.append(_issue(
                "UNRESOLVED_ROUTE_RULE", "라우팅 대상 또는 목적지 조건을 해석하지 못했습니다.",
                route_table=table_id, source=source,
            ))

    for res in sorted(index.values(), key=lambda r: r.id):
        if res.resource_type in {"route_table", "default_route_table"}:
            inline = res.attributes.get("route", []) or []
            if isinstance(inline, list):
                for route in inline:
                    if isinstance(route, dict):
                        record_route(res.id, res.id, route)
                    else:
                        issues.append(_issue("INVALID_ROUTE_BLOCK", "Route Block 형식이 올바르지 않습니다.", route_table=res.id))
            else:
                issues.append(_issue("INVALID_ROUTE_BLOCK", "Route Block이 목록이 아닙니다.", route_table=res.id))
        elif res.resource_type == "route":
            table_id = get_reference(res.attributes.get("route_table_id"))
            if table_id not in nodes or not table_id or nodes[table_id]["resource_type"] != "route_table":
                issues.append(_issue(
                    "UNRESOLVED_ROUTE_TABLE", "독립 Route의 Route Table 참조가 유효하지 않습니다.",
                    resource=res.id,
                ))
            else:
                record_route(table_id, res.id, res.attributes)

    return {
        "graph_type": "network_configuration_topology",
        "nodes": [nodes[k] for k in sorted(nodes)],
        "edges": [edges[k] for k in sorted(edges)],
        "route_rules": sorted(route_rules, key=lambda item: (item["route_table"], item["source"], str(item["destination"]))),
        "issues": issues,
        "metadata": {
            "packet_path_available": False,
            "all_edges_are_configuration_relationships": True,
            "note": "Topology는 인프라 배치와 정책 관계이며 패킷 경유 경로가 아닙니다.",
        },
    }
