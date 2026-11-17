#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/soldesk/cloudpath-analyzer"
ROUTING="$ROOT/backend/analyzer/routing_analyzer.py"
TESTS="$ROOT/tests/test_routing_edge_cases.py"
PYTHON="$ROOT/.venv/bin/python"

if [[ ! -f "$ROUTING" || ! -x "$PYTHON" || ! -f "$ROOT/tests/test_routing.py" ]]; then
  echo "[ERROR] CloudPath Analyzer 프로젝트 및 가상환경이 예상 경로에 없습니다: $ROOT" >&2
  exit 1
fi

STAMP="$(date +%Y%m%d_%H%M%S)"
cp -p "$ROUTING" "$ROUTING.bak_$STAMP"
if [[ -e "$TESTS" ]]; then
  cp -p "$TESTS" "$TESTS.bak_$STAMP"
fi

echo "[INFO] 기존 라우팅 분석 엔진 백업: $ROUTING.bak_$STAMP"
cat > "$ROUTING" <<'CLOUDPATH_ROUTING_PY'
import ipaddress
import re

REFERENCE_PATTERN = re.compile(
    r"^\$\{([a-zA-Z_][\w-]*\.[a-zA-Z_][\w-]*)\.[^}]+\}$"
)
IMPLICIT_MAIN_PREFIX = "implicit_main:"


def get_reference(value):
    """'${aws_vpc.main.id}' 등의 참조에서 리소스 주소를 추출한다."""
    if not isinstance(value, str):
        return None
    match = REFERENCE_PATTERN.fullmatch(value)
    return match.group(1) if match else None


def _unknown(subnet_id, destination_ip, reason, route_table=None, evidence=None):
    result = {
        "status": "UNKNOWN",
        "subnet": subnet_id,
        "destination": destination_ip,
        "reason": reason,
        "evidence": evidence or [],
    }
    if route_table is not None:
        result["route_table"] = route_table
    return result


def _resolve_route_table(resources, subnet_id):
    """(route_table_id, error_reason)를 반환한다."""
    subnet = next(
        (r for r in resources if r.id == subnet_id and r.resource_type == "subnet"),
        None,
    )
    if subnet is None:
        return None, "Subnet 리소스를 찾지 못했습니다."

    vpc_id = get_reference(subnet.attributes.get("vpc_id"))
    if vpc_id is None:
        return None, "Subnet의 VPC 참조를 해석할 수 없습니다."

    if not any(r.id == vpc_id and r.resource_type == "vpc" for r in resources):
        return None, "Subnet이 참조하는 VPC 리소스가 없습니다."

    explicit = [
        r for r in resources
        if r.resource_type == "route_table_association"
        and get_reference(r.attributes.get("subnet_id")) == subnet_id
    ]
    if len(explicit) > 1:
        return None, "Subnet에 대한 명시적 Route Table Association이 중복되었습니다."
    if explicit:
        table_id = get_reference(explicit[0].attributes.get("route_table_id"))
        if table_id is None:
            return None, "명시적 Route Table 참조를 해석할 수 없습니다."
        return table_id, None

    main = [
        r for r in resources
        if r.resource_type == "main_route_table_association"
        and get_reference(r.attributes.get("vpc_id")) == vpc_id
    ]
    defaults = [
        r for r in resources
        if r.resource_type == "default_route_table"
        and get_reference(r.attributes.get("default_route_table_id")) == vpc_id
    ]
    if len(main) + len(defaults) > 1:
        return None, "VPC의 Main Route Table 설정이 중복되거나 충돌합니다."
    if main:
        table_id = get_reference(main[0].attributes.get("route_table_id"))
        if table_id is None:
            return None, "Main Route Table 참조를 해석할 수 없습니다."
        return table_id, None
    if defaults:
        return defaults[0].id, None

    # 새로 정의한 VPC에는 AWS가 기본 Main Route Table을 생성한다고 가정한다.
    return f"{IMPLICIT_MAIN_PREFIX}{vpc_id}", None


def find_route_table(resources, subnet_id):
    """기존 호출부 호환용: Route Table 주소만 반환한다."""
    return _resolve_route_table(resources, subnet_id)[0]


def _validate_next_hop(route, resources):
    """(next_hop, error_reason)을 반환한다. 여기서는 경로 타깃의 정적 일관성만 확인한다."""
    supported = ("gateway_id", "nat_gateway_id", "target")
    unsupported = (
        "transit_gateway_id", "vpc_peering_connection_id", "network_interface_id",
        "instance_id", "egress_only_gateway_id", "local_gateway_id",
        "carrier_gateway_id", "core_network_arn", "vpc_endpoint_id",
    )
    if any(route.get(key) is not None for key in unsupported):
        return None, "지원하지 않는 Route Target 유형이 포함되어 있습니다."

    targets = [(key, route[key]) for key in supported if route.get(key) is not None]
    if len(targets) != 1:
        return None, "Route Target이 없거나 여러 개 지정되었습니다."
    key, value = targets[0]
    if key == "target":
        if value == "local":
            return "local", None
        return None, "지원하지 않거나 확인할 수 없는 Route Target입니다."
    if key == "gateway_id" and value == "local":
        return "local", None

    target_id = get_reference(value)
    if target_id is None:
        return None, "Route Target 참조를 해석할 수 없습니다."

    target_resource = next((r for r in resources if r.id == target_id), None)
    if target_resource is None:
        return None, f"Route Target 리소스가 없습니다: {target_id}"

    expected = "internet_gateway" if key == "gateway_id" else "nat_gateway"
    if target_resource.resource_type != expected:
        return None, (
            f"Route Target 유형을 확인할 수 없습니다: {target_resource.resource_type} "
            f"(현재 지원: {expected})"
        )
    return target_id, None


def analyze_route(resources, subnet_id, destination_ip):
    """IPv4 라우팅 정적 검증. ROUTE_FOUND는 실제 통신 성공이 아니다."""
    try:
        destination = ipaddress.ip_address(destination_ip)
    except (ValueError, TypeError):
        return _unknown(subnet_id, destination_ip, "목적지 IP 주소 형식이 올바르지 않습니다.")
    if destination.version != 4:
        return _unknown(subnet_id, destination_ip, "현재 IPv4 목적지 분석만 지원합니다.")

    table_id, error = _resolve_route_table(resources, subnet_id)
    if error:
        return _unknown(subnet_id, destination_ip, error)

    subnet = next(r for r in resources if r.id == subnet_id and r.resource_type == "subnet")
    subnet_vpc = get_reference(subnet.attributes.get("vpc_id"))

    implicit_main = table_id.startswith(IMPLICIT_MAIN_PREFIX)
    if implicit_main:
        table_vpc = table_id[len(IMPLICIT_MAIN_PREFIX):]
        routes = []
    else:
        table = next((r for r in resources if r.id == table_id), None)
        if table is None:
            return _unknown(subnet_id, destination_ip, "Route Table 리소스를 찾지 못했습니다.", table_id)
        if table.resource_type not in {"route_table", "default_route_table"}:
            return _unknown(subnet_id, destination_ip, "참조 대상이 Route Table이 아닙니다.", table_id)

        vpc_attribute = "default_route_table_id" if table.resource_type == "default_route_table" else "vpc_id"
        table_vpc = get_reference(table.attributes.get(vpc_attribute))
        inline = table.attributes.get("route", []) or []
        if not isinstance(inline, list) or not all(isinstance(r, dict) for r in inline):
            return _unknown(subnet_id, destination_ip, "Route Table의 route 블록을 해석할 수 없습니다.", table_id)
        routes = [dict(route, _source=table.id) for route in inline]

    if not table_vpc or table_vpc != subnet_vpc:
        return _unknown(subnet_id, destination_ip, "Subnet과 Route Table의 VPC가 다르거나 확인되지 않습니다.", table_id)

    for resource in resources:
        if resource.resource_type != "route":
            continue
        if get_reference(resource.attributes.get("route_table_id")) != table_id:
            continue
        routes.append({
            "cidr_block": resource.attributes.get("destination_cidr_block"),
            "gateway_id": resource.attributes.get("gateway_id"),
            "nat_gateway_id": resource.attributes.get("nat_gateway_id"),
            "transit_gateway_id": resource.attributes.get("transit_gateway_id"),
            "vpc_peering_connection_id": resource.attributes.get("vpc_peering_connection_id"),
            "network_interface_id": resource.attributes.get("network_interface_id"),
            "destination_prefix_list_id": resource.attributes.get("destination_prefix_list_id"),
            "_source": resource.id,
        })

    vpc = next((r for r in resources if r.id == subnet_vpc and r.resource_type == "vpc"), None)
    if vpc is None:
        return _unknown(subnet_id, destination_ip, "VPC 리소스를 찾지 못했습니다.", table_id)

    vpc_cidr = vpc.attributes.get("cidr_block")
    try:
        local_net = ipaddress.ip_network(vpc_cidr, strict=False)
        if local_net.version != 4:
            raise ValueError("VPC IPv4 CIDR required")
    except (ValueError, TypeError):
        return _unknown(subnet_id, destination_ip, "VPC CIDR이 유효한 IPv4 네트워크가 아닙니다.", table_id)

    routes.append({"cidr_block": str(local_net), "target": "local", "_source": f"{subnet_vpc}:implicit_local"})

    evidence = [{"check": "route_table_selection", "route_table": table_id}]
    matches = []
    for route in routes:
        source = route.get("_source", table_id)
        cidr = route.get("cidr_block")
        if cidr is None:
            if route.get("destination_prefix_list_id") or route.get("prefix_list_id"):
                return _unknown(subnet_id, destination_ip, f"Prefix List 경로를 아직 해석할 수 없습니다: {source}", table_id, evidence)
            if route.get("ipv6_cidr_block") or route.get("destination_ipv6_cidr_block"):
                continue
            return _unknown(subnet_id, destination_ip, f"Route의 IPv4 CIDR이 없습니다: {source}", table_id, evidence)

        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except (ValueError, TypeError):
            return _unknown(subnet_id, destination_ip, f"Route CIDR을 해석할 수 없습니다: {source} ({cidr})", table_id, evidence)
        if network.version == 4 and destination in network:
            matches.append((network, route, source))

    if not matches:
        return {
            "status": "NO_ROUTE",
            "subnet": subnet_id,
            "destination": destination_ip,
            "route_table": table_id,
            "reason": "목적지와 일치하는 IPv4 경로가 없습니다.",
            "evidence": evidence,
        }

    best_prefix = max(item[0].prefixlen for item in matches)
    best_matches = [item for item in matches if item[0].prefixlen == best_prefix]
    if len(best_matches) > 1:
        sources = ", ".join(item[2] for item in best_matches)
        return _unknown(
            subnet_id, destination_ip,
            f"최장 일치 Prefix에 경로가 중복되어 선택할 수 없습니다: {sources}",
            table_id, evidence,
        )

    network, selected, source = best_matches[0]
    evidence.append({"check": "longest_prefix_match", "cidr": str(network), "source": source})
    next_hop, error = _validate_next_hop(selected, resources)
    if error:
        return _unknown(subnet_id, destination_ip, f"{source}: {error}", table_id, evidence)

    evidence.append({"check": "next_hop", "target": next_hop})
    return {
        "status": "ROUTE_FOUND",
        "subnet": subnet_id,
        "destination": destination_ip,
        "route_table": table_id,
        "matched_cidr": str(network),
        "next_hop": next_hop,
        "reason": "일치하는 라우팅 규칙이 있습니다. 실제 통신 가능 여부는 별도 검증이 필요합니다.",
        "evidence": evidence,
    }
CLOUDPATH_ROUTING_PY

cat > "$TESTS" <<'CLOUDPATH_TEST_PY'
from copy import deepcopy

import pytest

from backend.iac.terraform_parser import parse_terraform
from backend.analyzer.routing_analyzer import analyze_route


SAMPLE = "samples/terraform/main.tf"


def load_resources():
    return parse_terraform(SAMPLE)


def find_resource(resources, resource_id):
    return next(resource for resource in resources if resource.id == resource_id)


def public_route(resources):
    table = find_resource(resources, "aws_route_table.public")
    return table.attributes["route"][0]


@pytest.mark.parametrize("destination", ["not-an-ip", "2001:db8::1"])
def test_invalid_or_unsupported_destination_is_unknown(destination):
    result = analyze_route(load_resources(), "aws_subnet.public", destination)
    assert result["status"] == "UNKNOWN"
    assert result["reason"]


def test_missing_subnet_is_unknown():
    result = analyze_route(load_resources(), "aws_subnet.missing", "8.8.8.8")
    assert result["status"] == "UNKNOWN"
    assert "Subnet" in result["reason"]


def test_missing_vpc_reference_is_unknown():
    resources = load_resources()
    find_resource(resources, "aws_subnet.public").attributes["vpc_id"] = (
        "${aws_vpc.missing.id}"
    )
    result = analyze_route(resources, "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "UNKNOWN"
    assert "VPC" in result["reason"]


def test_missing_route_table_is_unknown():
    resources = [
        resource for resource in load_resources()
        if resource.id != "aws_route_table.public"
    ]
    result = analyze_route(resources, "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "UNKNOWN"
    assert "Route Table" in result["reason"]


def test_duplicate_subnet_association_is_unknown():
    resources = load_resources()
    association = find_resource(resources, "aws_route_table_association.public")
    duplicate = deepcopy(association)
    duplicate.id = "aws_route_table_association.duplicate"
    resources.append(duplicate)
    result = analyze_route(resources, "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "UNKNOWN"
    assert "중복" in result["reason"]


def test_invalid_route_cidr_is_unknown():
    resources = load_resources()
    public_route(resources)["cidr_block"] = "invalid-cidr"
    result = analyze_route(resources, "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "UNKNOWN"
    assert "CIDR" in result["reason"]


def test_duplicate_matching_routes_are_unknown():
    resources = load_resources()
    table = find_resource(resources, "aws_route_table.public")
    table.attributes["route"].append(deepcopy(public_route(resources)))
    result = analyze_route(resources, "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "UNKNOWN"
    assert "중복" in result["reason"]


def test_longest_prefix_match_selects_more_specific_route():
    resources = load_resources()
    table = find_resource(resources, "aws_route_table.public")
    table.attributes["route"].append({
        "cidr_block": "8.8.8.0/24",
        "gateway_id": "${aws_internet_gateway.main.id}",
    })
    result = analyze_route(resources, "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "ROUTE_FOUND"
    assert result["matched_cidr"] == "8.8.8.0/24"


def test_route_without_target_is_unknown():
    resources = load_resources()
    public_route(resources).pop("gateway_id")
    result = analyze_route(resources, "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "UNKNOWN"
    assert "Target" in result["reason"]


def test_missing_next_hop_resource_is_unknown():
    resources = load_resources()
    public_route(resources)["gateway_id"] = "${aws_internet_gateway.missing.id}"
    result = analyze_route(resources, "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "UNKNOWN"
    assert "리소스" in result["reason"]


def test_unsupported_prefix_list_is_unknown_not_no_route():
    resources = load_resources()
    table = find_resource(resources, "aws_route_table.public")
    table.attributes["route"].append({
        "destination_prefix_list_id": "pl-example",
        "gateway_id": "${aws_internet_gateway.main.id}",
    })
    result = analyze_route(resources, "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "UNKNOWN"
    assert "Prefix List" in result["reason"]


def test_route_found_has_diagnostic_evidence():
    result = analyze_route(load_resources(), "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "ROUTE_FOUND"
    assert result["evidence"]
    checks = [item["check"] for item in result["evidence"]]
    assert "route_table_selection" in checks
    assert "longest_prefix_match" in checks
    assert "next_hop" in checks
CLOUDPATH_TEST_PY

cd "$ROOT"
echo "[INFO] Python 문법 검사 중..."
"$PYTHON" -m py_compile "$ROUTING" "$TESTS"
echo "[INFO] 전체 pytest 실행 중..."
"$PYTHON" -m pytest -v
