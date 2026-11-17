"""Phase 2-4: 다중 진단 오케스트레이터의 계약 테스트."""

import json

import pytest

from backend.analyzer.communication_analyzer import analyze_communication
from backend.models.diagnostics import CommunicationScenario, PolicyCheck, PolicyObservation
from backend.models.infrastructure import InfrastructureResource


def resource(resource_id, resource_type, **attributes):
    return InfrastructureResource(
        id=resource_id,
        provider="aws",
        type="network",
        resource_type=resource_type,
        name=resource_id.split(".")[-1],
        attributes=attributes,
    )


def network(*, has_default_route):
    routes = [{"cidr_block": "0.0.0.0/0", "gateway_id": "${aws_internet_gateway.main.id}"}] if has_default_route else []
    return [
        resource("aws_vpc.main", "vpc", cidr_block="10.0.0.0/16"),
        resource("aws_subnet.private", "subnet", vpc_id="${aws_vpc.main.id}", cidr_block="10.0.1.0/24"),
        resource("aws_internet_gateway.main", "internet_gateway", vpc_id="${aws_vpc.main.id}"),
        resource("aws_route_table.private", "route_table", vpc_id="${aws_vpc.main.id}", route=routes),
        resource("aws_route_table_association.private", "route_table_association",
                 subnet_id="${aws_subnet.private.id}", route_table_id="${aws_route_table.private.id}"),
    ]


def scenario(**overrides):
    data = {
        "source_subnet": "aws_subnet.private",
        "destination_ip": "8.8.8.8",
        "protocol": "tcp",
        "destination_port": 3306,
        "destination_resource": "aws_db_instance.main",
    }
    data.update(overrides)
    return CommunicationScenario(**data)


def observation(status, reason, resource="aws_db_instance.main"):
    return PolicyObservation(status=status, reason=reason, resource=resource)


def test_routing_blocker_and_two_additional_findings_collected():
    checks = [
        PolicyCheck("security_group", lambda _r, _s: [observation("BLOCKED", "3306 인바운드 누락")],
                    evaluation_mode="CONDITIONAL_CHECK", requires_destination_resource=True),
        PolicyCheck("network_acl", lambda _r, _s: [observation("WARNING", "검토가 필요한 NACL")]),
    ]
    result = analyze_communication(network(has_default_route=False), scenario(), checks)

    assert result["predicted_connectivity"] == "BLOCKED"
    assert result["first_blocker"] == "F001"
    assert [f["status"] for f in result["findings"]] == ["BLOCKED", "BLOCKED", "WARNING"]
    assert [f["evaluation_mode"] for f in result["findings"]] == [
        "PREDICTED_PATH", "CONDITIONAL_CHECK", "INDEPENDENT_CHECK"
    ]
    assert "해결" in result["findings"][1]["assumptions"][0]
    assert "routing" in result["findings"][1]["dependencies"]
    assert result["forwarding"]["hops"] == []
    assert result["forwarding"]["packet_stopped"] is True


def test_route_found_is_not_end_to_end_reachable():
    result = analyze_communication(network(has_default_route=True), scenario())
    assert result["forwarding"]["route_lookup"]["status"] == "ROUTE_FOUND"
    assert result["predicted_connectivity"] == "UNKNOWN"
    assert result["first_blocker"] is None
    assert result["findings"][0]["status"] == "PASS"
    assert result["coverage"]["checks"]["security_group"]["state"] == "NOT_EVALUATED"
    assert result["coverage"]["checks"]["full_path_simulation"]["state"] == "NOT_EVALUATED"


def test_conditional_check_without_target_is_not_evaluated():
    checks = [PolicyCheck(
        "security_group", lambda _r, _s: [observation("BLOCKED", "가정 불가")],
        evaluation_mode="CONDITIONAL_CHECK", requires_destination_resource=True
    )]
    result = analyze_communication(network(has_default_route=False), scenario(destination_resource=None), checks)
    assert len(result["findings"]) == 1
    assert result["coverage"]["checks"]["security_group"]["state"] == "NOT_EVALUATED"


def test_unknown_forwarding_does_not_stop_independent_checks():
    checks = [PolicyCheck("policy_a", lambda _r, _s: [observation("WARNING", "독립 검사 결과")])]
    result = analyze_communication(network(has_default_route=True), scenario(destination_ip="bad-ip"), checks)
    assert result["findings"][0]["status"] == "UNKNOWN"
    assert result["findings"][1]["status"] == "WARNING"
    assert result["coverage"]["checks"]["routing"]["state"] == "UNKNOWN"
    assert result["first_blocker"] is None


def test_failed_policy_runner_does_not_stop_the_next_one():
    def failure(_resources, _scenario):
        raise RuntimeError("test")
    checks = [
        PolicyCheck("broken_policy", failure),
        PolicyCheck("working_policy", lambda _r, _s: [observation("BLOCKED", "추가 정책 오류")]),
    ]
    result = analyze_communication(network(has_default_route=False), scenario(), checks)
    assert [f["status"] for f in result["findings"]] == ["BLOCKED", "UNKNOWN", "BLOCKED"]
    assert result["coverage"]["checks"]["broken_policy"]["state"] == "UNKNOWN"
    assert result["coverage"]["checks"]["working_policy"]["state"] == "EVALUATED"


def test_duplicate_policy_observations_deduplicated():
    obs = observation("BLOCKED", "동일 정책")
    checks = [PolicyCheck("policy_a", lambda _r, _s: [obs, obs])]
    result = analyze_communication(network(has_default_route=False), scenario(), checks)
    assert len(result["findings"]) == 2
    assert [f["id"] for f in result["findings"]] == ["F001", "F002"]


def test_empty_policy_results_mean_not_evaluated():
    result = analyze_communication(network(has_default_route=True), scenario(), [PolicyCheck("policy_a", lambda _r, _s: [])])
    assert result["coverage"]["checks"]["policy_a"]["state"] == "NOT_EVALUATED"


def test_invalid_policy_result_is_isolated():
    checks = [
        PolicyCheck("policy_a", lambda _r, _s: [{"status": "BLOCKED"}]),
        PolicyCheck("policy_b", lambda _r, _s: [observation("PASS", "정상 검사")]),
    ]
    result = analyze_communication(network(has_default_route=True), scenario(), checks)
    assert result["coverage"]["checks"]["policy_a"]["state"] == "UNKNOWN"
    assert result["coverage"]["checks"]["policy_b"]["state"] == "EVALUATED"


def test_duplicate_check_names_rejected():
    check = PolicyCheck("same", lambda _r, _s: [])
    with pytest.raises(ValueError, match="중복"):
        analyze_communication(network(has_default_route=True), scenario(), [check, check])


def test_predicted_path_mode_not_available_to_policy_plugins():
    with pytest.raises(ValueError, match="CONDITIONAL_CHECK"):
        PolicyCheck("unsafe", lambda _r, _s: [], evaluation_mode="PREDICTED_PATH")


def test_result_is_json_serializable_and_scenario_preserved():
    result = analyze_communication(network(has_default_route=False), scenario())
    raw = json.dumps(result, ensure_ascii=False)
    assert "3306" in raw
    assert result["scenario"]["source_subnet"] == "aws_subnet.private"


def test_relevant_cloud_policy_coverage_depends_on_request_type():
    aws_result = analyze_communication(network(has_default_route=True), scenario(request_type="aws_api"))
    web_result = analyze_communication(network(has_default_route=True), scenario(request_type="browser_http"))
    assert aws_result["coverage"]["checks"]["iam"]["state"] == "NOT_EVALUATED"
    assert web_result["coverage"]["checks"]["cors"]["state"] == "NOT_EVALUATED"
