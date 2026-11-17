#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${CLOUDPATH_ROOT:-/home/soldesk/cloudpath-analyzer}"
cd "$PROJECT_ROOT"
if [[ ! -f backend/analyzer/routing_analyzer.py || ! -f backend/models/infrastructure.py ]]; then
  echo "[ERROR] CloudPath Analyzer 프로젝트 루트가 아닙니다: $PROJECT_ROOT" >&2
  exit 1
fi

STAMP=$(date +%Y%m%d_%H%M%S)
mkdir -p backend/models backend/analyzer tests docs

echo "[INFO] Phase 2-4 신규 모듈과 테스트를 설치합니다."
if [[ -e "backend/models/diagnostics.py" ]]; then
  cp "backend/models/diagnostics.py" "backend/models/diagnostics.py.bak.$STAMP"
  echo "[BACKUP] backend/models/diagnostics.py.bak.$STAMP"
fi
cat > "backend/models/diagnostics.py" <<'__CLOUDPATH_24_DIAGNOSTICS_PY__'
"""CloudPath Analyzer의 공통 통신 진단 모델 (Phase 2-4)."""

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence


CHECK_STATUSES = frozenset({"PASS", "BLOCKED", "WARNING", "UNKNOWN"})
EVALUATION_MODES = frozenset({"CONDITIONAL_CHECK", "INDEPENDENT_CHECK"})


@dataclass(frozen=True)
class CommunicationScenario:
    """단일 통신 요청. source_subnet은 Terraform 리소스 주소이다."""

    source_subnet: str
    destination_ip: str
    protocol: str = "tcp"
    destination_port: int | None = None
    destination_resource: str | None = None
    request_type: str = "network"  # network | aws_api | browser_http


@dataclass(frozen=True)
class PolicyObservation:
    """정책 분석기가 관찰한 사실. 패킷 전달 성공의 증명은 아니다."""

    status: str
    reason: str
    resource: str | None = None
    evidence: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    assumptions: tuple[str, ...] = field(default_factory=tuple)
    dependencies: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self):
        if self.status not in CHECK_STATUSES:
            raise ValueError(f"허용되지 않은 PolicyObservation 상태: {self.status}")
        if not self.reason:
            raise ValueError("PolicyObservation.reason은 비어 있을 수 없습니다.")


PolicyRunner = Callable[[Sequence[Any], CommunicationScenario], Iterable[PolicyObservation]]


@dataclass(frozen=True)
class PolicyCheck:
    """상위 분석기에 등록하는 독립/조건부 검사의 계약.

    requires_destination_resource=True이면 명확한 목적지 리소스가 없는
    시나리오에서 검사를 실행하지 않고 NOT_EVALUATED로 기록한다.
    """

    name: str
    run: PolicyRunner
    evaluation_mode: str = "INDEPENDENT_CHECK"
    requires_destination_resource: bool = False
    assumptions: tuple[str, ...] = field(default_factory=tuple)
    dependencies: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self):
        if not self.name or self.name == "routing":
            raise ValueError("PolicyCheck.name은 routing과 중복되지 않는 이름이어야 합니다.")
        if self.evaluation_mode not in EVALUATION_MODES:
            raise ValueError("정책 검사는 CONDITIONAL_CHECK 또는 INDEPENDENT_CHECK만 지원합니다.")
        if not callable(self.run):
            raise ValueError("PolicyCheck.run은 호출 가능한 검사 함수여야 합니다.")
__CLOUDPATH_24_DIAGNOSTICS_PY__
echo "[WRITE] backend/models/diagnostics.py"
if [[ -e "backend/analyzer/communication_analyzer.py" ]]; then
  cp "backend/analyzer/communication_analyzer.py" "backend/analyzer/communication_analyzer.py.bak.$STAMP"
  echo "[BACKUP] backend/analyzer/communication_analyzer.py.bak.$STAMP"
fi
cat > "backend/analyzer/communication_analyzer.py" <<'__CLOUDPATH_24_COMMUNICATION_ANALYZER_PY__'
"""통신 시나리오별 Forwarding + Policy 진단 오케스트레이터 (Phase 2-4).

기존 analyze_route를 수정하지 않고 재사용한다. 아직 SG/NACL을 실제로
판정하는 구현은 없다. 등록된 정책 분석기만 실행하며, 미등록 영역은
NOT_EVALUATED로 명시한다.
"""

from dataclasses import asdict
from typing import Any, Sequence

from backend.analyzer.routing_analyzer import analyze_route
from backend.models.diagnostics import (
    CommunicationScenario,
    PolicyCheck,
    PolicyObservation,
)


# 인프라를 생성하거나 API를 호출하지 않는다.
# Phase 2-4에는 전체 네트워크 경로 추적 구현이 없으므로 공백을 드러낸다.
BASE_COVERAGE = (
    "routing",
    "security_group",
    "network_acl",
    "return_path",
    "full_path_simulation",
)


class _FindingCollector:
    def __init__(self):
        self.findings: list[dict[str, Any]] = []
        self.seen: set[tuple[Any, ...]] = set()

    def add(
        self,
        *,
        check: str,
        status: str,
        evaluation_mode: str,
        reason: str,
        resource: str | None = None,
        evidence: list[dict[str, Any]] | None = None,
        assumptions: list[str] | None = None,
        dependencies: list[str] | None = None,
    ) -> str | None:
        key = (check, status, evaluation_mode, resource, reason)
        if key in self.seen:
            return None
        self.seen.add(key)
        finding_id = f"F{len(self.findings) + 1:03d}"
        self.findings.append({
            "id": finding_id,
            "check": check,
            "status": status,
            "evaluation_mode": evaluation_mode,
            "resource": resource,
            "reason": reason,
            "evidence": evidence or [],
            "assumptions": assumptions or [],
            "dependencies": dependencies or [],
        })
        return finding_id


def _core_coverage(scenario: CommunicationScenario) -> list[str]:
    names = list(BASE_COVERAGE)
    if scenario.request_type == "aws_api":
        names.append("iam")
    if scenario.request_type == "browser_http":
        names.append("cors")
    return names


def _conditional_assumptions(route_status: str) -> list[str]:
    if route_status == "NO_ROUTE":
        return ["선행 라우팅 차단이 해결되어 검사 대상에 도달한다고 가정"]
    if route_status == "UNKNOWN":
        return ["라우팅 결과가 불확실하지만 검사 대상에 도달한다고 가정"]
    return ["라우팅 규칙만 확인되었으며 실제 종단 간 전달은 미검증"]


def analyze_communication(
    resources: Sequence[Any],
    scenario: CommunicationScenario,
    policy_checks: Sequence[PolicyCheck] = (),
) -> dict[str, Any]:
    """첫 차단이 있어도 등록된 독립/조건부 검사를 계속 실행한다.

    ROUTE_FOUND는 네트워크 도달 가능성의 증거가 아니므로 종합 결과는
    UNKNOWN이다. 후속 경로를 합성하거나 패킷이 통과했다고 주장하지 않는다.
    """
    names = [check.name for check in policy_checks]
    if len(names) != len(set(names)):
        raise ValueError("PolicyCheck 이름이 중복되었습니다.")

    collector = _FindingCollector()
    coverage: dict[str, dict[str, str]] = {}

    try:
        route = analyze_route(resources, scenario.source_subnet, scenario.destination_ip)
    except Exception as error:  # 분석 엔진 경계: 다른 검사는 계속 수행한다.
        route = {
            "status": "UNKNOWN",
            "reason": f"라우팅 분석기를 실행할 수 없습니다 ({type(error).__name__}).",
            "evidence": [],
        }

    route_status = route.get("status", "UNKNOWN")
    if route_status not in {"ROUTE_FOUND", "NO_ROUTE", "UNKNOWN"}:
        route_status = "UNKNOWN"
        route = {
            "status": "UNKNOWN",
            "reason": "라우팅 분석기가 알 수 없는 상태를 반환했습니다.",
            "evidence": [],
        }

    route_finding_status = {
        "ROUTE_FOUND": "PASS",  # 라우팅 규칙 확인에 한함
        "NO_ROUTE": "BLOCKED",
        "UNKNOWN": "UNKNOWN",
    }[route_status]

    first_blocker = collector.add(
        check="routing",
        status=route_finding_status,
        evaluation_mode="PREDICTED_PATH",
        resource=route.get("route_table") or scenario.source_subnet,
        reason=route.get("reason") or "라우팅 분석 결과가 불명확합니다.",
        evidence=list(route.get("evidence") or []),
    ) if route_status == "NO_ROUTE" else None

    if route_status != "NO_ROUTE":
        collector.add(
            check="routing",
            status=route_finding_status,
            evaluation_mode="PREDICTED_PATH",
            resource=route.get("route_table") or scenario.source_subnet,
            reason=route.get("reason") or "라우팅 분석 결과가 불명확합니다.",
            evidence=list(route.get("evidence") or []),
        )

    coverage["routing"] = {
        "state": "UNKNOWN" if route_status == "UNKNOWN" else "EVALUATED",
        "reason": "단일 서브넷의 라우팅 규칙 선택만 분석했습니다.",
    }

    for check in policy_checks:
        if check.requires_destination_resource and not scenario.destination_resource:
            coverage[check.name] = {
                "state": "NOT_EVALUATED",
                "reason": "목적지 리소스를 식별할 수 없어 검사하지 않았습니다.",
            }
            continue

        if check.evaluation_mode == "CONDITIONAL_CHECK":
            assumptions = _conditional_assumptions(route_status) + list(check.assumptions)
            dependencies = list(dict.fromkeys(["routing", *check.dependencies]))
        else:
            assumptions = list(check.assumptions)
            dependencies = list(check.dependencies)

        try:
            observations = list(check.run(resources, scenario))
            if not observations:
                coverage[check.name] = {
                    "state": "NOT_EVALUATED",
                    "reason": "검사기가 평가 결과를 반환하지 않았습니다.",
                }
                continue
            if not all(isinstance(obs, PolicyObservation) for obs in observations):
                raise TypeError("PolicyObservation만 반환할 수 있습니다.")
            for obs in observations:
                collector.add(
                    check=check.name,
                    status=obs.status,
                    evaluation_mode=check.evaluation_mode,
                    resource=obs.resource,
                    reason=obs.reason,
                    evidence=list(obs.evidence),
                    assumptions=list(dict.fromkeys([*assumptions, *obs.assumptions])),
                    dependencies=list(dict.fromkeys([*dependencies, *obs.dependencies])),
                )
            coverage[check.name] = {
                "state": "EVALUATED",
                "reason": "등록된 정책 검사기가 결과를 반환했습니다.",
            }
        except Exception as error:  # 검사별 오류를 격리하고 남은 검사를 계속한다.
            collector.add(
                check=check.name,
                status="UNKNOWN",
                evaluation_mode=check.evaluation_mode,
                resource=scenario.destination_resource,
                reason=f"정책 검사를 완료할 수 없습니다 ({type(error).__name__}).",
                assumptions=assumptions,
                dependencies=dependencies,
            )
            coverage[check.name] = {
                "state": "UNKNOWN",
                "reason": "검사기 실행 또는 결과 형식에 오류가 발생했습니다.",
            }

    for check_name in _core_coverage(scenario):
        if check_name not in coverage:
            coverage[check_name] = {
                "state": "NOT_EVALUATED",
                "reason": "이 단계에 해당 분석기가 연결되지 않았습니다.",
            }

    counts = {"evaluated": 0, "unknown": 0, "not_evaluated": 0}
    for entry in coverage.values():
        counts[entry["state"].lower()] += 1

    return {
        "scenario": asdict(scenario),
        # 현재는 라우팅 한 단계만 검증 가능. 전체 통신 성공은 판정하지 않는다.
        "predicted_connectivity": "BLOCKED" if route_status == "NO_ROUTE" else "UNKNOWN",
        "first_blocker": first_blocker,
        "forwarding": {
            "route_lookup": route,
            "path_complete": False,
            "hops": [],
            "packet_stopped": True if route_status == "NO_ROUTE" else None,
            "note": "종단 간 경로 시뮬레이션은 미구현이며 다음 홉을 실제 경유 경로로 간주하지 않습니다.",
        },
        "findings": collector.findings,
        "coverage": {
            "checks": coverage,
            **counts,
        },
    }
__CLOUDPATH_24_COMMUNICATION_ANALYZER_PY__
echo "[WRITE] backend/analyzer/communication_analyzer.py"
if [[ -e "tests/test_communication_analyzer.py" ]]; then
  cp "tests/test_communication_analyzer.py" "tests/test_communication_analyzer.py.bak.$STAMP"
  echo "[BACKUP] tests/test_communication_analyzer.py.bak.$STAMP"
fi
cat > "tests/test_communication_analyzer.py" <<'__CLOUDPATH_24_TEST_COMMUNICATION_ANALYZER_PY__'
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
__CLOUDPATH_24_TEST_COMMUNICATION_ANALYZER_PY__
echo "[WRITE] tests/test_communication_analyzer.py"
if [[ -e "docs/PHASE_2_4_DESIGN.md" ]]; then
  cp "docs/PHASE_2_4_DESIGN.md" "docs/PHASE_2_4_DESIGN.md.bak.$STAMP"
  echo "[BACKUP] docs/PHASE_2_4_DESIGN.md.bak.$STAMP"
fi
cat > "docs/PHASE_2_4_DESIGN.md" <<'__CLOUDPATH_24_PHASE_2_4_DESIGN_MD__'
# Phase 2-4 — Forwarding / Policy Evaluation 분리와 비중단 다중 진단

## 목적

CloudPath Analyzer의 핵심 요구사항 `REQ-MULTI-001`을 위한 최초 실행 구조를 구현한다.
실제 인프라를 배포하지 않고 가상 통신 시나리오를 평가한다.

## 책임 분리

- **Forwarding:** 기존 `routing_analyzer.analyze_route()`를 재사용해 단일 서브넷의 라우팅 규칙을 확인한다.
- **Policy Evaluation:** 외부에서 등록한 검사기(`PolicyCheck`)가 정책별 `PolicyObservation`을 반환한다.
- **Orchestration:** `analyze_communication()`은 전방향 경로 분석에서 차단 또는 불확실성이 발견돼도 평가 가능한 정책 검사를 계속 실행한다.
- **Diagnostics:** 검사 결과들을 `findings` 배열에 누적하고 검사 범위는 `coverage`에 표시한다.

## 절대 혼동하지 않을 개념

- `ROUTE_FOUND`는 **라우팅 규칙 발견**을 뜻한다. 종단 간 `REACHABLE`은 아니다.
- `NO_ROUTE`는 현재 구성에서 해당 목적지로 나갈 경로가 없다는 **라우팅 차단**이다.
- `PREDICTED_PATH`는 현재 구현에서 출발 서브넷의 **라우팅 판정 한 단계**만 담당한다.
- `CONDITIONAL_CHECK`는 가정을 명시한 후속 정책 검사다. 실제 패킷이 경유했다는 의미가 아니다.
- `INDEPENDENT_CHECK`는 경로 상태와 독립적으로 평가 가능한 구성 검증이다.
- `NOT_EVALUATED`는 `findings`의 차단 결과가 아니라 `coverage`에서만 표시한다.
- 아직 `hops`는 항상 빈 배열이며 `path_complete=false`이다. 존재하지 않는 경유지를 생성하지 않는다.

## 최소 API

```python
from backend.models.diagnostics import CommunicationScenario, PolicyCheck, PolicyObservation
from backend.analyzer.communication_analyzer import analyze_communication

scenario = CommunicationScenario(
    source_subnet="aws_subnet.private",
    destination_ip="8.8.8.8",
    protocol="tcp",
    destination_port=443,
)
result = analyze_communication(resources, scenario)
```

`policy_checks`는 `PolicyCheck(name=..., run=..., evaluation_mode=...)`로 주입한다.
`run(resources, scenario)`은 `PolicyObservation` 객체를 0개 이상 반환한다.
반환하지 않으면 `NOT_EVALUATED`가 기록된다.

## 출력

- `scenario`: 입력 통신 시나리오
- `predicted_connectivity`: `BLOCKED` 또는 `UNKNOWN` (아직 `REACHABLE` 판정 없음)
- `first_blocker`: 실제 예상 경로에서 검증된 첫 `BLOCKED` 진단 ID, 없으면 `null`
- `forwarding`: 원래 라우팅 판정과 *미구현 경로 추적* 상태
- `findings`: 확인된 개별 진단. `id`, `check`, `status`, `evaluation_mode`, `resource`, `reason`, `evidence`, `assumptions`, `dependencies` 제공
- `coverage`: 평가·불확실·미평가 검사 목록과 개수

## Phase 2-4 구현 완료 범위

- [x] 공통 진단 및 정책 검사기 데이터 모델
- [x] 라우팅과 정책 검사의 호출 계층 분리
- [x] 라우팅 `NO_ROUTE` 이후에도 등록된 독립/조건부 검사 실행
- [x] 검사별 오류 격리
- [x] 목적지 리소스 미확인 시 조건부 검사 보류
- [x] 검사 근거, 가정, 의존 관계, 미평가 범위 구조화
- [x] 동일 검사 중복 결과의 기본 중복 제거
- [x] 신규 자동 테스트 12개

## 아직 구현되지 않은 범위

- 실제 Security Group / NACL / IAM / CORS 규칙 평가기
- 단일 라우팅 조회를 넘어서는 종단 간 포워딩 경로
- 복수 경로 및 순환 탐지·탐색 제한
- 장애 수정 가정을 자동 생성하는 What-if 분석
- 정책 간 의미론적 중복/충돌 원인 병합
- 최종 UI 및 시각화

**주의:** `PolicyCheck`를 등록하지 않으면 실제 보안 정책을 검증한 것이 아니다. 대체로 `NOT_EVALUATED`와 `UNKNOWN`이 반환되는 것이 정상이다.
__CLOUDPATH_24_PHASE_2_4_DESIGN_MD__
echo "[WRITE] docs/PHASE_2_4_DESIGN.md"

echo "[INFO] Python 문법을 검사합니다."
python -m py_compile \
  backend/models/diagnostics.py \
  backend/analyzer/communication_analyzer.py \
  tests/test_communication_analyzer.py

echo "[INFO] 전체 pytest를 실행합니다."
python -m pytest -v
