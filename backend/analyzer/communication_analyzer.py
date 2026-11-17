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
