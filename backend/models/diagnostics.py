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
    source_resource: str | None = None
    source_ip: str | None = None
    complete_config: bool = False
    assume_direct_private: bool = False
    complete_nacl_config: bool = False
    assume_unmodified_default_nacl: bool = False
    source_port: int | None = None


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
