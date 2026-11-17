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
