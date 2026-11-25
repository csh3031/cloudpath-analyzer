# CloudPath Analyzer — Phase 3-2: Topology Navigation

- 기준: `PROJECT_VISION.md` v1.2 / `project_manifest.json` v1.2
- 범위: **구성 관계 그래프를 탐색하는 UX 개선**
- 실제 클라우드 리소스 배포 / AWS API 호출: 없음
- 테마·리소스별 색상·장애 표시 색상: **미확정이며 이번 단계에서 결정하지 않음**

## 구현 항목

1. **화면 맞춤 및 배율 제어**: Fit, 확대/축소, 100%, Ctrl+휠. 캔버스의 뷰포트 크기가 변할 때 스크롤 가능한 영역을 해당 배율에 맞춰 갱신한다.
2. **이동**: 빈 캔버스를 드래그해서 이동. Node의 기본 클릭 동작은 보존한다. 키보드 포커스 시 `+`, `-`, `0` 단축키 제공.
3. **연관 관계 강조**: 사용자가 노드를 선택하면 직접 연결된 노드와 연결선이 강조되고 관계없는 요소는 흐려진다. VPC의 `contains` 관계는 패킷 홉이 아니라 영역으로 표현한다.
4. **CIDR 등 안전한 표시 정보**: 기존 그래프 모델을 수정하지 않고 `resource_display`로 `cidr_block`, `availability_zone`만 전달한다. Terraform의 다른 전체 속성은 HTML에 자동 삽입하지 않는다. `${var...}` 등 미해결 표현식은 해결된 값으로 표시하지 않는다.
5. **정보 패널 간소화**: 주요 식별 정보와 관계/라우팅 규칙 우선, 원본 노드 JSON은 펼치기 선택형으로 표시.
6. **참조 그래프 배치 개선**: 참조 의존성 깊이와 연결 관계를 고려한 결정적 계층 배치. 순환 참조를 실제 경로로 해석하지 않는다.

## 계층 및 데이터 의미

- `network_graph`: 구성 관계. `contains`, `uses_route_table`, `attached_to` 등의 간선은 패킷 경유 여부가 아님.
- `reference_graph`: HCL 리소스 참조 관계. 실제 통신 가능성 아님.
- `resource_display`: 표시용 최소 속성. 분석기 판단에 반영되지 않음.
- `Packet Trace View`: 별도 화면으로 설계 확정, **현재 미구현**. 여기의 구성 간선을 가짜 패킷 경로로 그리지 않는다.
- 새로운 `build_resource_display`는 별도 렌더링 계층으로, 기존 `analyze_graphs`, `analyze_route`, `analyze_communication`의 API는 유지된다.

## 파일

- `frontend/static/topology_viewer.html` : 배율, 화면 맞춤, 노드 하이라이트, 배치, 상세 패널
- `backend/output/topology_html.py` : 선택 속성 전달 및 안전한 JSON 삽입
- `scripts/export_topology.py` : Terraform 리소스에서 표시 메타데이터를 추출하여 렌더러로 전달
- `tests/test_topology_navigation.py` : 새 회귀 테스트 8개

## 검증 목표

- 기존 57개 회귀 테스트 + 신규 8개 = **65 PASS 목표**
- 두 그래프 전환, Fit/Zoom/100%, 노드 클릭 강조, CIDR 표시, 원본 JSON 접기 확인
- 입력 CIDR에 HTML/스크립트 특수문자가 포함되더라도 실행 가능한 HTML로 삽입되지 않음
- 표시할 CIDR이 없는 리소스에는 값을 임의 생성하지 않음

## 알려진 제한

- 참조 그래프의 레이아웃은 외부 배치 엔진 없이 적용한 결정적 휴리스틱이다. 연결선 교차 최소화, 대규모 VPC 자동 영역화, 사용자 개별 노드 배치 저장은 다음 과제이다.
- 축소해서 볼 때 글자도 작아지므로 실제 분석에서는 확대 상태의 상세 패널을 함께 활용한다.
- 장애 진단 오버레이 / 시뮬레이션 애니메이션은 실제 패킷 분석 엔진 구현 후 별도 `Packet Trace View`에 적용한다.
- 성능 병목은 이번 단계에 포함되지 않으며 `Graph Issues: 0`은 인프라 정상 통신의 증명이 아니다.

## 다음 작업 후보

- Phase 3-3: 여러 VPC, AZ, Subnet 및 리소스가 포함된 대규모 시나리오에서 레이아웃/가독성 평가
- `docs/UI_VISUALIZATION_RESEARCH.md`에서 다크/라이트, 장애 표시, 리소스 색상, 간선 표현 후보 검증
- Package-friendly 모듈형 프런트엔드 구조로 전환 여부 검토 (기능 필요성에 따라 결정)

