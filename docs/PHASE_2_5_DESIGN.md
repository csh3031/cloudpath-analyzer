# Phase 2-5 — 참조 그래프와 네트워크 구성 그래프의 분리

## 목적

CloudPath Analyzer의 배포 전 가상 인프라 재현·시각화를 위해 **Terraform 코드 참조**와 **AWS 네트워크 구성의 의미**를 분리한다.

- 실제 AWS 인프라를 생성하거나 AWS API를 호출하지 않는다.
- Phase 2-4의 `analyze_communication` 및 35개 기존 테스트 인터페이스를 수정하지 않는다.
- 두 그래프 모두 현재 **구성 그래프**이며, 실제 패킷 경로를 예측하는 forwarding graph는 아니다.
- `packet_traversable=false`를 모든 연결선에 적용하여 시각화가 구성 관계를 패킷 홉으로 잘못 표시하지 않도록 한다.

## 신규 파일

- `backend/analyzer/reference_graph_analyzer.py`: `analyze_reference_graph(resources)`
- `backend/analyzer/network_graph_analyzer.py`: `analyze_network_graph(resources)`
- `backend/analyzer/graph_analyzer.py`: `analyze_graphs(resources)`
- `tests/test_graph_analyzer.py`: 자동 검증 16개

모든 상대 경로의 프로젝트 루트는 `/home/soldesk/cloudpath-analyzer`이다.

## API

```python
from backend.iac.terraform_parser import parse_terraform
from backend.analyzer.graph_analyzer import analyze_graphs

resources = parse_terraform('samples/terraform/main.tf')
graphs = analyze_graphs(resources)
reference = graphs['reference_graph']
network = graphs['network_graph']
```

### Reference graph

- `nodes`: Terraform이 선언한 리소스만 수록
- `edges`: 어떤 리소스가 다른 리소스를 참조하는지 (`relation=references`)
- `attribute_paths`: 참조가 발견된 속성 경로
- `external_inputs`: `var`, `local`, `module`, `data` 등 현재 파서가 해석하지 않은 입력
- `issues`: 없는 리소스 참조·중복 ID 등

참조 대상이 없는 경우 **없는 리소스를 생성하지 않는다**. 예: `aws_subnet.missing` 참조는 그래프 연결선이 아니라 `issues`에 기록한다.

### Network graph

- `nodes`: VPC, Subnet, Route Table, IGW, NAT GW, EC2, ENI, SG, NACL 등 표시 가능한 리소스
- `edges`: `contains`, `attached_to`, `uses_route_table`, `applies_to` 등 의미론적 구성 관계
- `route_rules`: Route Table 인라인 경로와 별도 `aws_route` 경로의 목적지·대상 메타데이터
- `issues`: 부모 연결 실패, 중복 연결, VPC 불일치, 미해결 라우팅 대상
- `metadata.packet_path_available=false`: **현재는 패킷 경로를 생성하지 않음**

`aws_route` 및 Route Table Association은 별도 전달 홉이 아니라 **라우팅 구성**으로 해석한다. SG는 **정책 적용 관계**이며 패킷이 SG 노드로 직접 이동한다고 주장하지 않는다.

### 암묵적 Main Route Table

Subnet에 명시적 연결이 없고 별도 메인 테이블도 지정되지 않으면 `routing_analyzer.find_route_table()`과 같은 기준으로 `implicit_main:aws_vpc.*` 노드를 생성한다. 이 노드는 실제 AWS 리소스가 아니라 추론된 논리 객체이므로 `synthetic=true`로 표시한다. 기존 VPC의 실측 정보를 대체하지 않는다.

## Phase 2-4와의 관계

- `analyze_route`와 `analyze_communication`은 변경하지 않는다.
- 네트워크 그래프 연결선은 `forwarding.hops`로 자동 변환하지 않는다.
- 향후 패킷 경로 시뮬레이터는 그래프의 구성 관계와 `route_rules`를 **입력 자료**로 활용하되, IP/포트/라우팅/정책 평가를 거쳐 실제 예상 홉을 따로 계산해야 한다.
- `findings`, `evidence`, `coverage`, `PREDICTED_PATH` 및 `CONDITIONAL_CHECK` 구분은 계속 유지한다.

## 기존 API 호환성

기존 `backend/analyzer/topology_analyzer.py`의 `analyze_topology()`는 **변경하지 않는다**. 기존 단일 그래프는 과거 호환용으로 남아 있으며, **신규 시각화/패킷 분석에는 `analyze_graphs()`를 사용한다**. 전환 후 기존 출력의 사용 여부를 점검해 제거 또는 지원 중단을 결정한다.

## 자동 테스트

신규 테스트 16개는 다음을 검증한다.

- Terraform 참조와 속성 경로 인식, 중복 참조 제거, 미해결 참조 표시
- 변수 값을 임의로 리소스로 간주하지 않음
- 네트워크 배치 관계와 라우팅 구성 관계 분리
- 독립 `aws_route`, Main Route Table, 기본 Main Route Table 표시
- 중복 Association·다른 VPC 테이블 선택 방지
- SG 정책 연결선을 패킷 이동선으로 오인하지 않음
- 미확인 다음 홉은 `UNKNOWN` 유지
- 결과 JSON 직렬화 및 그래프의 독립성

사용자 환경 기준: 기존 35개 + 신규 16개 = 전체 **51개** 테스트 목표.

## 이번 단계에서 하지 않는 일

- 종단 간 패킷 경로, SG/NACL/IAM/CORS의 실제 판정
- HCL 변수·`for_each`·`count`·모듈 계산; Terraform Plan JSON 지원
- ENI/인스턴스/서브넷 간 실제 패킷 전달 홉 추론
- VPC 간 Peering/Transit Gateway/VPN/복수 CIDR/IPv6의 완전한 모델
- 미지원 서비스와 구성을 임의로 정상 연결 처리
- UI 구현 (Phase 3에 본격 착수)

## 다음 단계

- `Phase 3`: 동일 인프라 모델로 토폴로지를 시각화하는 기본 UI 구현
- 그래프의 시각적 관계와 실제 forwarding 결과가 분리되었는지 지속 검증
- 이후 SG/NACL과 Packet Forwarding 엔진을 단계적으로 연결
