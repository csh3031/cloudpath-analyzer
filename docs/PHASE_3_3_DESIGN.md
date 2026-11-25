# CloudPath Analyzer — Phase 3-3 (의미 기반 토폴로지)

## 개발 목적

Phase 3-2의 그래프는 정확한 구성 관계를 데이터로 보유하고 있었지만, 시각적으로는 VPC의 리소스가 불규칙하게 배치되거나 코드 참조 관계가 네트워크 경로처럼 보일 수 있었다. Phase 3-3은 **실제 네트워크 경로를 계산했다고 주장하지 않으면서** 인프라 계층과 정책의 역할이 읽히도록 배치한다.

## 확정 원칙

1. **Network Topology / IaC Reference Graph를 별도 화면으로 유지한다.**
2. 실제 AWS 리소스를 배포하지 않고 Terraform 분석 결과로만 그림을 생성한다.
3. VPC는 영역, Subnet은 VPC 소속 요소, Route Table은 서브넷에 적용되는 **라우팅 정책**으로 배치한다.
4. IGW는 VPC에 부착된 리소스다. **Private Subnet이 Public Subnet 뒤에 직렬로 연결된 것은 아니다.** 같은 VPC의 서로 다른 서브넷이며, 인터넷 경로 성격은 라우팅 규칙으로 결정한다.
5. `0.0.0.0/0 → IGW`가 확인되는 서브넷은 **IGW 기본 경로 구성** 그룹으로 분류한다. 해당 사실만으로 인터넷 통신이 가능하다거나 퍼블릭 IP가 있다는 뜻은 아니다.
6. NAT 기본 경로, 다른 기본 경로, 미확인 경로, IGW 기본 경로 없음은 구분한다. 존재하지 않는 패킷 홉 또는 외부 네트워크 리소스를 임의 생성하지 않는다.
7. Route Table ↔ IGW 선은 라우팅 **설정** 관계다. 실제 패킷이 통과했다는 의미가 아니다.
8. Terraform 참조 그래프에서 연결 방향은 **참조하는 리소스 → 참조받는 리소스**다. 상자는 역할별 열로 그룹화한다.
9. 현재의 색상과 배경은 Phase 3-2 상태를 유지한다. 다크 테마와 장애 강조 디자인은 연구 중이며 확정하지 않는다.
10. Phase 2-4의 비중단 다중 문제 진단은 유지한다. 이 단계에서 종단 간 Packet Trace를 구현했다고 주장하지 않는다.

## 이번 구현 범위

- VPC 단위의 영역 표시
- 확인된 기본 경로 대상에 따라 서브넷의 구성 그룹 배치
- 서브넷 옆에 적용 Route Table 노드를 배치하고 설정 연결선 유지
- VPC 경계 인근의 IGW, 외부망 설명용 영역 (가상 리소스 아님)
- IaC Reference Graph: VPC / 네트워크 구성 / Association 등 역할별 분리, 참조 방향 화살표
- 기존 상세정보, 확대/축소, 화면 맞춤, 선택 강조, JSON 출력, 모든 기존 분석기 API 보존

## 제한 사항

- **기본 경로 유무**와 인터넷 실제 통신 가능성은 별개다 (퍼블릭 IP, SG, NACL, 반환 경로 등 미평가)
- NAT Gateway, 다중 Subnet/AZ/VPC가 늘어나면 배치 성능과 교차선을 추가 검증해야 한다
- 실제 패킷 경유 홉, 추론된 종단 간 경로, IAM·CORS, 장애 애니메이션은 아직 구현하지 않는다
- 토폴로지 그래프에 `packet_traversable=false`를 유지한다

## 실행 및 검증

```bash
cd /home/soldesk/cloudpath-analyzer
source .venv/bin/activate
python -m pytest -q
python scripts/export_topology.py --terraform samples/terraform/main.tf --output outputs/topology.html
python -m http.server 8000 --bind 127.0.0.1
```

브라우저: http://localhost:8000/outputs/topology.html

테마·시각적인 최종 디자인은 UI 연구 문서에서 결정한다.
