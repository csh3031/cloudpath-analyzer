# Phase 3-1 — 오프라인 인프라 토폴로지 뷰어

## 목적

- Phase 2-5 `analyze_graphs()` 결과를 이용해 실제 **브라우저 시각화**를 제공한다.
- Terraform만 입력하고 AWS에 리소스를 생성하거나 AWS API를 호출하지 않는다.
- **Network Graph**와 **Reference Graph**를 탭으로 구분한다.
- `contains`, `uses_route_table`, `attached_to`, `applies_to` 등은 구성 관계이고, **패킷이 실제 통과하는 선이 아니다**.
- 노드 클릭 시 리소스 ID, 유형, 관련 관계 및 라우팅 규칙을 표시한다.

## 파일

- `backend/output/topology_html.py`: JSON 안전 임베딩 및 오프라인 HTML 출력
- `frontend/static/topology_viewer.html`: HTML, CSS, JS로 구현한 인터랙티브 뷰어
- `scripts/export_topology.py`: Terraform 입력 → 그래프 분석 → HTML 생성
- `tests/test_topology_html.py`: HTML 렌더러 테스트 6건
- `outputs/topology.html`: 실행 결과 (생성 파일, Git에 기본 포함하지 않음)

## 사용 방법

```bash
cd /home/soldesk/cloudpath-analyzer
source .venv/bin/activate
python scripts/export_topology.py
python -m http.server 8000 --bind 127.0.0.1
```

Windows 브라우저에서 `http://localhost:8000/outputs/topology.html` 접속.

별도 Terraform 파일은 `python scripts/export_topology.py --terraform samples/terraform/standalone_route.tf` 형태로 지정한다.

## 한계

- 그래프 선은 구조/참조/정책 관계이지 패킷 홉이 아니다.
- Phase 3-1은 소규모 네트워크의 기본 레이아웃을 자동 배치한다. 대규모 리소스 시 최적화된 그래프 레이아웃이나 드래그 기능은 미구현이다.
- 다중 장애(`findings`)를 네트워크 위에 표시하는 기능은 후속 Phase 3 개발에 포함한다.
- SG/NACL/IAM/CORS 실제 정책 평가, 종단 간 통신 시뮬레이션은 아직 미구현이다.
- UI는 오프라인 단일 HTML로 동작하며 CDN, Node/npm, 외부 이미지가 필요하지 않다.
