# Phase 6-2 H — 통합 검수 및 인계 준비

기준: 2026-11-26 G 후속 사용자 회귀 435 PASS(2.61초). H 목표 443 PASS. 실제 AWS API 호출/리소스 변경 없음. 합성 데이터는 실제 AWS 증거가 아니다.

## 지원 범위

단일 VPC/Region, primary IPv4 CIDR, 서로 다른 Subnet, 단일 일반 ENI/primary IP EC2, 명시적 Local Route, IPv4 TCP 및 양 포트, SG CIDR/NACL 정책. 조건부 응답은 TCP 연결 추적 가정이 필요하다. 동일 Subnet, SG 참조/Prefix List, 전파/복합 경로, 실제 연결 추적·호스트·애플리케이션 및 수집 완전성/최신성/원자성/인증 미검증. UNKNOWN 보존.

## 브라우저 수동 검수

프로젝트 루트에서 `.venv` 활성화 후 `python scripts/serve_cloudpath.py --terraform samples/aws/phase62_demo/aws_static_tcp_example.json` 실행. localhost:8001 접속. Packet Trace 탭에서 10.0.1.10 → 10.0.2.10 TCP 50000 → 443 선택. 이후 Upload 기능으로 아래 합성 파일을 하나씩 교체해 재실행(또는 서버 종료 후 해당 파일로 재기동).

| 파일 (samples/aws/phase62_demo/) | 전체 | 조건부 | 최초/중단 지점 |
|---|---|---|---|
| aws_static_tcp_example.json | UNKNOWN | REACHABLE | 없음 |
| request_blocked.json | BLOCKED | NOT_EVALUATED | request:SOURCE_SG_EGRESS; Route 추가 독립 차단 |
| response_blocked.json | UNKNOWN | BLOCKED | response:SOURCE_NACL_EGRESS (조건부) |
| unknown_then_blocked.json | UNKNOWN | NOT_EVALUATED | request:SOURCE_SG_EGRESS UNKNOWN; Route 독립 차단; 최초 차단 없음 |

- [ ] 443 PASS 사용자 실행 로그
- [ ] 네 가지 시나리오의 전체/조건부 판정 및 최초 차단/UNKNOWN 중단 확인
- [ ] 요청 재생/다음/초기화, 차단/UNKNOWN에서 중단, 응답/독립 검사 실제 재생 제외
- [ ] 판정 근거 펼치기, 관련 리소스/기존 구성선 강조, 해제 및 Packet Trace 복귀
- [ ] 결과 JSON 저장 및 동일 입력에서 재불러오기
- [ ] 입력 교체 후 이전 결과 JSON 다시 가져오기: 지문 불일치 표시와 구조도 강조 금지
- [ ] 기존 Terraform 입력으로 전환 후 기존 구조도/Packet Trace 동작 확인

## 인계 기준

H 완료 판정에는 사용자 회귀 및 수동 브라우저 증거 기록이 필요하다. 실제 AWS 조회/관측 검수와 V1 출시 요건은 별도로 미완료. 실패/미확인 항목은 숨기지 않는다. Git 상태 및 변경점을 검토한 뒤 필요한 파일만 명시적으로 stage/commit 하고 새 archive와 환경 로그를 확보한다. 자동 commit/push 또는 과거 스크립트/outputs 삭제 금지.
