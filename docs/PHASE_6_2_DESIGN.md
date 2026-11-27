# Phase 6-2 — 실제 AWS Inventory 정적 통신 분석

- 기준선: 2026-11-25, `09f1184118232c44b7cb469439f08f379b8a55be`, 사용자 환경 288 PASS.
- 현재 개발 단위: H 통합 검수(A~G 사용자 환경 적용 완료). 기존 Phase 6-2-1 등의 공식 번호는 변경하지 않는다.
- 제품 버전 및 상위 설계 개정은 유지한다(0.1.0-dev / 1.3).

## 최초 단위 (역사 기록)

`backend/aws/route_evidence.py::lookup_observed_route(raw, source_subnet_id, destination_ip)`는 기존 Inventory loader를 통해 입력 형식 및 기본 구조를 검증한 뒤 수집된 원본의 allowlist 필드를 사용한다. 변환 과정에서 생략되는 비활성 Route/Association도 판정 근거로 보존한다. AWS API를 호출하거나 AWS 설정을 수정하지 않는다.

- 단일 VPC/Region, primary IPv4 CIDR 내부의 서로 다른 available Subnet 사이의 출발 Subnet Route Table 선택과 목적지 IPv4 경로 조회에 한정한다.
- 명시적 Subnet Association 우선, 없으면 확인된 Main Association 사용. 중복/미확정 Association은 UNKNOWN. 암묵적 Table/Local Route 생성 금지.
- IPv4 longest prefix match. 동순위, Prefix List 내용 미수집, 미확정 Route 상태는 UNKNOWN.
- 선택된 blackhole은 Route Lookup 단계의 BLOCKED. active local (primary CIDR)은 LOCAL_CANDIDATE. 다른 대상은 UNKNOWN.
- 응답은 STATIC_AWS_INVENTORY_ROUTE_LOOKUP, 입력 지문, 수집 시각, Table/Association/Route 근거, 제한 사항을 포함한다. Local 후보는 패킷 도달 또는 세션 성공을 뜻하지 않는다. 수집 완전성, 최신성, 원자성, 인증 여부를 확정하지 않는다.
- 기존 AWS Inventory의 analysis_restricted=True를 유지한다. Terraform 기존 분석과 UI를 수정하지 않는다.
- 테스트: 기존 288개 + 신규 18개 = 306개 예상. 실제 사용자 환경 결과는 적용 후 기록한다.

## 최초 단위 당시 후속 계획 (역사 기록)

1. ENI/IP 소유권, Instance attachment 및 실행 상태, subnet/SG 관계와 데이터 일관성 확인. 다중 ENI 및 미지원 상태를 UNKNOWN으로 처리.
2. 관측 Route Lookup을 Forwarding에 연결. 동일 Subnet, 양방향 경로 및 첫 차단 순서를 별도 검증.
3. 실제 ENI 기준 SG 및 명시적 NACL 규칙 연동. 누락/참조/상태/지원 범위 검증. 수집 완전성 및 시점 판정 규칙 확정.
4. 통합 세션 결과의 STATIC_AWS_INVENTORY_PREDICTION 구분, 요청/응답 및 조건부 검사, 웹 제한 조건부 해제. 운영 환경/브라우저 검증은 별도.

기존 추적 백업 파일 및 과거 적용 스크립트는 삭제하지 않는다. `.gitignore`의 `*.bak_*` 패턴만 추가하며 이미 추적 중인 파일에는 영향이 없다.

## 내부 C 단계 — Endpoint evidence

- 사용자 환경의 첫 적용 결과: 2026-11-26, 288 → 306 PASS (1.97초), AWS 분석 제한 유지.
- `backend/aws/endpoint_evidence.py::lookup_observed_endpoint(raw, private_ip)`는 입력 지문/수집 시각과 VPC, Subnet, ENI, Instance, SG 연결 근거를 반환한다.
- 동일 VPC primary IPv4 CIDR, available VPC/Subnet, 단일 primary IPv4 주소와 단일 일반 ENI, in-use ENI, requester-managed=False, device index 0, running EC2, 양방향 Instance/ENI 연결 및 SG 일치만 후보로 인정한다. SG 목록 존재만 확인하며 정책 허용 여부는 판정하지 않는다.
- IP 중복, 다중 ENI/주소, 누락 또는 불일치, 미확정 상태는 UNKNOWN. 형식/기본 구조 오류는 기존 loader와 동일하게 ValueError. v1에는 attachment status가 없고 수집의 원자성/완전성/최신성도 보장되지 않는다. ENDPOINT_CANDIDATE는 실제 접속 성공 또는 현재 실행 확인이 아니다.
- 신규 31개 테스트, 전체 목표 337 PASS. 실제 사용자 환경 결과는 다음 적용 후 기록한다.
- Route Lookup, 기존 분석 엔진, UI 및 수집기 변경 없음. AWS 웹 분석 제한 유지. 다음 내부 D 단계에서 Endpoint와 Route evidence를 연결한다.

## 내부 D 단계 — Directional forwarding evidence

- 사용자 환경 C 단계 적용 결과: 2026-11-26, 306 → 337 PASS (1.03초). AWS 웹 분석 제한 유지.
- `backend/aws/forwarding_evidence.py::trace_observed_forwarding(raw, source_ip, destination_ip)`는 동일한 immutable AWS Inventory bytes에서 양 Endpoint와 요청/응답 Route Lookup 근거를 통합한다. 기존 IaC Forwarding에는 연결하지 않으며 AWS API 호출도 없다.
- 두 Endpoint 후보, 서로 다른 Subnet, primary IPv4, AWS 예약 주소 제외, 명시적 active local Route 및 전파 Route 미사용인 경우에만 방향별 FORWARDING_CANDIDATE를 반환한다. 동일 Endpoint/Subnet, 미확정 Endpoint/Route 및 전파 Route는 UNKNOWN이다.
- 선택된 blackhole은 그 방향의 Route Lookup에서 BLOCKED 및 packet_stopped를 기록하고 이후 hop을 생성하지 않는다. 반대 방향은 독립적인 조건부 역방향 검사이며 실제 응답이 발생했다고 주장하지 않는다. UNKNOWN은 명확한 차단으로 변환하지 않는다.
- 입력 지문/수집 시각, Endpoint 근거, 각 방향의 Route 근거 및 단계별 hop을 보존한다. 모든 policy_status와 session_status는 NOT_EVALUATED. path_complete는 지원 범위 내 Forwarding 후보만 의미한다. 수집의 최신성·원자성·완전성·인증, 실제 패킷, 호스트 및 애플리케이션 상태는 확인되지 않는다.
- 신규 25개 테스트, 전체 목표 362 PASS. 실제 사용자 환경 결과는 다음 적용 후 기록한다. 기존 AWS 및 IaC 분석, UI, 수집기 변경 없음.
- 다음 E 단계: ENI 기반 SG 및 Subnet NACL의 별도 정책 평가. SG 상태 저장/응답 처리와 NACL 비상태 저장 평가를 구분하고 정보 누락은 보수적으로 처리한다.

## 내부 E 단계 — Independent policy evidence

- 사용자 환경 D 단계 적용 결과: 2026-11-26, 337 → 362 PASS (1.62초). AWS 웹 분석 제한 유지.
- `backend/aws/policy_evidence.py::evaluate_observed_policy(raw, source_ip, destination_ip, source_port, destination_port)`는 기존 Forwarding evidence와 동일 입력 지문에 기반한 독립 정책 검사다. 교차 Subnet의 단일 ENI primary IPv4 EC2 및 명시적인 TCP 양 포트로 제한한다.
- 요청: 출발 ENI SG egress, 출발 Subnet NACL egress, 목적 Subnet NACL ingress, 목적 ENI SG ingress. SG의 IPv4 CIDR 허용 규칙 합집합을 평가하며 미해결 SG 참조 및 Prefix List는 UNKNOWN으로 보존한다. 규칙 목록의 완전성은 보장되지 않는다.
- 응답: 두 SG는 추적된 연결이라는 전제의 CONDITIONAL만 반환한다. 현재 연결 추적 상태 또는 untracked flow는 확정하지 않는다. 두 NACL은 응답의 목적지 포트(요청 출발 포트)로 독립 검사한다.
- NACL은 명시적 단일 Association 및 IPv4 rule number 오름차순 첫 일치 규칙을 사용한다. 누락된 Association, 불명확한 우선순위 또는 명시적 일치/default 규칙 없음은 UNKNOWN. 후속 정책 검사 결과는 독립적 근거이며 실제 패킷 hop을 나타내지 않는다.
- 정책 후보 허용은 실제 통신 성공이 아니다. 전체 session_status는 NOT_EVALUATED. 기존 AWS/TF 웹 분석 및 수집기 변경 없음. 최신성, 완전성, 인증 및 호스트/애플리케이션 검증은 별도.
- 신규 21개 테스트, 전체 목표 383 PASS. 사용자 환경 결과는 후속 적용 후 기록한다. 다음 F 단계에서 첫 차단 및 조건부 응답을 통합하되 연결 추적 및 수집 제약을 보존한다.

## 내부 F 단계 — Integrated session evidence

- 사용자 환경 E 단계 적용 결과: 2026-11-26, 362 → 383 PASS (1.11초). AWS 웹 분석 제한 유지.
- `backend/aws/session_evidence.py::analyze_observed_session(raw, source_ip, destination_ip, source_port, destination_port)`는 E 정책 근거(포함된 D/B/C 근거 포함)를 통합한다. 동일 입력 지문과 수집 시각을 보존한다. AWS API, 기존 IaC 엔진 및 웹은 변경하지 않는다.
- 요청 검사 순서: 양 Endpoint 및 범위 사전 검증 → 출발 SG egress → 출발 NACL egress → Route Lookup → 목적 NACL ingress → 목적 SG ingress. trace는 검사 ID의 순서이며 관측 패킷 또는 물리적 hop이 아니다. 최초 BLOCKED 또는 UNKNOWN/NOT_EVALUATED에서 예상 경로 중단. 이후 가능한 검사 근거는 INDEPENDENT_CHECK로 보존하고 최초 장애와 구분한다. 앞선 UNKNOWN 이후의 BLOCKED를 최초 차단으로 단정하지 않는다.
- 요청 경로의 모든 검사가 PASS인 경우에만 조건부 응답 trace를 구성한다. 요청 성공 예측과 TCP 연결 추적이라는 명시적 가정을 둔다. 응답 SG의 CONDITIONAL은 그대로 보존하고 NACL/Route는 역방향으로 검사한다. 요청이 불완전하면 응답 trace는 비워 두고 독립 근거만 남긴다.
- `predicted_connectivity`는 요청 경로 최초 BLOCKED가 확인되면 BLOCKED, 그 외 UNKNOWN(실제 연결 추적 미확인). 별도 `conditional_connectivity`는 요청 후보 및 tracked reply 가정하의 REACHABLE/BLOCKED/UNKNOWN, 요청 미충족 시 NOT_EVALUATED. `first_blocker`는 요청의 최초 장애 ID, `conditional_first_blocker`는 조건부 응답의 최초 장애 ID다. 이는 업로드된 구성에 대한 정적 판정이며 현재 실환경의 성공/실패를 보장하지 않는다.
- 결과에 scenario, findings(고유 ID/상태/근거/평가 모드/가정/의존 관계), trace, evidence, coverage, limitations를 포함한다. 수집 완전성/최신성/원자성/인증, attachment 상태, 연결 추적, 호스트 방화벽/애플리케이션은 미확인. 기존 지원 범위 및 UNKNOWN 유지.
- 신규 26개 테스트, 전체 목표 409 PASS. 실제 사용자 환경 결과는 다음 적용 후 기록한다. 다음 G 단계에서 이 결과의 웹 연동 계약과 분석 허용 조건을 검토한다. 웹 분석 제한은 이번 단위에서 해제하지 않는다.

## G — AWS static session web integration (first unit)

- F user regression: 409 passed in 1.78s (2026-11-26). New target: 423.
- `/api/aws-analyze` accepts only current input identity, two distinct EC2 endpoint indexes, TCP and explicit ports; legacy `/api/analyze` continues to reject AWS snapshots. HCL/Plan contract unchanged.
- CLI startup and transactional upload retain validated original AWS bytes in server memory only, not exposed through context or persisted; exact bytes are required for source fingerprint. Analysis uses sanitized evidence; no AWS calls or live packets.
- Same origin/token/size protections apply; replacement rotates token and identity. UI distinguishes predicted request, conditional reply, and independent findings; selected evidence resources can be inspected on existing graph with identity check. No AWS packet-edge overlay or imported AWS result playback yet; leave these for follow-up verification/extension. No synthetic forwarding arrows on topology.
- AWS assumptions cannot be overridden by the IaC checkboxes. The result JSON is downloadable; overall and conditional verdicts remain separate. Existing IaC Trace playback and overlays remain unchanged.
- `samples/aws/phase62_demo/aws_static_tcp_example.json` is a synthetic fixture only; run `python scripts/serve_cloudpath.py --terraform samples/aws/phase62_demo/aws_static_tcp_example.json` and select TCP 50000 -> 443. Expected overall UNKNOWN, conditional REACHABLE. Browser E2E and real AWS verification remain pending.

## G follow-up — saved results, request replay and evidence emphasis

- G first user regression: 423 passed in 2.40s (2026-11-26). New target: 435 (12 additional tests).
- AWS web results share the existing result selector and JSON import; validate schema, direction, ordered trace, stop conditions, and verdict consistency before display. Imports are not recomputed or authenticated; matching identity is not proof of authenticity. Older G results retain their original resource IDs.
- Replay highlights only the request's ordered predicted checks and stops on BLOCKED or UNKNOWN/NOT_EVALUATED; conditional reply and independent findings remain separately readable, never replayed as actual traffic.
- A selected finding can emphasize known resources, existing Subnet boundaries and already rendered configuration relationship lines only. The server enriches evidence IDs with actual ENI/Instance/Subnet membership. No synthetic packet arrows; no unsupported Local Route hop drawn. Stale input identity prevents graph emphasis. Policy-layer toggles still apply.
- AWS and IaC result contracts remain separate. No new AWS API or write operation. Browser E2E and real AWS validation remain pending; local Chromium navigation was blocked by environment policy. H final verification must record those limitations.

## H — Cross-layer acceptance and handoff preparation

- G follow-up user regression: 435 passed in 2.61s (2026-11-26). H target: 443 (+8).
- On-disk synthetic fixtures: success candidate, request block plus independent route block, conditional response block, unknown before independent block. Additional missing route/ACL, stopped EC2 and stale identity checks. Backend/web/result contract verified separately from browser DOM and live AWS.
- No runtime code or UI changes in this unit. Manual acceptance guide: `docs/PHASE_6_2_ACCEPTANCE.md`. Do not mark H or V1 release complete solely from pytest. Record user regression and browser evidence before declaring H closed; real AWS validation remains a separate outstanding requirement. No Git commit or remote push is performed automatically.

### Browser acceptance feedback: evidence readability and input provenance
- Distinguish configuration upload (replaces snapshot/graph) from saved result import (display only).
- Show current filename/type/identity and submitted scenario; mark edited inputs and failed analysis as not recalculated. Reject a response that does not match the submitted input identity and tuple.
- AWS findings display Korean explanations, policy IDs, applicable CIDR/port evidence and evaluation mode before optional raw JSON. One graph jump per finding highlights known configuration resources only. IAM/host/application checks remain outside this TCP scope.
- Regression includes 443 versus 80/8443, reply port interpretation, UNKNOWN, response mismatch, and HTTP AWS-to-Plan replacement with different graph node IDs. Actual user file and browser verification remain pending.

### Browser feedback: configuration versus saved-result switching
- Configuration JSON and saved result JSON are distinct. Reject result JSON at configuration upload before parsing it as a Plan; preserve server snapshot on rejection.
- Client preflight classifies by content, not filename, and reports unsupported older results without fabricating a session trace. Result imports do not modify configuration or recalculate.
- Explicit reload recovery for stale token / input; successful replacement still reloads server-rendered graph. Browser acceptance and user full regression pending.

### Browser feedback: explicit configuration failure state
- User confirmed the five valid/invalid configuration switch checks in the preceding unit. Full 459-test log not yet supplied.
- Failed configuration uploads enter a persistent error screen: red alert and modal, file selection reset, graph/trace hidden and navigation inert until successful replacement or explicit server reload. Closing the modal does not restore the old display. No server reset, data deletion or AWS call. Saved-result imports remain separate.
- Cancelled replacement keeps the existing error state if already failed. Explicit reload may discard unsaved browser-only analysis results and requires confirmation. Network failure may leave server state uncertain; reload queries current server configuration rather than claiming rollback.
- Browser acceptance remains required. New tests exercise the failure handler and wiring without a real DOM/browser.

### Phase 6-2 handoff — 2026-11-26
- User reported 463 passed in 5.16s, and accepted the failure modal and persistent failure screen. Configuration-switch checks 1–5 passed; intermittent common upload/refresh inconsistency CP-6.2-UI-001 was reported from Network Topology, with Packet Trace common upload as a possible workaround. Not reproducible on demand; root cause unresolved. Retain for follow-up, not a verified fix.
- Phase 6-2 initial implementation is complete; real AWS validation and the intermittent issue remain outstanding. Remote Git status must be confirmed by user.

## Phase 6-2-1 — VPC / Subnet folding
- Presentation only: collapse confirmed containment descendants; preserve ambiguous/orphan membership, and keep subnet-local/shared policies outside the subnet when folding it. VPC collapse hides known VPC descendants; nested subnet choices survive VPC expansion. No graph mutation, synthetic paths, packet or AWS API calls.
- Hidden links are excluded from routing and counted separately. Selected finding overlays are identity-checked by existing code. Hidden resource checks in the active direction are summarized as predicted blocks, conditional/independent blocks and unknowns; no selected result means unassessed, not success. Check counts can overlap across regions if a check references several resources. No actual reachability claim.
- Individual and global fold controls in Network Topology; reference graph unaffected; reset on page reload / input replacement. Persistent layout is deferred to 6-2-3. Drag editing is deferred to 6-2-2.
- User baseline 463; target 469 (+6 tests). Browser DOM smoke tested with rendered synthetic AWS HTML, without live HTTP navigation. Actual user browser and full regression pending.

## Phase 6-2-2 — manual placement and policy inspection

- View-only resource drag mode; per-tab in-memory offsets, existing region boundaries and node/label collisions checked on release. No changes to graph, membership or analysis input. Connections and selected trace overlay are rerouted on release; rejected drops restore original position. Folding and switching tabs retain offsets when still geometrically valid. Persistent save/restore remains Phase 6-2-3. Dense layouts can limit valid moves; container resizing/free cross-region placement is not included.
- Resource click detail exposes allowlisted SG inbound/outbound, NACL inbound/outbound (ordered by rule number), and route table definitions plus existing graph route summaries. Inline and identifiable standalone rules shown with provenance; unresolved values/owners and mixed management warned. No raw policy descriptions, arbitrary attributes or secret expressions exported. Displayed configuration is not an effective policy verdict or live verification.
- Previous target 469 tests; seven new tests, target 476. Separate environment: 422 pass, 9 failures and 6 collection errors attributable to missing python-hcl2. Chromium DOM (rendered synthetic AWS HTML, no live HTTP navigation) checked policy details, drag, recalculated lines, fold/tab restoration, reset. User regression and browser acceptance pending. CP-6.2-UI-001 remains open.

## Phase 6-2-3 — layout persistence

- User confirmed Phase 6-2-2 browser behavior; full 476-test terminal log was not supplied. Apply gate requires 476 passed before modification; target 482 (+6).
- Explicit save stores only manual offsets in both graph views and the nested VPC/Subnet collapsed IDs in browser localStorage, keyed by the exact versioned input fingerprint. Same input automatically restores on page load; different input has its own saved state or automatic layout. A save is not an infrastructure change. No server-side persistence, AWS calls, analysis output, tokens, or raw configuration values stored by this feature.
- Explicit restore validates version, identity, resource IDs, duplicates, coordinate bounds, item/size limits before changing state. The existing geometry checks run on each visible node; invalid placements fall back to automatic positions and report a count. Hidden offsets are retained until visible. Dense layouts can limit valid placements. No viewport zoom, pan, or selected analysis persistence.
- Current-tab automatic placement reset remains an unsaved edit; whole-layout reset confirms then removes only the current fingerprint's stored layout and resets both views and folds. Storage failures report an error; missing identity disables persistence. Browser/site data clearing or a different browser/origin loses access to the saved layouts. Changes are not autosaved.
- Verification: six new tests and 50 related tests pass. Chromium DOM tested with a mocked localStorage and rendered synthetic AWS/Plan HTML: drag/save, simulated reload, nested fold restoration, fingerprint separation, explicit restore/reset, and graph immutability. Actual browser storage and HTTP navigation remain to be verified in user environment; navigation blocked by environment policy. Full regression cannot be reproduced here without python-hcl2. CP-6.2-UI-001 and real AWS validation remain open.
