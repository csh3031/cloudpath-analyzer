# Phase 6-3 — External evidence integration

## A. Reachability Analyzer (offline comparison, first increment)

- Previous layout persistence regression target: 482; user confirmation of actual run pending. This increment targets 504 tests.
- Inputs: existing Inventory v1 and one record each in AWS CLI `describe-network-insights-paths` / `describe-network-insights-analyses` JSON outputs. No credentials or AWS API calls, no new analysis execution, no resources created. Synthetic fixtures are not actual AWS exports.
- Recompute the CloudPath static session from the inventory and explicit TCP tuple; preserve its original verdict and fingerprint. Validate path/analysis IDs, successful analysis state, strict boolean, IPv4 endpoint ownership, region, ARN scope, filters and exact TCP tuple. Broad source port filters are not treated as evidence for an exact session. Extra scope filters and warnings prevent comparison.
- A provisional 300-second time gap threshold prevents comparison of distant snapshots; proximity does not establish equivalent configuration. Inventory v1 has no verified account identity. Both evidence sources are unauthenticated. AWS Reachability Analyzer is static model analysis, not live traffic.
- `CONSISTENT_CANDIDATE` / `DISCREPANCY_CANDIDATE` are comparison hints only. `NOT_COMPARABLE` retains reasons. Never change the original predicted/conditional verdict or promote it to actual connectivity. Conditional response tracking and AWS path semantics may differ.
- CLI: `scripts/compare_reachability.py` (see --help); sample files in `samples/aws/phase63_demo/`. All file inputs limited to 5 MiB; one record only, no paginated evidence sets. The comparison reports identifiers, timestamps and results, not arbitrary raw AWS fields.
- A remaining: actual AWS export compatibility review; B: Flow Logs observed evidence; C: unified web evidence panel and acceptance. No live or browser acceptance claimed by this increment. Existing CP-6.2-UI-001 remains open.

References: AWS EC2 API NetworkInsightsPath, NetworkInsightsAnalysis; AWS VPC Reachability Analyzer user guide (How Reachability Analyzer works). See official AWS documentation for exact export schemas.

## B. VPC Flow Logs (offline observation correlation)

- User execution verified A: 504 passed, CLI returned CONSISTENT_CANDIDATE with live_observation=false. B adds 29 tests (target 533).
- Read UTF-8 default version 2 whitespace-delimited text (14 fields), optionally with exact header. Maximum 5 MiB and 50,000 lines. Custom schemas, CloudWatch JSON wrappers, compressed objects and malformed records are not supported. No API, resource creation or credentials.
- Recompute the same static IPv4 TCP scenario on Inventory v1. Correlate exact forward/reverse five-tuples at the two verified endpoint ENI candidates, distinct subnets. The reverse tuple is not proof of a tracked reply. Include only records fully contained within snapshot time +/- 300 seconds (provisional heuristic); report partial and outside windows separately. Timestamp proximity is not configuration equivalence.
- Deduplicate identical parsed records. Report record counts by tuple direction, ENI and ACCEPT/REJECT. No packet sum, causal policy attribution, observed complete path or application verdict. Preserve original static result. NO_MATCHING_RECORDS never means blocked; NODATA/SKIPDATA indicate coverage limitations. Missing/mixed account IDs in matching records prevent tentative correlation; inventory account and log region/authenticity remain unverified even otherwise.
- Observation labels: ACCEPT_RECORDS, REJECT_RECORDS, MIXED_RECORDS, NO_MATCHING_RECORDS, NOT_COMPARABLE. `live_observation=false` means no live collection or probing was performed by CloudPath; uploaded records are a distinct observational evidence type, not verified evidence of current traffic.
- CLI `scripts/compare_flow_logs.py` and synthetic `samples/aws/phase63_demo/flow_logs_v2.txt`. Actual AWS export compatibility and unified web display remain pending. CP-6.2-UI-001 remains open.
- Reference: https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html

## C. Unified web evidence comparison

- User B verification: 533 passed; sample CLI showed ACCEPT_RECORDS, four records and SKIPDATA=1, without changing the static verdict.
- Local POST `/api/aws-evidence` requires the current server token, origin, exact input identity and AWS TCP scenario. Accept a complete Reachability path/analysis pair and/or default v2 Flow Logs text, base64 encoded; combined decoded limit 5 MiB. Recompute the static result on the current snapshot and compare using the A/B modules. Preserve graph, snapshot, token and static prediction. No AWS calls or file persistence.
- Packet Trace shows external evidence only for a fresh web analysis of the current configuration and input revision. Files and comparison results are transient, not restored from saved trace files. Scenario changes, a new analysis, result selection and upload failure invalidate the displayed comparison; late responses are ignored. Separate comparison JSON export is not a topology input or a replayable trace.
- Display separate static comparison and uploaded log record summary with coverage warnings, original verdict, and raw comparison details. No observed end-to-end path, causal policy attribution or actual session-success assertion.
- C adds 15 backend/API tests (target 548). Actual browser acceptance with local server and real AWS export compatibility remain pending. CP-6.2-UI-001 remains open. D will consolidate acceptance and release scope before Phase 7.

### C follow-up — shared file drop zones

- User confirmed unified external evidence screen with expected static comparison and four matching ACCEPT records (screenshot); full 548-pass log not supplied yet. This increment verifies it before applying.
- Add drop zones to configuration upload, saved trace JSON import, and each of the three external evidence inputs; keep native file chooser and existing validation/handlers. Dropping configuration or evidence only selects files, never submits. Trace import retains its existing immediate add behavior.
- Use native FileList via DataTransfer and a bubbling change event. Replace the current selection rather than append. Reject multiple files on single-role evidence inputs, clear the selection, invalidate old evidence, and show an inline warning. Existing upload errors, file limits, token/fingerprint checks and evidence comparison rules remain authoritative. Prevent default file navigation outside designated zones; leave non-file drags alone. No changes to backend, analysis model or AWS operations.
- Browser support for assigning FileList is required for drop; native chooser remains available. CP-6.2-UI-001 remains open.

## D. Integration acceptance and handoff

- User C file-drop regression: 555 passed in 4.81s (2026-11-27). User confirmed A/B CLI output and C unified evidence display. Actual file drop and layout persistence browser acceptance remain unconfirmed.
- D adds three cross-layer regression cases (target 558): port-dependent evidence comparison with immutable static verdict, and HTTP configuration replacement invalidating old tokens and fingerprints, followed by restored configuration comparison. No runtime code change or AWS calls.
- Proceed to Phase 7 after successful D regression, retaining actual AWS exports, full browser E2E and CP-6.2-UI-001 as open acceptance work. See PHASE_6_3_ACCEPTANCE.md. No V1 release declaration.
