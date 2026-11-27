# Phase 6 handoff — 2026-11-27

## Verified user evidence

- 482, 504, 533, 555 full regression passes; latest 555 in 4.81s. Reachability comparison CONSISTENT_CANDIDATE; Flow Logs ACCEPT_RECORDS, four matching records, SKIPDATA=1. Both from synthetic fixtures. User screenshot confirms unified web evidence display.
- User confirmed collapse/drag and policy inspection, and upload failure screen.

## D acceptance

Run `python -m pytest -q`: target 558, not yet verified in user environment. Three added tests exercise original verdict preservation for 443 and 80, stale token/fingerprint rejection on HTTP configuration replacement and successful restoration. No runtime source changes.

## Open acceptance items

- Actual browser file drop, explicit layout save/reload/reset and full integrated browser acceptance. Check valid and invalid drop, keyboard/native chooser, and no auto-submit.
- Actual AWS exports and read-only inventory compatibility, collection completeness, scope and observation linkage; never equate static or uploaded evidence with actual end-to-end success.
- CP-6.2-UI-001: intermittent common upload/refresh inconsistency in Network Topology; capture Console, HTTP response and input fingerprints when reproduced. No verified fix.
- Git commit and remote synchronization must be confirmed separately.

## Next: Phase 7

Start with bounded IGW/NAT path and translation support: define support matrix, input/collection evidence and immutable forwarding/policy boundaries before implementing. Then multi-VPC connectivity, managed services and authorization/application policy, retaining V1 scope in PROJECT_VISION.md and CLOUDPATH_V1_RELEASE_SCOPE.md. Unresolved or unsupported paths remain UNKNOWN/NOT_EVALUATED. This is a development handoff, not V1 acceptance.
