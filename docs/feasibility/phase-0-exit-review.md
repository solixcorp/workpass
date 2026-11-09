# Phase 0 exit review

**Status:** as of this review, `spec-graph entity update PHS-...-w4e --status resolved` is blocked by the delivery gate with 17 findings; the phase deliberately stays active. This document records what Phase 0 actually verified, so the remaining work is a decision, not a mystery.

## Exit criteria status

| Exit criterion | Status | Evidence |
|---|---|---|
| A maintained OIDC/OAuth, SAML, password and passkey implementation path is validated against Workers limits. | **Substantially met** with three named residuals | Password: PBKDF2-SHA-256 600,000 iterations measured at 50–61 ms wall per sign-in on local workerd, identical work on wrong and correct passwords (`docs/feasibility/phase-0-workers-auth-engine.md`, latency smoke). OIDC: local discovery, authorization-code exchange with S256 PKCE, ES256 ID-token verification, and a single-code-reuse rejection succeeded in earlier recorded probes. SAML: the dependency-free chain is covered by 17 automated checks plus a full signed-request round trip on workerd (registration, enablement, signed redirect, POST-bound signed Response verified against published metadata, replay/tamper/issuer rejection and issuance audit); third-party compatibility remains. Passkey: the Better Auth server verification path passes both registration and authentication ceremonies headlessly on workerd with a synthetic ES256 credential (`scripts/passkey-smoke.ts`, run recorded in the feasibility doc). |
| Tailscale OIDC WebFinger and login requirements are tested or documented as blocked. | **Met (blocked by design)** | `DEC-1794160956-y42` (active): real Tailscale validation is deferred until a company email domain, HTTPS WebFinger route and a disposable tenant exist. `TSK-...-r5p` is resolved with documented prerequisites. |
| TypeScript and the proposed D1 audit plus Workers Logs split are reviewed against runtime, security and retention needs. | **Met** | `DEC-1794163184-ns2` (mandatory stack, Workers-compatible path exercised by all recorded smokes), `DEC-1794159981-8mg` (D1 audit with one-year retention; Workers Logs retention documented as diagnostic-only), plus the runtime limits section of the feasibility doc. |
| Open recovery, MFA and app-target questions are recorded without inventing decisions. | **Met (by design)** | Six unresolved questions and six unmitigated risks are explicitly preserved in the graph; nothing was invented to satisfy the gate (`spec-graph query unresolved`). |

### Named residuals of criterion 1

1. SAML live interoperability with a real test service provider (`TSK-...-fa7`); the headless round trip proves the whole local chain, so only third-party compatibility remains; the test SP must be selected (`QST-...-84w`).
2. The browser-side `navigator.credentials` ceremony for passkeys; everything server-side is verified headlessly.
3. Deployed-plan CPU accounting for the password work factor; the local measurement is wall time, not a plan quota check.

## Gate blockers (why the phase stays active)

`delivery_completeness`: twelve requirement/decision entities are covered by Phase 0 tasks but were not delivered — because they cannot be. They are product requirements whose implementation belongs to later phases (for example `REQ-...-8c1` is implemented by the Phase 3 SAML tasks, `REQ-...-z1v` by the Phase 2 password task). Every one of them is **also covered by its later-phase task**, so the Phase 0 covers are redundant duplicates for requirements, and unresolved policy for two decisions (`DEC-...-fb0` MFA policy and `DEC-...-8f5` test-SP selection are still open by design).

`phase_tasks`: child tasks `TSK-...-kh9` (engine comparison) and `TSK-...-6z0` (security and service decisions) are active, not resolved. Their scopes are fixed while active; resolving them honestly would require delivering entities they merely evaluated.

## Closing options (product-owner decision)

1. **Re-scope graph-natively (recommended).** Deprecate `TSK-...-kh9` and `TSK-...-6z0` with a reason (deprecated is terminal but preserves history), then create narrow Phase 0 tasks that cover and deliver only what Phase 0 produced: the engine-validation decision `DEC-1794203820-gz2` and the recorded feasibility evidence. Requirement coverage is already carried by the later-phase tasks, so nothing is orphaned except two intentionally open policy decisions, which must remain open until the product owner decides them.
2. **Force the phase closed.** `--force --reason "..."` records `completion_forced = true` with the accepted findings in the phase history; this preserves the current graph shape but leaves Phase 0 claiming undelivered requirements.
3. **Keep Phase 0 open** until options 1 is chosen. There is no third technical path: the immutability of active-task scope is a graph invariant, not a tooling gap.

After the phase closes, `phase next --activate` gates Phase 1 on predecessors being resolved.

## What does NOT block the exit

- The SAML login being unreachable in practice: enablement is deliberately gated on live interoperability and belongs to Phase 3.
- The portal/consent UI work: owned by Phase 1 (`TSK-...-jms`), explicitly out of the PoC.
- Sign-in, passkey, OIDC and audit foundations: already exercised as recorded in the feasibility evidence section.
