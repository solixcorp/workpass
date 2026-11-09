# Fingerprint Device Risk and Trusted-Device Policy

**Status:** initial backend implementation is present but disabled by default. This document describes implemented behavior and remaining deployment/security-validation gaps. It does not claim production enforcement is ready.

## Goals and security boundaries

- Keep the existing password, username, passkey, or OIDC authentication as the primary proof of identity. Fingerprint is a risk input, never an authenticator.
- Use server-verified event data for decisions. A browser-supplied `visitor_id`, confidence score, bot result, IP, or device label is untrusted input.
- Treat a trusted device as a revocable, time-limited convenience signal for an already authenticated account—not a permanent allowlist and not a way to skip primary authentication.
- Evaluate changes over time and combine signals. A new device or IP alone is not sufficient evidence to permanently block a person.
- Preserve recovery and administrator review paths, avoid account enumeration, and minimize retained device/network data.

## Fingerprint data ingestion

The browser agent must send the `event_id` alongside password/username sign-in, passkey verification, or trusted-device enrollment. The Worker does not accept a client-provided `visitor_id` as proof of identity. Sealed Client Results are currently unsupported and are explicitly rejected.

Implemented integration: receive `event_id` and retrieve the event from the Fingerprint Server API using a server-only API key and configured region. Never send a Server API key or sealing key to a browser. Sealed Client Result verification is not implemented.

Before using a result, the backend must:

1. The backend validates the event's shape, provider response, and configured region; it rejects mismatched, missing, or malformed values.
2. It enforces freshness (default maximum age: 120 seconds), checks the event origin against `AUTH_BASE_URL` and configured allowed origins, and checks the browser request origin when present.
3. Enforce one-time use of the event ID. A unique D1 claim is created and consumed before primary authentication is processed, preventing the same event from being reused across credential attempts; simultaneous-claim behavior still needs verification on the deployed D1 path.
4. The implementation uses the verified server result for visitor identifier, confidence, bot, suspect score (when configured), tampering, MITM, location spoofing, and coarse country. It ignores client copies of those fields.
5. Provider timeouts and invalid responses are treated as unavailable signals. `observe` continues baseline authentication; `enforce` denies the affected flow. Raw payloads, credentials, API keys, sealed results, and IP addresses are not logged or persisted.

An event ID is not a secret or proof by itself. Sealed results are encrypted against client modification but do not inherently prevent replay; freshness and one-time-use checks remain necessary. The provider documents both the Server API and Sealed Client Results as server-side verification paths and explicitly calls out replay protection.

## Events covered

Risk evaluation should be attached to interactive identity boundaries, not every ordinary application API request in the first release:

- Email/password and username/password sign-in.
- Passkey authentication.
- The interactive OIDC authorization/login flow, before issuing an authorization result.
- Session refresh when a browser context and fresh signal are available; missing browser signals on a server-to-server token call must not be mistaken for a new trusted device.
- Sensitive account actions such as passkey enrollment/removal, password change/recovery, trusted-device enrollment/revocation, and administrator session revocation.

OAuth refresh and client-credentials requests need separate handling. Do not require a browser fingerprint for machine-to-machine clients. Bind interactive OIDC risk decisions to the authenticated session/authorization attempt rather than trusting an unrelated token request.

## Signals and interpretation

Combine the following as evidence, subject to actual Fingerprint plan/field availability:

- Verified visitor identifier and provider confidence. Confidence describes the estimated accuracy of the identification, not whether the user is authorized.
- Bot/automation and other enabled Smart Signals, including any provider risk/suspect score.
- New or changed visitor identifier for the account.
- Time since the previous successful authentication, recent failed attempts, and frequency of distinct devices or locations.
- Coarse network/region change and travel-time plausibility, where reliable server-side event data is available. Implemented as the authentik-semantics history distance and impossible-travel checks below.
- Recent password reset, passkey changes, account recovery, trusted-device changes, or administrator action.
- Current session age and whether the request is an interactive login, refresh, or sensitive action.

Do not treat an IP address, VPN/proxy indication, country, ASN, device fingerprint, low confidence, or provider score as a standalone definitive verdict. Mobile networks, corporate VPNs, browser upgrades, privacy settings, travel, and provider model changes can all cause legitimate variation. Fingerprint identification is probabilistic and can produce false matches and false splits.

## Decision policy

Use three rollout modes:

| Mode | Behavior |
|---|---|
| `disabled` | Fingerprint is not called and has no effect. This is the default state. Normal authentication policy still applies. No device is trusted based on absent signals. |
| `observe` | Verify and record risk outcomes on a best-effort basis for measurement, but do not weaken or silently replace existing authentication. A risk-storage or observation-write failure does not block baseline authentication. Use this mode to measure false positives, provider availability, latency, and cost before enforcement. |
| `enforce` | Apply the actions below. Interactive flows require a fresh, verified event. Missing credentials or provider errors deny the affected flow; the Worker does not silently downgrade. |

Current initial risk behavior is:

| Risk case | Current action |
|---|---|
| Active trusted device with adequate confidence and no strong signal | Allow normal primary authentication and session issuance. The device never replaces the password/passkey. |
| New/untrusted device or low confidence | `step_up`; in `enforce`, the session is issued but a step-up challenge is opened and SSO issuance stays withheld until a second factor is verified (`stepUpChallenge` is added to the sign-in/authorize response). Accounts without any enrollable second factor fail closed; the session is withheld. |
| Different device plus different country within 30 minutes | `deny`; `enforce` withholds the new session. Existing sessions are not revoked automatically. |
| Bot=`bad`, tampering, MITM, location spoofing, or configured suspect-score threshold | `deny`; `enforce` withholds the new session. A `good` bot is not enrolled as a trusted device. Existing sessions are not revoked automatically. |
| Provider/API outage, missing/stale event, replay, invalid event, or rate limit | `observe` records unavailability and permits baseline authentication; `enforce` denies before session issuance. |

Suggested evaluation windows (starting points for shadow-mode measurement, not final thresholds): compare device/network changes over 15 minutes, 24 hours, and 30 days; treat a verified, materially different country within 30 minutes as a strong review signal, not an automatic conclusion of fraud. Do not use a universal numeric Fingerprint confidence or suspect-score cutoff until the selected product plan, signal semantics, baseline data, and false-positive rate have been reviewed.

## Trusted-device lifecycle

A trusted-device record is scoped to one immutable internal user ID and a server-side keyed digest of the verified Fingerprint visitor identifier. It contains only created/last-seen/expiry/revocation timestamps and a short human-readable label. Do not store the raw event payload or use a visitor identifier as a global user key.

Current initial lifecycle:

1. Enroll only from an authenticated session after current-password confirmation and a fresh, unused Fingerprint event. This is a temporary bootstrap policy until an independent step-up or account-owner confirmation flow is available. Do not trust a device automatically on its first successful login.
2. Require a verified, sufficiently reliable event at enrollment and on later use. If the visitor ID is unavailable or confidence is insufficient, treat the device as unknown; do not fall back to an IP-only match.
3. Apply trust only to the same account, and only as one factor in the low-risk policy. A match never bypasses password/passkey authentication, account status checks, rate limits, or high-risk rules.
4. Use an initial maximum lifetime of 30 days, with no indefinite renewal. Re-approval is required after expiry. Tune the period only after balancing security and user friction.
5. The authenticated API lets users list/revoke devices and lets an administrator revoke devices for one user. Revocation takes effect on the next risk decision. Device-list UI remains out of scope.
6. Trust is revoked on password reset, administrator password change, account suspension/removal, and strong compromise signals. Account recovery and other credential-change paths still need to be connected.

The initial implementation should avoid a hard device-count limit until operational needs are known, but must support bulk revocation and detect unusual device churn. A later policy may set a per-account limit based on observed use.

## IP/device velocity and session response

Maintain a compact account security history to compare successful authentication events. Prefer country/region and a keyed digest of a normalized network value over retaining raw IP addresses; retain raw IP only if a documented incident/legal need justifies it, with a short explicit retention period and restricted access.

The initial implementation records a deny decision when a different verified device and country appear within 30 minutes. In `enforce`, it deletes only the newly created D1 session and withholds its response/cookie. It does not revoke existing sessions or trusted devices, and does not send user notifications. A user blocked on a new device needs an existing authenticated device to enroll it or an independently verified recovery path; recovery is not implemented here.

Implemented beyond that initial rule: login-time GeoIP history checks that mirror authentik's GeoIP Policy distance settings (authentik 2025.2+). The current login is compared with the configured number of the user's most recent successful-login observations (`GEOIP_HISTORY_LOGIN_COUNT`, default 5). If `GEOIP_CHECK_HISTORY_DISTANCE` is enabled (default off), any compared observation farther than `GEOIP_HISTORY_MAX_DISTANCE_KM` (default 100) plus `GEOIP_DISTANCE_TOLERANCE_KM` (default 50) yields the reason `history_distance_exceeded`. If `GEOIP_CHECK_IMPOSSIBLE_TRAVEL` is enabled (default on while the pipeline is enabled), any compared observation whose distance is at least the built-in allowance — 1,000 km per elapsed hour, rounded down to whole hours and clamped to one hour, plus `GEOIP_IMPOSSIBLE_TOLERANCE_KM` (default 100) — yields `impossible_travel`. Positions come from Fingerprint event geolocation coordinates when available, otherwise from a country centroid; both are coarse lower bounds. These findings are review-grade evidence, never standalone verdicts: they escalate to `step_up` (in `enforce`, the session is withheld; existing sessions stay alive) and never to `deny`. Distance/VPN false positives from VPNs, carrier NAT, and GeoIP database error are expected; calibrate in observe mode first. The session-side complement — binding an issued session to the network/location that created it — is a separate feature in [Session Network/GeoIP binding](session-geo-binding.md).

The initial risk rules do not revoke existing IdP sessions. Downstream application sessions may not be revocable by the IdP; any future revocation feature must not be described as terminating already-issued downstream sessions.

## Data, audit, and operations

- Keep Fingerprint server keys in Worker secrets, separated by environment and least privilege. Do not commit keys or include them in diagnostics.
- Record a correlation ID, user ID when known, event type, risk band/reason codes, provider status, action, and timestamps in the security audit trail. Do not store passwords, cookies, access/refresh tokens, sealed payloads, raw IP by default, or the full provider response.
- Provider event IDs remain in the replay-claim table for 24 hours. Risk-decision history stores no provider event ID. A daily Worker Cron removes observations older than 30 days, risk decisions and inactive device records older than 90 days, expired replay claims, and old rate-limit counters, even while risk evaluation is disabled. The cleanup processes existing tables even if the application schema is only partially initialized. The 90-day retention of reasons/user IDs needs privacy-owner approval.
- The one-year D1 audit-event retention is a separate product requirement and is not enforced by this Fingerprint cleanup job.
- Store trust/revocation state and replay claims in D1. Verify uniqueness under concurrent requests and measure read/write volume, latency, quotas, and provider cost before enforcement.
- Alert operators on sustained provider failures, unexpected missing-signal rates, sudden risk-action spikes, replay attempts, and audit-write failures. Review false-positive and false-negative samples under approved access controls.
- Define retention, deletion, consent/notice, data-processing, and jurisdiction requirements with the company privacy owner. Fingerprint's own compliance claims do not decide the company's controller obligations or legal basis.

## Implemented API contract and limitations

For interactive sign-in and passkey verification, the browser-to-Worker request may include:

```json
{
  "fingerprint": {
    "event_id": "<provider-event-id>"
  }
}
```

Login endpoints accept `fingerprint: { event_id }`; `sealed_result` is explicitly rejected. This includes the OPAQUE two-phase login: `/api/opaque/auth/start` carries the event id on the login transcript and `/api/opaque/auth/finish` verifies, claims and evaluates it through the shared gate before issuing a session. Interactive OAuth authorization accepts a `fingerprint_event_id` query parameter only when an authenticated session is already present. A request without a session proceeds to the normal login flow; after login, the authorization request must be continued with a current event in enforce mode. Responses do not reveal provider details or risk rules. A missing event never grants trust or bypasses primary authentication.

Event claims are retained for 24 hours for replay prevention, device/network observations for 30 days, and risk-decision records for 90 days. These are initial technical defaults and still require privacy-owner approval and a deletion policy.

## Rollout and open prerequisites

1. Provide Fingerprint credentials and select region; complete privacy/notice review and set a budget.
2. Add browser event correlation; no frontend was included in this backend change.
3. Add an independent step-up/recovery mechanism before enforcing step-up outcomes; do not enable `enforce` without a tested recovery route.
4. Run observe mode and calibrate thresholds against false positives, provider outages, and expected D1/provider cost.
5. Verify D1 concurrency and real login/new-session-revocation flows before production enforcement.

## Sources

- [Fingerprint Quick Start](https://docs.fingerprint.com/docs/quick-start-guide.md)
- [Account Takeover tutorial](https://docs.fingerprint.com/docs/account-takeover-use-case-tutorial.md)
- [Identification accuracy and confidence](https://docs.fingerprint.com/docs/identification-accuracy-and-confidence.md)
- [Server-side intelligence](https://docs.fingerprint.com/docs/get-server-side-intelligence.md)
- [Sealed Client Results](https://docs.fingerprint.com/docs/sealed-client-results.md)
- [Protecting from client-side tampering and replay](https://docs.fingerprint.com/docs/protecting-from-client-side-tampering.md)
- [Get event Server API](https://docs.fingerprint.com/reference/server-api-get-event.md)
- [Privacy and compliance](https://docs.fingerprint.com/docs/privacy-and-compliance.md)
