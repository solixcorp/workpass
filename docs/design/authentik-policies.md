# Authentik-benchmarked policy framework

**Decision inputs:** expression policies run as a custom safe JS-subset interpreter
(termination-guaranteed; no `eval`); zxcvbn is replaced by an embedded lightweight
strength estimator (no new dependency); AKQL support is the documented-operator
subset (all comparison operators, and/or + parens, typed values, dot-notated paths)
without `not`-prefix or autocomplete surfaces; execution follows the
authentik binding model (ordered bindings, `all`/`any` modes, negate,
failure-result, pass-if-no-bindings, disabled skip) with a **step budget in place
of wall-clock timeouts** (Workers cannot kill synchronous execution).

## Deviations from authentik (documented, deliberate)

- **No flows/stages/sources.** Policies bind to the surfaces this platform has:
  `application` (protocol-qualified subjects), `login` (the shared login
  pipeline gate), `password_entry` (every password set/change/reset), `user_write`
  (admin create, SCIM inbound create, invite join), and `notification_rule`.
  The authentik recipes that need a flow engine (`source_switch`, flow-plan
  context mutation) are out of scope; `unique_email` and `whitelist_email` are
  supported as expression policies at the `user_write`/`password_entry` points.
- **Timeouts are step budgets.** Each policy execution gets a bounded number of
  interpreter steps; exhaustion is a policy error, routed through the binding's
  failure result.
- **`ak_create_jwt` is not provided** (token issuance is a platform concern);
  Python-only conveniences that need a request object (`requests` session) are
  replaced by nothing — expression code cannot make arbitrary network calls.
- **Expression language is JavaScript**, mirroring the authentik example style
  (`return request.user.username !== null`). The helper names keep the `ak_`
  prefix for recognizability.

## Security posture

- The interpreter resolves identifiers only from: locals, the context object,
  allowlisted namespaces (`request`, `context`, `Math`, `JSON`, `Number`,
  `String`, `Boolean`, `Array`, `Object`, `Date`), and the provided helpers.
  Member calls beyond data values go through a fixed method allowlist and only
  on plain-data receivers.
- Every evaluation consumes steps from a budget; loops are bounded by the same
  budget. There is no path to host globals, `eval`, `import`, `globalThis`, or
  dynamic code text.
- Policy evaluation failures follow the binding's failure result; default fail.
- The step budget also bounds AKQL evaluation (parser + evaluation share a cap)
  so a pathological query cannot stall a request.

## Model

- `policies` — id, name (unique), type (`expression`, `password`, `password_expiry`,
  `password_uniqueness`, `reputation`, `geoip`, `event_matcher`), config JSON
  (validated per type), enabled, execution_logging.
- `policy_bindings` — target (`application` | `login` | `password_entry` |
  `user_write` | `notification_rule`), target_ref (subject id or rule id),
  policy_id **or** direct bind (`bind_user_id` / `bind_group_id`), order, mode
  (`all`/`any`, the target-wide convention read from the lowest-order binding),
  negate, failure_result (`fail`|`pass`), enabled.
- Evaluation: ordered (order asc), disabled skipped, empty set passes, messages
  collected across bindings, negate flips only the boolean.
- `login` and `password_entry` are global: their canonical `targetRef` is `""`;
  omission means the same thing, while nonempty aliases are rejected. Existing
  nonempty bindings must be reviewed and recreated with the empty reference.
  Notification bindings instead use the notification rule ID.
- Login-pipeline integration: the login gate (fingerprint/risk pipeline) consults
  `login` bindings before issuing; application access consults `application`
  bindings in `evaluateAppAccess` (account gate → group gate/temporal grant →
  bound policies).
- Password integration points: plaintext bootstrap and better-auth password
  create, set, change and reset are checked by the server against bound policies.
  Plaintext login checks the login surface, not password quality on every login.

### OPAQUE password enforcement scope

OPAQUE activation and password change send a registration record, not plaintext;
the server cannot cryptographically infer or verify its password complexity or
reuse. Browser checks are advisory and a modified client can bypass them; this
residual risk is intentional and visible to policy owners. Activation currently
does not itself call the browser password checker. The administration rules API
reports `enforcementScope` separately for plaintext writes and each OPAQUE flow.
Server verification is subject to the configured binding mode and failure result;
no bindings means pass. Admin user creation issues an activation link without
accepting a password.

## Typed policies

| Type | Enforces | Notes |
|---|---|---|
| `password` | min length, per-class minimums, symbol set, HIBP range check, lightweight strength score (repeats, sequences, keyboard rows, top-common list, leet normalization) → 0–4 minimum score | Reads the configured password field from context; fails with user-visible messages |
| `password_expiry` | days since last change; `deny_only` otherwise additionally marks the password unusable | `password_meta` tracks last change; unusable passwords fail sign-in until reset |
| `password_uniqueness` | prevents reuse of the last N passwords | `password_history` stores per-entry PBKDF2 digests of the plaintext; comparisons are capped by the policy count |
| `reputation` | IP and/or username score ≥ threshold ⇒ fail | `reputation_scores` ledger, ±1 on login outcomes, entries expire (settings) |
| `geoip` | country/ASN allow or deny, distance vs recent login observations, impossible travel | Reuses the GeoIP engine and device-observation history; data unavailable ⇒ policy error (failure result applies) |
| `event_matcher` | action / app / client_ip exact fields + AKQL query over the event projection | `audit_events` gains `client_ip` + `event_context` columns with hash-chain v2 (both fields covered by the tamper hash) |
| `expression` | arbitrary bounded JS | Full helper set below |

## Expression environment

`request` (`user` = resolved user object snapshot, `context` = mutable dict),
`context` (aliased request context), `ak_client_ip`, `ak_is_sso_flow` (false in
this platform — no external sources), helpers: `ak_message`, `regex_match`,
`regex_replace`, `list_flatten`, `ak_call_policy` (with kwargs into
`request.context`), `ak_is_group_member`, `ak_user_by`, `ak_user_has_authenticator`
(totp/duo/static/webauthn), `ak_create_event`, `ak_send_email` (shared
transactional mail), `ip_in_subnet`, `resolve_dns`/`reverse_dns` (DoH, 32-entry
3-minute cache), `ak_logger` (console).

## Events & notifications

`notification_rules` bind event-matcher policies (the `notification_rule`
target) and transports (`webhook` URL or `email` recipient via the shared mail
module). `insertAuditEvent` enqueues matched rules into `pending_event_notifications`
(best-effort, never blocks the audit write); a scheduled dispatcher drains the
queue. AKQL is available on the events listing as a `search` parameter using the
same evaluation.

## What remains out of scope

Flow-plan mutation, source routing (`source_switch`), brand context, live
Tailscale source interop. AKQL autocomplete. Wall-clock policy timeouts.
`ak_create_jwt`.
