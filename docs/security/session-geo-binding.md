# Session Network/GeoIP Binding

**Model:** authentik's User Login stage session bindings
(<https://docs.goauthentik.io/security/security-hardening/>; "session GeoIP binding"), adapted to
this Worker stack. This is the session-side half of the GeoIP model; do not confuse it with the
login-time GeoIP history checks in [device risk policy](device-risk-and-trust.md):

- Login-time checks decide whether a *new login* is granted.
- Session binding decides whether an *already issued session* may keep working when it is used
  from a network or location other than the one that created it. A stolen session cookie replayed
  from another network never passes a login flow, so only the binding catches it.
  They must both exist; neither alone closes the takeover window.

## Configuration

| Variable | Values | Default | Meaning |
|---|---|---|---|
| `SESSION_BINDING_MODE` | `disabled` / `observe` / `enforce` | `disabled` | `observe` records drift without terminating; `enforce` terminates the session. |
| `SESSION_BINDING_NETWORK` | `off` / `asn` / `asn_and_ip` | `off` | Authentik's ASN / ASN+network / ASN+network+IP ladder; our only network identity is the IP, so the upper two tiers coincide here. |
| `SESSION_BINDING_GEOIP` | `off` / `country` / `country_and_city` | `off` | Authentik's continent / continent+country / continent+country+city ladder; continent is not tracked, so the levels are country/city based. |

## How it works

- At session creation (Better Auth `databaseHooks.session.create.after`) the envelope is stored in
  `session_network_bindings`: keyed HMAC digests of the client IP, ASN, and city, plus the country
  code. The raw IP and city string are never stored.
- Client data comes from the Cloudflare edge context (`request.cf`, `cf-connecting-ip`) — derived
  from the request IP at the edge, never from client-supplied `X-Forwarded-For`-style headers.
  If a reverse proxy sits in front of the Worker, configure the real proxy addresses with Cloudflare
  trust settings so the observed client IP is genuine; the same spoofing hazard authentik's
  `TRUSTED_PROXY_CIDRS` covers applies here.
- The envelope records which strictness levels were configured *at binding time*, so a later
  configuration change can never turn existing sessions into instant violations.
- Evaluation happens on interactive identity surfaces only (`/api/auth/get-session`,
  `/api/auth/oauth2/authorize`, `/api/auth/oauth2/consent`), consistent with the codebase policy
  of attaching risk to identity boundaries rather than every request.
- A violation in `enforce` deletes the session row (immediate sign-out everywhere for that cookie)
  and writes the audit event `authentication.session.location_violation`; observe writes
  `authentication.session.location_drift.observe`. Session termination is the durable protection;
  the audit row is best-effort.

## Documented deviations from authentik

- **Missing envelope is allowed.** Sessions that predate the feature, or sessions created without
  edge data (none in production Workers), run unbound until re-login. Terminating every
  pre-existing session at rollout would be a support incident; new sessions bind immediately.
- **Missing data at evaluation is a violation** when the envelope recorded that level with data
  (authentik-parallel fail-closed), but a level is skipped entirely when the *stored* envelope was
  captured without the data for it.
- **City tolerance.** When the edge reports no city for the current request, the decision falls
  back to country equality. At the `country_and_city` level, any observed city on a session whose
  envelope was bound without a city is a violation (the city cannot be matched).

## Operational starting points (from authentik's hardening guide)

- Office/home fixed lines: Network `asn_and_ip`, GeoIP `country` (or `country_and_city`).
- Mobile/travel: Network `asn`, GeoIP `country`.
- Always-on-VPN users: loosen the levels or expect drift events for the VPN egress ASN; start in
  `observe` and read the drift audit events before enforcing.
- ASN and IP moves are location-move **detection**, not replay protection.

Related: `src/security/session-geo-binding.ts`, `session_network_bindings` table, cron cleanup
(30 days) wired in `src/index.ts`.
