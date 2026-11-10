# Device Authorization Grant (RFC 8628)

Device flow for input-constrained clients (CLIs, TVs, printers): the device
posts a client_id, the user approves on a browser page, and the device polls
for tokens. Fail-closed behind `ENABLE_DEVICE_FLOW=true` — the authorization
endpoint, the approval pages, the discovery advertisement, and the token grant
all check the flag; unset, every route 404s and the grant type is absent from
the provider, exactly like the OAuth 1.0a and SSF surfaces.

## Flow

1. `POST /api/auth/oauth2/device/authorize` (public, form-encoded):
   `client_id` + `scope` (required). The client must be registered with the
   `urn:ietf:params:oauth:grant-type:device_code` grant and the requested
   scopes must be a subset of its registered scopes. Response (200,
   `Cache-Control: no-store`):
   `{ device_code, user_code, verification_uri, verification_uri_complete, expires_in: 600, interval: 5 }`.
   A client may hold at most 20 active grants; past the cap the endpoint
   answers 429 `invalid_request`, not another grant.
2. The user opens `GET /device`. The page never collects credentials: an
   unauthenticated visit renders a 403 guidance page ("sign in through your
   organization's portal first, then reopen the verification link"). With a
   session the user types (or follows `verification_uri_complete` to) the user
   code and sees the requesting client name and scopes before
   deciding.
3. Decisions POST `user_code` to `/api/device/flow/approve` or
   `/api/device/flow/deny` (session cookie required). The lookup endpoint
   `/api/device/flow/verify` is **session-required too** — only a signed-in
   user learns what a code is for, so codes cannot be probed without a portal
   session. Both are single-shot: the conditional update makes double-decisions
   no-ops and expired or already decided requests answer 409.
4. The device polls `POST /api/auth/oauth2/token` with
   `grant_type=urn:ietf:params:oauth:grant-type:device_code`.
   Lifecycle per RFC 8628 §3.5: pending → `authorization_pending`; polling
   faster than `interval` → `slow_down`; denied → `access_denied`; approved →
   tokens (issued exactly once, then the grant is `consumed`'); expired →
   `invalid_grant`.

## Storage and fail-closed properties (`oauth_device_grants`)

- `device_code` is a 43-character random token stored **only as a SHA-256
  digest**; the token grant looks up by digest. `user_code` is the
  human surface: 8 characters from an unambiguous alphabet (no 0/O/1/I),
  stored verbatim, `XXXX-XXXX` shaped, normalization accepts lowercase,
  spaces, and missing dashes.
- Issued tokens bind `sessionId` from the **approving browser session**, so
  the device tokens die with the approval session (offboarding-safe, the same
  discipline the rest of the grant surface follows). The user's ban state is
  re-checked at the token moment; banned accounts get `invalid_grant`.
- Poll bookkeeping (`last_poll_at`) is written on every poll; a violating poll
  is answered `slow_down` and the poll clock keeps advancing.
- Expired and decided rows are removed by the daily scheduled cleanup
  (`cleanupDeviceGrants`); cleanup runs regardless of the flag.

## Registration

Register the client for the grant like every other client, e.g. with
`grantTypes` including `urn:ietf:params:oauth:grant-type:device_code` (public
clients use `tokenEndpointAuthMethod: "none"`; confidential ones
authenticate with their registered credentials at the token request).

## Auditing

`authentication.device_flow.authorize` (device), `.verify_failed`
(approval-page lookups of unknown codes), `.approved` / `.denied` (user
decisions), `.token_issued` (token grant). No issuance without a successful
audit write.

## Verification

`tests/oauth/device-flow.test.ts` (store state machine, tolerant user-code
entry, caps, cleanup) and `tests/oauth/extended-grants.test.ts` (grant
lifecycle: single-use issuance, `authorization_pending`/`slow_down`,
`access_denied`, client mismatch, unregistered grant, flag-off fail-closed,
unexpected request fields).

### Live HTTP verification (2026-11-10, local worker)

The full device flow was driven end-to-end over real HTTP (`wrangler dev` +
migrated local D1, DCR-registered confidential client):

- discovery advertises the grant and `device_authorization_endpoint` only
  while `ENABLE_DEVICE_FLOW=true`; `/device/*` routes 404 when the flag is off;
- authorize → `authorization_pending` → (session approval) → token
  (Bearer + ID token, scope narrowed to the requested `openid email`) →
  introspection reports `active`, the issuing client, the subject and the
  approving session's `sid` → a second redemption is `invalid_grant`
  (single-use); fast re-polls surface `slow_down`; unknown codes and other
  clients' grants are `invalid_grant`; a banned subject never receives tokens.

The smoke surfaced and fixed three integration bugs the unit tests could not
cover: the `/api/auth/*` audit middleware shadowing the mounted device/CIBA
routes (fixed by mount order), a form-field mismatch in the approval
endpoints, and backchannel credential-channel parity with the token endpoint.
