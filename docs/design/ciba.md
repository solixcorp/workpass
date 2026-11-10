# OpenID CIBA poll mode

Client-Initiated Backchannel Authentication, **poll mode only**: the client
authenticates to the backchannel endpoint, the server notifies the user, and
the client polls the token endpoint. There is no browser redirect anywhere in
the flow. Fail-closed behind `ENABLE_CIBA=true` — the backchannel endpoint,
the approval page, the discovery advertisement, and the token grant all check
the flag; unset, every route 404s and the grant type is absent from the
provider.

## Flow

1. `POST /api/auth/oauth2/bc-authorize` (form-encoded). The client
   authenticates with `client_secret_basic` or `client_secret_post`
   over the provider's hashed-secret storage; **CIBA clients must be
   confidential** — clients registered with `tokenEndpointAuthMethod: "none"`
   are refused (`invalid_client`), and the client's registration must include
   the grant `urn:openid:params:grant-type:ciba`.
   - `scope` (required; subset of the client's registered scopes),
   - `login_hint` (required; exact case-sensitive email or username — exactly
     one account must match, otherwise `unknown_user_id` and nothing is
     created; banned accounts fail closed the same way),
   - `binding_message` (optional, ≤ 128 chars, control characters stripped —
     shown to the user verbatim on the approval page),
   - response: `{ auth_req_id, expires_in: 300, interval: 5 }`
     (`Cache-Control: no-store`).
2. Notification is best-effort email (`sendTransactionEmail`) pointing at
   `/ciba`; a delivery failure is logged, never fatal — the approval page
   always lists the pending requests, so the notification is an accelerator,
   not a dependency.
3. The user signs in through the organization's portal (the approval page
   never collects credentials; an unauthenticated visit gets a guidance page,
   not a sign-in form) and opens `GET /ciba` (script-independent HTML form):
   every pending request shows the client name, the binding message, and the
   requested scopes, with Approve / Deny posting to `/api/ciba/decide`
   (session cookie required, form-only). Decisions are single-shot (the
   conditional update makes double-approvals no-ops).
4. The client polls `POST /api/auth/oauth2/token` with
   `grant_type=urn:openid:params:grant-type:ciba`, authenticating
   confidentially through the provider (basic/post/assertion — all methods
   supported, but the client must be registered for the grant). Lifecycle:
   pending → `authorization_pending`; polling faster than `interval` →
   `slow_down`; denied → `access_denied`; approved → tokens issued exactly
   once; expired → `invalid_grant`.

## Storage and fail-closed properties (`oauth_ciba_requests`)

- `auth_req_id` is a 43-character random token stored **only as a SHA-256
  digest**. The approval surface only ever sees the digest (`request.id`), so
  the bearer value never crosses from the client to the user page.
- Caps: at most 5 pending requests per user and 20 per client; past a cap the
  endpoint answers 429, not another request.
- Approved tokens bind `sessionId` from the approving browser session
  (offboarding-safe), and the user's ban state is re-checked at the token
  moment (`invalid_grant` when banned).
- Expired and decided rows are removed by the daily scheduled cleanup
  (`cleanupCibaRequests`); cleanup runs regardless of the flag.

## Deliberate limits

- Poll mode only: this deployment's notification surface is email, and push
  delivery modes (ping) add a reverse-channel requirement nobody needs yet.
- Client authentication at the backchannel endpoint honors
  `client_secret_basic` and `client_secret_post` **on exactly the registered
  channel** — a client registered with `client_secret_post` cannot present
  its credentials through Basic and vice versa (live-verified; the provider's
  token endpoint enforces the same). Assertion methods (`private_key_jwt`…) do
  authenticate at the token endpoint through the provider, but the backchannel
  endpoint does not verify client JWT assertions yet — treat that as future
  work if FAPI-grade assertions are actually needed.
- `unknown_user_id` is answered for unknown, ambiguous, and banned identities
  alike — the endpoint does not disclose which.

## Auditing

`authentication.ciba.client_auth_failed` (bad client), `.unknown_or_banned_user`,
`.request_created`, `.approved` / `.denied`, `.token_issued`. No issuance
without a successful audit write.

## Verification

`tests/oauth/ciba.test.ts` (store: roundtrip, single-use, user cap and
slot-freeing, cleanup, binding-message sanitization) and
`tests/oauth/extended-grants.test.ts` (grant lifecycle: single-use issuance,
pending/slow_down, wrong client, public client refusal, flag-off fail-closed,
malformed bodies).

### Live HTTP verification (2026-11-10, local worker)

The full poll-mode CIBA flow was driven end-to-end over real HTTP against a
DCR-registered confidential client:

- discovery advertises `backchannel_authentication_endpoint` and
  `backchannel_token_delivery_modes_supported: ["poll"]` only while
  `ENABLE_CIBA=true`;
- `bc-authorize` (by email and by username `login_hint`) → pending poll →
  `authorization_pending` → approval through the signed-in `/ciba` page form →
  confidential token request → tokens (Bearer + ID token, requested scope) →
  introspection reports `active` with the approving session's `sid` → a second
  poll is `invalid_grant` (single-use); channel mismatch (Basic credentials
  for a `client_secret_post` client) is rejected `invalid_client` at the
  backchannel endpoint exactly like the token endpoint.

Not yet exercised live: notification email delivery (no provider configured
in the local deployment — the notification is best-effort by design).
