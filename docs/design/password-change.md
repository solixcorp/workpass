# OPAQUE self-service password change

This flow requires a live session, the exact configured `Origin` and a fresh OPAQUE proof of the current password. All four requests are POSTs with JSON, same-origin cookies and base64url-encoded (unpadded) protocol messages. Each of the verification and registration phases has a shared per-user limit of 10 requests per minute. Responses are `Cache-Control: no-store`.

## Browser sequence

Use `getOpaqueConfig(OpaqueID.OPAQUE_P256)`, `OpaqueClient` and `ScryptMemHardFn`, as in `web/src/lib/opaque.ts` and `web/src/lib/activation.ts`. The existing exported `opaqueSignIn` and `activateAccount` perform whole different flows; they cannot be called for this change. Their wire helpers are private, so the browser must implement the same base64url encoding/decoding or extract shared helpers.

1. Make an `OpaqueClient`, call `authInit(currentPassword)`, serialize KE1 and POST `/api/me/password/verify-start` with `{ "ke1": "<base64url>" }`. Response: `{ "ke2": "<base64url>", "credentialIdentifier": "<normalized enrolled email>", "serverIdentity": "<origin>", "transcriptId": "<uuid>" }`. Bind the client to the signed-in user's independently known normalized email; do not blindly trust a server-supplied identifier.
2. Call `client.authFinish(KE2.deserialize(config, bytes), serverIdentity, normalizedEmail)`. If the client rejects the password, stop. Otherwise POST `/api/me/password/verify-finish` with `{ "ke3": "<base64url>", "transcriptId": "<uuid>" }`. Response: `{ "confirmed": true, "expiresAt": "<ISO timestamp>", "rules": { "minLength": 12, "minUpper": 0, "minLower": 0, "minDigit": 0, "minSymbol": 0, "symbolSet": "<configured symbols>", "checkHibp": false } }` (values depend on active rules).
3. Check the new password in the browser against the returned rules. Create a new `OpaqueClient` and call `registerInit(newPassword)`. POST `/api/me/password/register-start` with `{ "registrationRequest": "<base64url>" }`. Response: `{ "registrationResponse": "<base64url>", "credentialIdentifier": "<normalized enrolled email>", "serverIdentity": "<origin>" }`.
4. Call `client.registerFinish(RegistrationResponse.deserialize(config, bytes), serverIdentity, normalizedEmail)`. POST `/api/me/password/register-finish` with `{ "record": "<base64url>" }`. Response: `{ "changed": true }`.

The confirmation expires in five minutes and is tied to the session and exact previously verified record; it is consumed atomically with replacement. A new verify-start invalidates an existing confirmation for that session. Transcripts expire in two minutes and are single-use. A failed proof gets 401; absent, expired or used confirmation gets 403; rate limiting gets 429; malformed messages get 400. Origin mismatch gets 403; a missing session gets 401. A wrong password is normally detected locally before a finish request, and thus cannot always produce a server-side failure audit event.

Successful replacement revokes all other IdP sessions and all OAuth access and refresh tokens in the same database transaction, retains the current session and trusted devices, records an audit event and sends the existing best-effort security notice. Application backchannel logout is attempted using a pre-revocation snapshot; delivery is best-effort. Database migrations must be run before enabling this flow. Old first-enrollment `/api/opaque/register/finish` is an insert only; it cannot overwrite an existing record. Administrator-issued activation tokens remain an independent token-authorized replacement path.

## Accepted password-policy limitation

OPAQUE hides the password from the server by design. The server cannot check password complexity, breach-list membership, or equality with the old password using these messages. Browser-only policy checks are explicitly accepted and can be bypassed by direct API callers. The returned rules match activation's browser rules; `checkHibp` is an instruction/indicator, not proof that HIBP was checked. Activation's existing `checkPassword` checks complexity but not HIBP or all server policy features. Do not represent these checks as server-enforced. OPAQUE cannot enforce password reuse history either.

## Other password paths

Unless `ALLOW_PLAINTEXT_PASSWORD_LOGIN` is exactly `true`, HTTP `/api/auth/change-password`, `/api/auth/set-password`, and `/api/auth/admin/set-user-password` return 404. In the explicit plaintext mode they are delegated to better-auth; in the installed version `setPassword` is server-only. Existing better-auth hashes are not removed by this change and remain relevant if plaintext mode is enabled later.

Lockdown deletes OPAQUE credentials. The pre-existing recovery-token redemption accepts plaintext and updates only a better-auth password hash; it does not register an OPAQUE credential. With plaintext login disabled, that recovery alone does not enable sign-in: an administrator-issued activation link can establish a new OPAQUE credential. This pre-existing recovery limitation is not changed by this feature.
