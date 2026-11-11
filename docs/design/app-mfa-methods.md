# Application MFA methods

Application policies store `mfaMethods` as a comma-separated set. Supported IDs are `totp`, `hotp`, `duo`, `passkey`, `email`, and `sms`. An empty list retains the existing rule: any session-bound MFA proof suffices. The migration gives existing policies an empty list and existing proof rows an `unknown` method. Unknown proofs satisfy only an empty list. A non-empty list is retained but inactive while `requireMfa` is false. Observe-mode policies may save globally unavailable methods.

Admin GET/PUT `/api/admin/app-access-policies` use `mfaMethods` arrays. GET also supplies `availableMfaMethods` with Korean labels and global availability. Email and SMS share the global OTP switch; SMS also requires an SMS provider and email requires transactional email availability. Passkey availability follows the global passkey switch and the WorkPass sign-in policy. In enforce mode, a required method that is unavailable globally is rejected on save.

Proofs contain an accumulating set of methods scoped to a session token and user. OTP send records an HMAC of the code, its channel and send time; a successful verification uses the matching unexpired channel (three minutes, the configured Better Auth default). Neither OTP nor its plaintext is stored in the channel table. Missing or ambiguous channel metadata yields `unknown`. Backup codes also remain `unknown`.

`passkey` means the session was created with a user-verifying passkey assertion. The passkey plugin requires user verification. Current step-up has no in-session WebAuthn assertion, so passkey-only remediation tells the user to sign in again with a passkey. A full step-up needs a session-bound, replay-protected WebAuthn challenge and assertion verification, a proof write for the acting session, and matching client UI.

An app-specific challenge can be requested with `GET /api/security/step-up/challenge?subject=<encoded-policy-subject>`. It returns `requiredMethods`, usable `methods` and UI on a 403, or a Korean denial with `requiredMethods` when no method can be offered. OTP currently routes to a verified phone first, otherwise email, so an account with a verified phone is not offered email until channel selection is implemented. The UI maps `email`/`sms` to the existing `otp` control and `duo` to `duo_push`; backup codes are not offered for specific app methods.

HOTP and Duo verification sites must pass their method names to `recordSessionMfaProof`; until the separate in-progress changes are integrated, those verifications record `unknown` and cannot satisfy a specific app method.
