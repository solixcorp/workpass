# Secure Web Authentication (SWA) workflow (Phase 5)

**Status:** backend-only implementation of the authorization and audit authority. Portal and extension UI are excluded by product direction.

## Security design

**The identity provider never sees or stores the application credentials.** Secure Web Authentication supports web applications that lack federation: the controlled workflow is that the identity platform is *the authority* deciding who may be automatically signed in where, while the captured application credentials remain with the user's own agent and never pass through, or get logged by, the IdP. This removes the credential-vault exposure class entirely rather than mitigating it.

| Layer | Responsibility | Safeguards |
|---|---|---|
| IdP (this backend) | Registers SWA applications by exact origin; issues short-lived, single-use, browser-session-bound grants; records visible grant and revocation audit events | `https:`-only exact-origin registration, no credentials or fragments; grants expire in five minutes; consumption is atomic and single-use inside one statement; every mutation audited with actor, target and outcome |
| User agent (extension/local, future client) | Holds the captured application credentials locally, exchanges a grant once, then signs the user into the application origin | Must prove possession of the grant nonce; the exchange binds application origin byte-exactly |
| Application origin | Receives the user's own sign-in form | Receives credentials only from the user's own agent at its own trusted origin — never from the IdP |

## Workflow

1. **Application registration.** An administrator registers an SWA application with `{name, origin}`; names are 1–64 characters from `[A-Za-z0-9_.-]`, the origin is an exact `https://host` (no paths, credentials, fragments), and the registration is created disabled. Enablement, disablement and deletion follow the same deliberate two-step lifecycle as the other managed-application surfaces; all mutations are audited (`swa.application.*`).
2. **Grant issuance (user-triggered).** An authenticated user requests `POST /api/swa/grants` with the application's exact origin. The IdP checks the registration is enabled and origin-exact, and writes an atomic grant: nonce, user, application, five-minute expiry, audit `swa.grant.issue` with the user as actor and the application as target.
3. **Grant exchange (agent proves possession).** `POST /api/swa/exchange` consumes the nonce in one atomic, single-use statement, refusing replays and unknown or expired nonces, binding the application origin byte-exactly, and returning the attestation (application, user, expiry, audit `swa.grant.exchange`).
4. **Revocation and visibility.** Disablement and deletion of an application immediately stop new grants; a grants-per-application listing gives the visible-activity view used for offboarding; audit rows are the tamper-evident record.

## Why not a credential vault

Storing shared application passwords would concentrate every application's credentials into one database with a backup/immutability surface that the recorded open question about backup controls has not resolved. Not accepting credentials at all means the enumeration of data collected shrinks to nothing and the strongest available protection is structural. If a vault is ever demanded, it is a separate product decision with its own security review.

## What remains open

- The browser-side client (extension or user script) is a future client; only the IdP contract exists here.
- Real SaaS targets and their browser flows (QST-...-84w).
- Grant policy beyond user-triggered issuance (pools, group-based auto-entitlements) — an application binding plus release policy decision.
- Credential capture UX and any credential storage would be a separate reviewed design.
