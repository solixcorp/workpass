# Sign-in password link requests

`POST /idp/idx/request-link` accepts `{ "stateHandle": "02.id.…" }`. The sealed handle must be live and contain the identifier captured during identify; malformed, missing, and expired handles receive the same 401 IDX error as other stateful IDX steps. Valid requests receive HTTP 200 `{ "sent": true }` and `Cache-Control: no-store`, independent of account state. The existing per-client-address IDX limiter can still return 429.

The password challenge advertises a `request-link` link alternative. Work is deferred with the Worker execution context where available. Existing, non-banned, non-locked accounts are sent a one-time activation link (the existing OPAQUE registration flow also replaces an existing password); a per-account hourly budget permits three issuance attempts. Delivery failures, missing accounts, ineligible accounts, and budget exhaustion do not change the response. Each valid-handle request records `identity.user.link_requested` with success; the target is set only for a matching account.

The e-mail identifies the request as coming from the sign-in screen and tells recipients to ignore it if they did not request it. This flow does not unlock locked accounts; those continue to require the separate administrator-controlled account recovery process.
