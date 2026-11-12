# Email provider abstraction

Transactional email (account invitations, two-factor OTP) is delivered through
one of five providers, selected per deployment by environment configuration.
There is no SMTP library dependency: the SMTP transport is an in-repo client
adapted from the MIT-licensed [worker-mailer](https://github.com/zou-yu/worker-mailer)
(zou-yu, Copyright (c) zou-yu) — one message per connection, implicit TLS
(465) or STARTTLS (587), AUTH PLAIN / AUTH LOGIN, negotiated only against what
the server advertises. When STARTTLS is selected (including the port 587
default), the server must advertise STARTTLS and the TLS upgrade must succeed
before authentication or message delivery. Missing STARTTLS or a failed
handshake throws a delivery error; there is no plaintext fallback. Implicit
TLS and deliberately selected plaintext transports are unchanged.

## Selection

`MAIL_PROVIDER` names the provider; an unknown value fails loudly. When it is
unset, a deployment with only `RESEND_API_KEY` keeps using Resend (the
pre-selection default). With neither — or with a selected provider missing
credentials — delivery throws and callers surface the error; no path silently
drops a message.

| `MAIL_PROVIDER` | Delivery | Required configuration |
| --- | --- | --- |
| `smtp` | Generic authenticated SMTP relay (Cloudflare `smtp.mx.cloudflare.net:465`, Maileroo relay, corporate smarthost …) | `MAIL_SMTP_HOST`; optionally `MAIL_SMTP_PORT` (465 → implicit TLS, 587 → STARTTLS by default), `MAIL_SMTP_SECURE` (`true` forces implicit TLS, `false` + no STARTTLS is a deliberate plaintext opt-in), `MAIL_SMTP_STARTTLS`, `MAIL_SMTP_USERNAME`/`MAIL_SMTP_PASSWORD` |
| `resend` | Resend HTTP API, `https://api.resend.com/emails` | `MAIL_RESEND_API_KEY` (legacy `RESEND_API_KEY` still works) |
| `cloudflare` | Email Sending REST API, `POST /accounts/{account_id}/email/sending/send` | `MAIL_CLOUDFLARE_ACCOUNT_ID`, `MAIL_CLOUDFLARE_API_TOKEN` (API token with **Email Sending: Edit**) |
| `maileroo` | Maileroo basic email API, `POST https://smtp.maileroo.com/api/v2/emails` (template endpoints unused) | `MAIL_MAILEROO_API_KEY` (domain sending key) |
| `ses` | Amazon SES v2, `POST /v2/email/outbound-emails`, SigV4 signed with Web Crypto (no SDK) | `MAIL_SES_REGION`, `MAIL_SES_ACCESS_KEY_ID`, `MAIL_SES_SECRET_ACCESS_KEY` (standard `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` fall back); `MAIL_SES_ENDPOINT` overrides the endpoint |

Sender identity: `MAIL_FROM` / `MAIL_FROM_NAME` / `MAIL_REPLY_TO` are the
generic defaults. Purpose-specific variables win above them:
`INVITATION_EMAIL_FROM` for invitations, `MFA_OTP_EMAIL_FROM` for OTP. A
missing sender address fails closed even with provider credentials.

## Dev and testing overrides

The per-purpose dev/webhook channels keep their precedence above providers:

- `INVITATION_EMAIL_WEBHOOK_URL` — records the invitation message as JSON
  (`{to, subject, text, from, sentAt}`) at any receiver URL.
- `MFA_OTP_EMAIL_WEBHOOK_URL` — same pattern, and the body keeps the raw code
  alongside the message (`{to, userId, otp, sentAt}`) for headless receivers.
- `ENABLE_DEV_MOCKS=true` additionally exposes the built-in mock mailbox at
  `/dev/mocks/invitation-email` (never on production deployments).

## Module layout

- `src/mail/provider.ts` — message model, provider interface, env resolution
  and registry (`MAIL_PROVIDER_IDS`, `resolveMailProvider`).
- `src/mail/send.ts` — purpose-agnostic dispatch (`deliverMessage`: webhook
  precedence, fail-closed gates, Reply-To) plus the invitation wrappers.
- `src/mail/providers/resend.ts`, `cloudflare.ts`, `maileroo.ts`, `ses.ts`,
  `smtp.ts` — one module per provider; each exports `id`, `isEnabled(env)`,
  `requiredEnv`, `send(env, message)`.
- `src/mail/providers/smtp/client.ts` — vendored transport over
  `cloudflare:sockets` (lazily imported so bun tests never require a worker
  runtime); `smtp/mime.ts` — MIME assembly (quoted-printable bodies, RFC 2047
  headers, dot-stuffing).
- `src/mfa/otp-senders.ts` — OTP/SMS routing onto the shared dispatch.

Adding a provider: implement the `MailProvider` interface in
`src/mail/providers/`, register it in `src/mail/provider.ts`, add its env
variables to `src/env.ts` and this document, and cover its request shape in
`tests/mail-providers.test.ts`.

## Private CA / custom TLS certificates (not supported)

authentik-style "SMTP server with TLS verification" — mounting a private CA
bundle and pointing `SSL_CERT_FILE` at it — is not available on this
platform. Workers have no mountable filesystem, and the `cloudflare:sockets`
TLS layer validates against the platform's built-in public root CAs only:
there is no option to inject a custom CA or skip verification. Connecting to
an SMTP server whose certificate is signed by a private CA fails at TLS
validation. Deployments that need such a relay should point `MAIL_SMTP_*` at
a hop with a publicly trusted certificate (or deliberately choose
`MAIL_SMTP_SECURE=false` for a credential-less internal-network relay).

## Operations notes

- Providers verify sender-domain ownership out of band (Resend domain, SES
  verified identity, Cloudflare onboarded Email Sending domain, Maileroo
  verified domain). The IdP does not manage DNS records; fail the deployment
  checklist item until the first message is confirmed received.
- SES signing key material and every API token are deployment secrets — set
  them through `wrangler secret put`, never in `wrangler.jsonc`.
- Delivery failures throw; the routes translate them into 5xx responses and
  audit events. Retry semantics belong to the caller (invitation re-delivery
  is a button; OTP codes are short-lived).
