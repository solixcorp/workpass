# E-mail and SMS provider settings

An administrator chooses how e-mail and SMS leave the system in the console ("메시지 발송"). What is saved
there takes the place of the matching deployment variables for every request (cached 30 seconds per
isolate, like the other admin settings); removing it goes back to the deployment's own variables.

## Storage

`delivery_settings` holds one row per kind (`email`, `sms`): the provider, the non-secret values as JSON,
and the secrets as one sealed string (`sealString`, AAD `delivery:<kind>`). Secrets need
`AEAD_SEALING_KEY`; without it the console refuses to save them (`409`) instead of storing them in the
clear. A row that cannot be opened (the key was changed) is ignored and the deployment's variables apply.

Secrets are write-only: the API returns only whether each one is set. Omitting a secret on save keeps the
stored one; switching provider drops the previous provider's secrets.

## Providers

E-mail: Resend, SMTP, Cloudflare Email Sending, Maileroo, Amazon SES (the providers in `src/mail`). A saved
e-mail configuration also replaces the development mailbox webhooks
(`INVITATION_EMAIL_WEBHOOK_URL`, `MFA_OTP_EMAIL_WEBHOOK_URL`) and the per-purpose sender addresses.

SMS (`src/sms/provider.ts`): Solapi (domestic +82 numbers only; HMAC-SHA256 request signing), Twilio, and a
generic webhook (`{ to, code, text, sentAt }`, optional bearer token). `SMS_PROVIDER`, `SMS_FROM` and the
`SMS_*` credentials are the deployment-variable equivalents; a deployment with only
`MFA_SMS_WEBHOOK_URL` keeps working as a webhook. Other gateways (for example NHN Cloud or Naver Cloud SENS)
are added as one function in `sendSms` and one entry in `src/delivery/catalog.ts`.

## API (administrator)

- `GET /api/admin/delivery`: for each kind the source (`console`, `deployment`, `none`), provider, values,
  `secretsSet`, whether it can send; the provider catalog with field definitions; `canStoreSecrets`.
- `PUT /api/admin/delivery/:kind` `{ provider, values, secrets }`; `DELETE /api/admin/delivery/:kind`.
- `POST /api/admin/delivery/:kind/test` `{ to }` sends one real message with what is saved and returns
  `{ ok }` or `{ ok: false, error }`; stored secrets are masked out of the error text.
