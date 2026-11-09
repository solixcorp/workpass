# WS-Federation passive profile (Phase 5)

**Status:** backend-only implementation; no portal or browser UI is included by product direction.

## Supported subset (narrowly documented)

This identity provider implements exactly one WS-Federation flow for legacy applications and nothing else:

| Endpoint | Behavior |
|---|---|
| `GET /wsfed/signin` | Passive sign-in endpoint. |
| `GET /wsfed/metadata` | Federation metadata (entity descriptor with the signing key and passive requestor endpoint). |
| `wa=wsignout1.0` | Simple local cleanup page only; no federated cleanup is issued by this profile. |

## Sign-in request handling (`wa=wsignin1.0`)

1. **Realm resolution (untrusted).** `wtrealm` resolves an *enabled* relying-party registration; unknown or disabled realms produce a generic 401 that reveals nothing.
2. **Reply validation.** `wreply`, when present, must equal the registered reply URL byte-for-byte; when absent, the token goes to the registered reply URL. There is no open-redirect surface: every delivery destination is the stored URL.
3. **Session (mandatory).** An issuer-visible session is required; without one the same-origin sign-in page is rendered and the browser reloads the same request after sign-in. The authentication timestamp comes from the session's creation time and is validated for sanity.
4. **Context.** `wctx` is opaque, echoed back bounded to 256 bytes, and never interpreted.
5. **Issue and audit.** The signed token is posted to the registered reply URL behind one audited unit (`wsfed.token.issue` with the signing user as actor and the relying-party registration as target). The content security policy locks scripts to inline only and the form action to the reply URL's origin.

## Issued token shape

`wresult` is a WS-Trust `RequestSecurityTokenResponse` carrying a bearer **SAML 1.1** assertion:

- `TokenType` `urn:oasis:names:tc:SAML:1.0:assertion`; `RequestType` `Issue`; `KeyType` `BearerKey`.
- Lifetime: five minutes with a thirty-second back-clock on `Created`/`NotBefore`.
- Assertion: `MajorVersion 1 / MinorVersion 1`, issuer set from the shared `SAML_IDP_ENTITY_ID`, conditions with `AudienceRestrictionCondition` limited to the registered realm, one `AuthenticationStatement` with the password authentication method and the account email as the `NameIdentifier` (`emailAddress` format), bearer subject confirmation.
- Signature: enveloped RSA-SHA256 with exclusive canonicalization, digest over the assertion with the Signature element removed by the enveloped transform, `KeyInfo` embedding the signing certificate. The XML is canonical by construction, so relying parties recompute the same digest over the same bytes.

The signing pair is the shared WebCrypto key configured via the three `SAML_IDP_*` values and checked for a private/certificate match at load time. Key lifecycle (rotation, revocation) remains the recorded owner-policy gap.

## Replay protection

WS-Federation passive sign-in carries no signed request from the application: the relying party protects its own sessions and bearer-token replay (clock window plus its session binding). This profile relies on that party-side protection rather than an IdP claim, and this limitation is documented rather than hidden.

## What remains open

- Real service-provider interoperability with a legacy WS-Federation relying party (their token validation, decryption — none offered — and client behavior). Headless verification covers the IdP's own conformance only.
- Federated sign-out cleanup (`wcleanup1.0` or token-cancellation) unsupported by this subset.
- Attribute claims beyond the email identifier are not released by this profile; an application binding would be required.
- Key rotation with overlap; certificate expiry checks on the relying party's side.
