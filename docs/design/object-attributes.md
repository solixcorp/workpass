# Custom object attributes design

**Status:** implemented backend foundation; user attribute release into protocol tokens gates behind an operator flag. Group/account attribute release stays open.

## Goal and non-goals

Operators can attach operator-defined properties ("custom attributes") to the supported object types — Better Auth users, directory groups, and accounts — and manage them through one administration API. Non-goals for this phase: SCIM extension schemas or attribute passthrough on the inbound/outbound SCIM surfaces, releasing attributes as protocol claims (SAML attributes, OIDC token claims), end-user editable attributes, and per-attribute definitions/schema registry.

## Storage model

- **One flat JSON object per object.** `object_attributes` keys on `(object_type, object_id)` — `object_type` is constrained to `user`, `group`, `account` — so all attribute logic is one table with one upsert, never per-attribute churn across joins. An empty set removes the row: no tombstones.
- **Values are JSON primitives only** (string, number, boolean, null). Nested objects, arrays, and opaque structures are rejected at the write path, keeping any downstream consumer (audit exports, future claim release) simple.
- **Validation bounds:** keys 1–64 characters from `[A-Za-z0-9_.:-]`; strings at most 512 characters and control-character free; numbers finite within the safe-integer range; at most 32 entries; the serialized object at most 4096 bytes.
- **Referential check:** the addressed object must exist in its owning table (`user`, `directory_groups`, `accounts`) before a write is accepted.
- **Lifecycle ties:** deleting a directory group or an account deletes its attribute row in the same D1 batch as the object. Users are Better Auth-owned rows and outlive deactivation by design, so user attributes are cleared explicitly, not by lifecycle triggers.

For users, the identity-source-of-truth rule still holds (docs/design/directory-groups.md): attributes are supplementary operator data, never a second copy of identity fields Better Auth already owns (`email`, `username`, `role`, ban state).

## Administration API

All routes live under `/api/admin/attributes/{objectType}/{objectId}` with `objectType` ∈ `user|group|account`, require an administrator session and the exact configured `Origin` for writes, and are audited (`attributes.set`, `attributes.delete`). Reads are session-gated but not audited, matching the other admin read routes.

| Method and path | Behavior |
|---|---|
| `GET /api/admin/attributes/{objectType}/{objectId}` | `{objectType, objectId, attributes, updatedAt}`; 400 on an unsupported type, 404 when the object does not exist, `{}` attributes when none are set. |
| `PUT /api/admin/attributes/{objectType}/{objectId}` | `{attributes}` replaces the whole set (an absent key is removed). 201-equivalent 200 with the stored set; 400 on any validation failure; 404 on an unknown object. |
| `DELETE /api/admin/attributes/{objectType}/{objectId}` | 200 with `{deleted: true}`; idempotent (also 200 when no attributes existed). |

Group reads surface the attributes inline: `GET /api/admin/directory-groups/{id}` includes `attributes` on the group object.

## Attribute release into protocol tokens

`ENABLE_ATTRIBUTE_CLAIMS=true` releases the **acting user's** attributes with the token issuance, always fail-closed:

- **Surfaces.** The same claim surfaces as active-account claims: OIDC access/ID tokens (and the UserInfo response entry point), the JWT plugin payload, and SAML 2.0/WS-Federation assertion attributes at `/saml/sso` and `/wsfed/signin`.
- **Shape.** One URI-namespaced JSON claim `<IdP origin>/claims/attributes` carrying the flat attribute object (primitive values, `null` included); SAML emits one simple-string attribute per entry named `<origin>/claims/attributes/<key>`, skipping `null` entries and stringifying primitives.
- **Deliberate exclusions (superseded):** group and account attributes initially stayed unreleased; they now release under their own policy columns (below).

## Per-application claim release policy

The global flags make release possible; a **claim release policy** row decides which kinds one application receives, evaluated as an AND with the flags (a row can only narrow, never widen). Subjects use the same namespace as app-access policies: `saml:<entityId>`, `oidc:<clientId>`, `wsfed:<realm>`. No row keeps the flag-only default, and a policy evaluation failure fails closed. Admin surface: `GET/PUT/DELETE /api/admin/claim-release-policies/{subject}` with `{allowAccountClaims?, allowUserAttributes?, allowAccountAttributes?, allowGroupAttributes?, attributeAllowlist?}` (absent keys default to allowed; the optional allowlist releases only listed user-attribute keys), audited (`claim.policy.update`, `claim.policy.delete`).

## Group and account attribute release

Within a token, the active account's attribute set is released as `<origin>/claims/account-attributes` (an AND of `ENABLE_ACCOUNT_CLAIMS` and the policy's `allowAccountAttributes`), and the acting user's own directory groups' attributes as `<origin>/claims/group-attributes` (an AND of `ENABLE_ATTRIBUTE_CLAIMS` and `allowGroupAttributes`), deterministically capped to a 4 KiB bundle in ascending group-id order. On SAML 2.0/WS-Federation they surface as per-key attribute URNs (`.../attributes-account/<key>`, `.../attributes-group/<groupId>/<key>`). Group membership changes or group-attribute writes take effect on the next token issuance; empty sets release no claim.

## Scope-gated standard claims (phone, groups)

The provider advertises two release scopes on top of the identity trio, both flow only when the client was granted the scope (consented), merged additively into OIDC access tokens, ID tokens, and the UserInfo response by the claim-release extension:

- `phone` → `phone_number` and `phone_number_verified`, straight from the phoneNumber plugin's user record. Standard OIDC scope-based release; no extra flag.
- `groups` → `groups`, the acting user's directory group **names** (not the attribute bundle). It rides the same gate as the group-attribute bundle — the AND of `ENABLE_ATTRIBUTE_CLAIMS` and the policy's `allowGroupAttributes` — so suppressing group release suppresses both shapes. Empty memberships release no claim.

No `address` scope: the user model has no address source. `request_parameter_supported` stays `false`; a client asking for the claims through the OIDC `claims.userinfo` request parameter instead of scopes gets nothing.

## SCIM attribute push and self-propagation

Outbound SCIM attribute push runs behind `ENABLE_SCIM_ATTRIBUTE_RELEASE=true`: create/patch payloads to targets carry the user's custom attributes as the `urn:solixcorp:scim:1.0:CustomAttributes` extension (patch as a path-scoped operation, deactivation never carries profile data). Fail-closed default; it remains a deliberate per-target operator decision (privacy review). User attribute changes are queued automatically when the app has a configured target and attribute release is enabled; unmapped or locked changes are visible as `scim.operation.skipped` audit events with a reason and require operator reconciliation. The scheduled run drains up to 50 operations, oldest first.

## Update events (SSF SET)

Attribute changes emit a SET through the SSF sender when a recipient's registered `event_types` include the URN:

- Event type: `urn:solixcorp:internal-auth:attributes-changed:1.0`; subject identifies the affected object: `{"user": {"user_id": ...}}`, `{"group": {"group_id": ...}}`, or `{"account": {"account_id": ...}}`; event payload `{object_type, object_id, changed_keys (≤ 32)}`.
- Emission points: the attributes admin API (set and delete), and inbound SCIM attribute writes — best-effort; delivery failures land in the bounded-retry delivery rows, never block the attribute write. The sender flag (`ENABLE_SSF_SENDER`) gates all of it.

## What remains open

- The attribute-change event type is this platform's own namespace — standards registration and per-key payload schemas would be a follow-up standardization task.
