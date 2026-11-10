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
- **Deliberate exclusions.** Group and account attributes are **not** released: groups are claim-release candidates owned by the later per-application binding and release policy (docs/design/directory-groups.md), and account attributes describe shared objects whose audiences require their own allow/deny decision.

## Per-application claim release policy

The global flags make release possible; a **claim release policy** row decides which kinds one application receives, evaluated as an AND with the flags (a row can only narrow, never widen). Subjects use the same namespace as app-access policies: `saml:<entityId>`, `oidc:<clientId>`, `wsfed:<realm>`. No row keeps the flag-only default, and a policy evaluation failure fails closed. Admin surface: `GET/PUT/DELETE /api/admin/claim-release-policies/{subject}` with `{allowAccountClaims?, allowUserAttributes?}` (absent keys default to allowed), audited (`claim.policy.update`, `claim.policy.delete`).

## What remains open

- Group and account attribute release as claims (user attributes release fully; a per-attribute allow/deny granularity inside a released set would be a further refinement).
- Outbound SCIM attribute push is implemented behind `ENABLE_SCIM_ATTRIBUTE_RELEASE=true`: create/patch payloads to targets carry the user's custom attributes as the `urn:solixcorp:scim:1.0:CustomAttributes` extension (patch as a path-scoped operation, deactivation never carries profile data). Fail-closed default; it is still a deliberate per-target operator decision (privacy review), and attribute changes surface only on the next manually triggered `update` operation — there is no automatic lifecycle trigger yet.
- Update events for attributes (an SSF SET event type would let downstream apps follow changes).
