# Administrator integration views

All reads below require an administrator session and return `Cache-Control: no-store`, including authentication failures. They do not return bearer tokens, signing keys, SETs, event payloads, delivery errors, URL paths, or URL query strings. Timestamps are ISO 8601 strings or `null`. Lists are snapshots, not transactionally consistent across queries.

## Overview

`GET /api/admin/integrations/status` returns:

```json
{
  "scimOutbound": { "enabled": true, "configured": true, "baseUrlHost": "scim.example.com", "operationCounts": { "pending": 0, "in_progress": 0, "succeeded": 4, "failed": 1, "outcome_unknown": 0 }, "lastActivityAt": "2026-01-01T00:00:00.000Z" },
  "scimInbound": { "enabled": false, "configured": false, "lastActivityAt": null },
  "ssfSender": { "enabled": false, "configured": false, "streamCount": 0, "lastActivityAt": null },
  "ssfReceiver": { "enabled": false, "configured": false, "streamCount": 0, "lastActivityAt": null },
  "claims": { "accountClaimsEnabled": false, "attributeClaimsEnabled": false, "scimAttributeReleaseEnabled": false, "lastPolicyUpdateAt": null }
}
```

`enabled` is the exact `"true"` flag, independent of `configured`. Outbound SCIM configuration checks target ID, URL restrictions and nonblank token, including the development loopback exception. Inbound SCIM checks that its bearer token is at least 32 characters. Sender configuration means management token and sealing key are present; receiver configuration means `SSF_STREAMS` parses and contains at least one stream. These are configuration checks, not end-to-end health, key validity, or interoperability tests. Receiver counts include configured streams even when disabled; an invalid configuration yields zero. Activity is the latest SCIM operation update, inbound SCIM mutation audit, SSF delivery update, SSF inbox receipt, or claim policy update respectively; audit/inbox/delivery retention affects history.

## SCIM journal

`GET /api/admin/scim-operations?status=failed&userId=USER&page=1&limit=20` returns:

```json
{ "operations": [{ "id": "op", "target_id": "target", "user_id": "USER", "operation": "update", "status": "failed", "remote_status": 400, "created_at": "2026-01-01T00:00:00.000Z", "updated_at": "2026-01-01T00:00:00.000Z", "user_name": "Kim", "user_email": "kim@example.com" }], "total": 1, "page": 1, "limit": 20 }
```

Both filters are optional and exact; status is `pending`, `in_progress`, `succeeded`, `failed`, or `outcome_unknown`. User fields and `remote_status` may be null. Operations sort by `created_at` descending, then `id` descending. Page defaults to 1 and limit to 20; both must be positive integers and limit must not exceed 100 (invalid values return 400). The existing POST and read-one routes are unchanged.

## SSF

`GET /api/admin/ssf/streams` returns:

```json
{ "streams": [{ "id": "outgoing", "direction": "sender", "deliveryMethod": "push", "endpointHost": "receiver.example.com", "status": "enabled", "createdAt": "2026-01-01T00:00:00.000Z", "lastEventAt": null, "eventsDelivered": 0, "eventsFailed": 0 }, { "id": "incoming", "direction": "receiver", "deliveryMethod": "push", "endpointHost": "idp.example.com", "status": "enabled", "createdAt": null, "lastEventAt": null, "eventsDelivered": null, "eventsFailed": null }] }
```

Sender status reflects the recipient's own disabled flag, independent of the deployment sender flag; receiver status reflects the receiver flag. Receiver creation time and delivery outcomes are not tracked. Sender delivery counts count retained rows in `delivered` and `failed`/`abandoned` states, not attempts; `retry` is neither. Sender `lastEventAt` is the latest retained delivery update; receiver `lastEventAt` is the latest retained receipt. Receiver endpoint host is the local identity provider host. A deleted sender may still have retained delivery events. The existing stream create/delete endpoints use an operator bearer token, not an administrator session; they remain unchanged.

`GET /api/admin/ssf/events?page=1&limit=20` returns both retained sender delivery rows and receiver inbox rows, newest first:

```json
{ "events": [{ "id": "event-id", "streamId": "outgoing", "direction": "sender", "state": "delivered", "attempts": 1, "httpStatus": 200, "occurredAt": "2026-01-01T00:00:00.000Z" }], "total": 1, "page": 1, "limit": 20 }
```

`attempts` and `httpStatus` are nullable; receiver rows always have both null. The event time is delivery creation or inbox receipt, not the sender's latest retry. Sender IDs are delivery IDs and receiver IDs are SET JTIs; IDs are not necessarily globally unique. Paging validation matches the SCIM journal. Records can be pruned by existing retention jobs.

## Claim release policies

`GET /api/admin/claim-release-policies` returns:

```json
{ "policies": [{ "subject": "oidc:client-id", "allowAccountClaims": true, "allowUserAttributes": false, "attributeAllowlist": null, "allowAccountAttributes": true, "allowGroupAttributes": true, "applicationName": "Example", "applicationSlug": "example" }], "applicationsWithoutPolicy": [{ "subject": "saml:entity-id", "applicationName": "Another", "applicationSlug": "another", "defaults": { "allowAccountClaims": false, "allowUserAttributes": false, "allowAccountAttributes": false, "allowGroupAttributes": false, "attributeAllowlist": null } }] }
```

Unresolved policies have null application name/slug. The no-policy list includes only registered apps with a bound, valid `oidc:`, `saml:`, or `wsfed:` subject accepted by the existing write API; bookmarks, SWA, and unbound apps are excluded. Its `defaults` describe *effective* flag-only decisions with no policy, not values to blindly write: a created policy's booleans are additionally ANDed with global flags and omitted write fields default to true. A null allowlist means all flag-permitted user attribute keys. Existing GET-one, PUT, and DELETE remain unchanged. Subject resolution supports `app:`/`bookmark:` rows for legacy data even though the current policy write API rejects those subject types.
