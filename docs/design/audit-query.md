# Audit event query and request metadata

Administrator-only `GET /api/admin/audit-events` accepts `query`, an AKQL expression applied in SQL **before** pagination, total counting and cursor selection. It is ANDed with `userId`, `actorUserId`, `targetUserId`, `eventType`, `outcome`, `from`, `to`, `eventPrefix`, `q`, `ip` (exact) and `country` (exact). Existing `search` remains a legacy, post-page matcher with its original projection and pagination limitations; use `query` instead. When both are present, `query` is applied in SQL and `search` then filters the returned page, so `total` remains the SQL total.

Examples (URL encode parameter values):

```
GET /api/admin/audit-events?page=1&limit=20&query=country%20%3D%20%22KR%22%20and%20outcome%20%3D%20%22failure%22
GET /api/admin/audit-events?query=ip%20startswith%20%22203.0.113.%22
GET /api/admin/audit-events?query=actor%20%3D%20None
GET /api/admin/audit-events/fields
```

Field names are case-insensitive. Operators and `and`, `or`, `not` are lowercase; `None` is capitalized. Parentheses group expressions; `and` binds more tightly than `or`. Standalone `not (...)` is not supported by the existing AKQL parser: use `!=`, `!~`, `not in`, `not startswith` or `not endswith` instead.

| Field | Aliases | Meaning |
| --- | --- | --- |
| `id` | | event ID |
| `event_type` | `type` | event type |
| `outcome` | | outcome |
| `client_ip` | `ip` | IP address |
| `request_path` | `path` | request path |
| `time` | `occurred_at` | UTC event time |
| `actor`, `target` | | person ID, email or name |
| `user` | | actor or target |
| `actor.email`, `actor.name`, `target.email`, `target.name` | | person attributes |
| `context` | | raw context JSON text |
| `country`, `region`, `city`, `asn` | | stored edge geography |

Most fields support `=`, `==`, `!=`, `<`, `<=`, `>`, `>=`, `~`, `!~`, `in`, `not in`, `startswith`, `not startswith`, `endswith`, `not endswith`. `/fields` gives the exact allowed operators per field and Korean descriptions/examples. `context` only supports `~`. Text pattern operations use SQLite LIKE (ASCII case-insensitive) with literal `%`, `_` and backslash escaped; equality is case-sensitive. `actor` and `target` match ID, email or name; `~`/`!~` use email/name only. `user` checks either person. Negated person comparisons negate the whole match, including missing users. `actor = None` tests for no actor ID, `actor != None` for an actor ID (likewise target). `user = None` means both IDs null, and `user != None` means at least one is present. Null tests on person attribute fields are not supported. List values must be strings or numbers; empty lists are allowed. Time accepts ISO dates/timestamps and `-30m`, `-24h`, `-7d`, quoted or unquoted, relative to request time; they are normalized to UTC. Comparisons bind values, never SQL text. Maximum AST nodes/depth and bound parameters are 50; query length and token count are also bounded.

Invalid queries return 400, for example:

```json
{"error":"문자열이 닫히지 않았습니다.","position":5,"detail":"unterminated string in AKQL query"}
```

`position` is a zero-based input character offset when known, otherwise `null`; `detail` contains the original English diagnostic. Unknown-field errors enumerate canonical valid fields. `GET /api/admin/audit-events/fields` returns `{ "fields": [{ "name": "...", "aliases": [], "description": "...", "operators": [], "examples": [] }], "examples": [{ "title": "...", "query": "..." }] }`.

## IP and geography

Both list events and detail `event` include `client_ip` and `client_geo`, the latter either `null` or `{ "country": string|null, "region": string|null, "city": string|null, "asn": string|null }`. `event_context` remains the stored JSON text, including `geo` where captured; stored `geo` also includes nullable `timezone`. Existing rows have not been backfilled and return null when geo is absent. No coordinates or user-agent family are stored by this feature.

At request entry, per-request AsyncLocalStorage captures `cf-connecting-ip`, falling back to `x-real-ip`, then the first `x-forwarded-for` hop, and Cloudflare `request.cf` country/region/city/asn/timezone. Fallback headers are trustworthy only behind a trusted Cloudflare/proxy configuration; direct clients may spoof them. Explicitly supplied `client_ip`, including null, takes precedence. No request context means null IP and no added geo. The `nodejs_als` Workers compatibility flag enables AsyncLocalStorage without enabling all Node compatibility. New metadata is included in existing v2 hashes; old hashes and rows are unchanged. Updates preserve the original metadata.
