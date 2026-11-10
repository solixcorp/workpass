# Applications design (bookmarks and protocol-backed apps)

**Status:** implemented backend foundation; launch-page UI and idp-initiated SSO launch remain open.

## Goal and non-goals

A unified application registry, modeled on authentik's Applications: one registry covers plain **bookmark** applications (a launch URL only, no SSO protocol) and **backed** protocol applications whose binding references an already registered provider — SAML 2.0 SP entity id, WS-Federation realm, OIDC client id, or SWA application origin. Users get one launch list. Non-goals for this phase: portal UI, application icons, idp-initiated SAML/OIDC launching from the dashboard (SP/RP-initiated flows stay as implemented), entitlements, and backchannel-provider grouping.

## Identity model

- **Applications are first-party objects.** `applications` holds an immutable UUID `id`, a unique `slug` (1–64 characters from `[a-z0-9-]`, starting with a letter or digit), a 1–128 character `name`, an optional `description`, the `protocol` (`bookmark|saml|wsfed|oidc|swa`), a nullable `binding`, a nullable `launchUrl`, `hide_from_dashboard`, `enabled`, and audit metadata.
- **Bookmark apps.** `binding` is null and `launchUrl` is required — an https URL the user is sent to directly. No SSO protocol involvement.
- **Backed apps.** `binding` is required and must reference a registered provider of the declared protocol (SAML entity id, WS-Fed realm, SWA origin, OIDC client id), validated at write time. Deleting an application never touches the provider registration — the dashboard link and the provider lifecycle stay decoupled.
- **`launchUrl` for backed apps is optional** — authentik derives launch URLs from providers, but only the bookmark case has a mandatory URL here.
- **Created disabled** like every registry in this codebase; enablement is a deliberate two-step lifecycle (`/enable`, `/disable`).

## Visibility model

- Visibility is gated by the `app:<slug>` access-policy subject — the same policy engine, groups, account gate, temporal grants and enforcement modes as the application issuance gates (see `src/access/policies.ts`).
- **No policy row = every signed-in user sees the app** (authentik's empty-binding default). A policy row narrows: group bindings, the per-account `requiredAccount` gate, MFA and method constraints apply the same way.
- `hideFromDashboard` (authentik's "Hide from Application Dashboard" parity): the app does not appear in the user's launch list while anything already authorized keeps working.
- Policy subjects on the dashboard are independent of the issuance subjects (`saml:<entityId>` etc.): an app may be listed to everyone it matters for while its sign-in chain keeps its own gate.
- Reading is session-gated but not audited, matching the other user reads.

## Administration API

All routes live under `/api/admin/applications` and follow the registry lifecycle language. Reads are session-gated; mutations need the exact configured `Origin` and are audited.

| Method and path | Behavior |
|---|---|
| `GET /api/admin/applications` | Every application including hidden and disabled, ordered by name. |
| `POST /api/admin/applications` | `{slug, name, protocol, binding?, launchUrl?, description?, hideFromDashboard?}` → 201; 409 on a duplicate slug; 400 with precise validation messages. Audited (`app.create`). |
| `GET /api/admin/applications/{slug}` | One application (admin session). |
| `PATCH /api/admin/applications/{slug}` | Name/description/launchUrl/hideFromDashboard/binding updates; `protocol` is immutable (400) since a change would orphan the stored gate policy. Binding integrity rules re-run on every patch. Audited (`app.update`). |
| `POST /api/admin/applications/{slug}/enable` and `/disable` | Two-step lifecycle, audited (`app.enable`, `app.disable`). |
| `DELETE /api/admin/applications/{slug}` | 200; removes the dashboard surface only. Audited (`app.delete`). |

## User-facing launch API

| Method and path | Behavior |
|---|---|
| `GET /api/applications` | Session-gated, no-store. Enabled, not-hidden applications the user passes, ordered by name: `{slug, name, description, protocol, launchUrl}`. Bookmark apps launch directly by URL; backed apps keep their protocol entry points. |

## What remains open

- IdP-initiated launching from the dashboard (`/application/launch/{slug}`-style redirect flows for SAML and OIDC).
- Application icons and dashboard grouping categories.
- Application entitlements (authentik parity: scoping claims to per-app grants).
- Wire the launch page HTML into the portal UI (frontend, excluded).
