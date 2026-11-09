# Directory groups design (Phase 1)

**Status:** implemented backend foundation; claim delivery into protocols remains open.

## Goal and non-goals

`TSK-1794159217-k1y` models the directory that later protocol work will authorize against. This design covers group definitions and membership with minimum personal data stored in D1. Non-goals for this phase: per-application group/claim policies (`REQ-1794159886-wya`, owned by the later protocol tasks), portal UI (`REQ-...-t17`, excluded by product direction), SCIM group push (inbound/outbound SCIM scope is still an open question), and MFA policy.

## Identity model

- **Identity source of truth is Better Auth.** The `user` record keeps the immutable local identity (`id` never changes while username or email may), the `role` column carries the platform-level role (`admin`, `user`) managed by the Better Auth admin APIs, and account status (banned/active) stays in Better Auth's own records. Duplicating either in a directory table would create a second source of truth.
- **Groups are first-party objects.** `directory_groups` holds an immutable UUID `id`, a unique `name` (1–64 characters from `[A-Za-z0-9_.-]`), an optional `description`, and audit metadata (`created_by`, timestamps).
- **Membership is a plain association.** `directory_group_members` holds `(group_id, user_id)` with `granted_by` and `granted_at`, plus an index on `user_id` for "groups of a user" lookups. Deleting a group deletes its memberships in one batch.
- **Minimum personal data:** groups never store emails, names or identifiers beyond the Better Auth user ID reference; no display metadata on members.

## Administration API

All routes live under `/api/admin/directory-groups`, require an administrator session and the exact configured `Origin`, and are audited (`directory.group.create`, `directory.group.delete`, `directory.member.add`, `directory.member.remove`). Reading is session-gated but not audited, matching the existing admin read routes.

| Method and path | Behavior |
|---|---|
| `GET /api/admin/directory-groups` | Cursor list (`limit` 1–100, default 50), omits members. |
| `POST /api/admin/directory-groups` | `{name, description?}` → 201 with the group; 409 when the unique name exists; 400 on invalid input. |
| `GET /api/admin/directory-groups/{id}` | Group detail with members (admin session). |
| `DELETE /api/admin/directory-groups/{id}` | 200 and removal of the group with its memberships in one D1 batch; 404 when absent. |
| `POST /api/admin/directory-groups/{id}/members` | `{userId}` → 201; rejects unknown users (404), duplicate membership (409) and self-grants are allowed (an admin may join a group). |
| `DELETE /api/admin/directory-groups/{id}/members/{userId}` | 200; 404 when the membership is absent. |

`userId` must reference an existing Better Auth user; the check queries the `user` table in the same D1 binding before granting.

## What remains open

- Group-to-application claim/release policies and which audiences see which groups (`REQ-...-wya`; the protocol tasks own this).
- Directory write propagation to downstream apps (SCIM push is a separate task with its own safety gates).
- Group renaming (rename touches the unique name and the downstream claim mapping; deferred until app bindings exist).
- Self-service group views and any non-admin read surface (portal scope).
