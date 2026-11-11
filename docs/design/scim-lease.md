# SCIM operation leases and reconciliation

An in-progress operation older than ten minutes becomes `outcome_unknown` lazily during same-target/user creation, provisioning sync, or scheduled cleanup. It is marked `abandoned` and audited; it is never retried automatically, because the remote server may have applied the mutation. Pending and fresh operations are not expired. Unknown operations retain the single-open-operation slot.

After checking the remote system, an administrator may POST `{ "note": "..." }` (note optional, at most 2000 characters) to `/api/admin/scim-operations/:id/resolve`. Only an unknown operation can be resolved. Resolution marks it failed, records the operator, timestamp and note, and releases the slot for a new operation. This records an operator decision, not proof the remote mutation failed. Resolution and expiry are audited. The operations list exposes nullable `resolved_at`, `resolved_by_name`, `resolution_note`, and boolean `abandoned`.

Deployments must run the existing database migration to add the reconciliation columns before using this feature.

## Per-application sync lease

Run `/_internal/migrate` before deploying this code to add `sync_lock_owner` and `sync_lock_at`. The separate per-application sync lock is a five-minute lease with a random owner token and UTC heartbeat timestamp. A lock with no timestamp (including a legacy lock) or older than five minutes can be taken over using a compare-and-set; takeover emits `app.provisioning.sync_lease_taken_over`. Deploy only after old Workers have stopped syncing, because legacy Workers cannot heartbeat or respect lease ownership.

The lease is renewed between users and before saving the cursor; the current request still scans at most 50 users. Release and cursor updates are owner-guarded, so an abandoned Worker cannot clear a successor's lock or overwrite its cursor. A single user operation taking more than five minutes can lose the lease; in-flight remote requests cannot be revoked, and SCIM operation reconciliation remains necessary for uncertain outcomes. The GET provisioning response includes `syncRunning`, true only for an unexpired lease, and `lastSyncAt`, the last successfully saved batch time. Concurrent sync requests return 409 while the lease is fresh.
