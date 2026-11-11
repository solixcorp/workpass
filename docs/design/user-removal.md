# User removal safety status

`POST /api/auth/admin/remove-user` is deliberately unavailable (503) after
authentication, origin and self/last-administrator checks. Do not expose it as
a working delete operation yet. This is a fail-closed measure, not a completed
offboarding implementation.

Two blockers must be resolved before enabling deletion:

* A queued SCIM deactivate is not executable after deletion: the current
  executor requires both the local user row and the SCIM mapping. Application
  targets and the deployment-wide target need a durable deactivation workflow,
  including handling an existing active or outcome-unknown operation.
* A D1 batch before Better Auth's independently executed delete cannot make the
  cleanup and user deletion atomic. Authorization failure, validation failure,
  or a later database error can leave an existing user partially erased. The
  authorization decision, all local deletions, and the user deletion need a
  coordinated atomic design. Account membership administration already refuses
  removal of the last account administrator; user deletion needs an equivalent
  invariant. Do not infer a rule about account creators or sole ordinary members.

The last-active-platform-administrator checks for ban and role change are
pre-checks, not transactional invariants: concurrent operations can both pass.
They require database-level serialization or an equivalent atomic guard before
they can guarantee the invariant. Other administrative user-write paths must
also be reviewed for bypasses.

Audit events are retained. A future implementation must preserve their existing
hashes, capture the deleted email/name with the agreed limits, revoke all tokens
and sessions, issue back-channel logout, and enumerate all user-linked tables
including the Better Auth schema and dynamically created tables. In particular,
`location_proofs` is keyed by a hash rather than a user ID; determine how its
token hash is derived before attempting cleanup.
