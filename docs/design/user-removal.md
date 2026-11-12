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

After the application migration, SQLite triggers prevent an update or delete
of the last active platform administrator. The HTTP pre-check remains for a
clear conflict response. In a concurrent ban, the losing administrator may
instead receive 401 if the winning ban has already revoked their session.
The same invariant prevents emergency lockdown of the last administrator;
the lockdown endpoint returns 409 without locking the account. Establish a
second active administrator first. This is a security/availability tradeoff:
it also prevents a sole administrator from self-locking a compromised account.
The triggers must be installed by running the migration before relying on this
invariant; installations that have not run it still have only the pre-check.

SCIM transport classifies HTTP 500, 408, 409, network errors and invalid
responses as outcome unknown. A 500 can follow a committed remote change, so
automatically retrying it conflicts with the requirement to stop until an
administrator reconciles unknown outcomes. A safe deletion design must use
the existing SCIM resolve workflow before continuing, not silently retry.
The proposed automatic recovery from a stubbed 500 needs product clarification.

Audit events are retained. A future implementation must preserve their existing
hashes, capture the deleted email/name with the agreed limits, revoke all tokens
and sessions, issue back-channel logout, and enumerate all user-linked tables
including the Better Auth schema and dynamically created tables. In particular,
`location_proofs` is keyed by a hash rather than a user ID; determine how its
token hash is derived before attempting cleanup.
