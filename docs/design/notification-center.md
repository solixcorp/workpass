# Notification center

`categoryOfKind` assigns `app_assigned` to `apps`, `access_request` and `app_request` to `requests`, and all other kinds to locked `security`. This includes `security_*`, `suspicious_report`, `report_closed`, and `phone_verified`; unknown kinds default to security so they cannot inadvertently be suppressed. Category is independent of the recipient's role; reviewer notices follow the same mapping. There is no separate admin category.

Preferences are per user and default to enabled. Only apps and requests can be changed; security remains on even if a bad preference row exists. Preferences affect new notices, not historical ones. Bulk delivery reads disabled recipients once before batching inserts; security notices always bypass preferences.

The bell's unpaged endpoint retains its latest-50 unread count. With `page`, `unread` is the caller's overall unread count, and `total` is the number matching the optional category and unread filters. Results are ordered newest first with an ID tie-breaker. Pagination is not a snapshot, so concurrently arriving notifications can shift page boundaries.

Administrators can revoke one session by ID. The endpoint refuses the caller's current session, removes token-bound MFA proofs, step-up challenges, network bindings, and account contexts along with the session in a D1 batch, and audits success and failure. It does not revoke already issued OAuth tokens or other sessions.
