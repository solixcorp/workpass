# Location scopes

Group rules replace the global place set for users in one or more groups with rules: their effective set is the union of those groups' places. Others use the global set. Global mode, signal, margin and browser accuracy apply; off disables group checks. Exempt group membership overrides both group and application checks.

Application rules have their own observe or enforce mode, independent of the global mode, and use the global signal, margin and accuracy. OIDC checks `oidc:<client_id>` at authorization; SAML checks `saml:<entityId>` and WS-Federation checks `wsfed:<realm>` before issuing an assertion. OIDC may redirect to `/location` and resume; SAML and WS-Federation deny instead. Failed checks produce `authentication.location.observe` or `authentication.location.denied` with `subject` in the audit context.

Only enabled places count. A scoped rule with no enabled places fails its check; deleting a place removes it from rules and removes empty rules. Browser proofs are bound to their matched place and cannot satisfy a different scope. Administrators cannot save a group rule that would lock themselves out while the global policy enforces. Place deletion and disabling, like other place changes, do not have a lockout guard.

`GET /api/admin/location` includes `groupRules`, `appRules` and `applications`. Administrators manage rules with `PUT` or `DELETE /api/admin/location/groups/:groupId` and `PUT` or `DELETE /api/admin/location/apps/:encodedSubject`. Group PUT takes `{ "placeIds": ["place-id"] }`; an empty array removes the rule. App PUT takes `{ "placeIds": ["place-id"], "mode": "observe" }` (or `enforce`); the list must not be empty. App subjects correspond to valid protocol bindings in the applications list. Rule changes are audited. All administrator responses are no-store.

Location is a risk signal, not reliable proof of physical presence. Browser positions are user-supplied and network positions can be coarse or affected by VPNs.
