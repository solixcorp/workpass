# Application entitlements

An application owns up to 50 uniquely keyed entitlements. Keys are immutable,
lowercase and match `[a-z0-9][a-z0-9_.:-]{0,63}`. Administrators assign each
entitlement to directory groups; there are no direct user assignments. A person
holds a key when they belong to an assigned group and the enabled application
passes its `app:<slug>` access policy, including account and bound-policy gates.
The administrator list counts distinct current holders using the same evaluation.
App or group deletion cascades to the appropriate entitlement rows or bindings.

For a uniquely bound OIDC, SAML or WS-Fed application, `entitlements` is
released for the requesting application only. OIDC returns a scope-independent
string array in ID tokens, UserInfo and the existing access-token extension;
if the app has entitlements but the user holds none, the array is empty. SAML
and WS-Fed use one attribute with multiple string values; empty sets produce no
attribute. An absent or ambiguous protocol binding releases nothing. The
existing `ENABLE_ATTRIBUTE_CLAIMS` flag and `allowUserAttributes` policy must
allow release, and a configured attribute allowlist must include `entitlements`.
No scope or discovery metadata is added. Failures in claim resolution suppress
claims on the OIDC extension. No notification is sent when assignments change.

Administrative writes are audited and group replacement is transactional.
Existing tokens are not revoked when membership or assignments change; a newly
issued token or UserInfo response reflects the current membership and policy.
