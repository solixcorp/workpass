"""
One-shot graph completion: create the implemented API contract interfaces and
their acceptance criteria, then wire implements/has_criterion edges for the
requirements whose implementations already exist in the backend. Run once:
  python3 scripts/complete-graph.py
"""

import json
import subprocess
import sys

INTERFACES = {
    "REQ-1794159215-r8k": {
        "title": "WebAuthn passkey verification endpoints",
        "description": "GET /api/auth/passkey/generate-register-options and /generate-authenticate-options return challenge-based options with a signed challenge cookie; POST /verify-registration and /verify-authentication verify the browser ceremony response with challenge, origin and RP-ID checks under the shared authorization gate.",
        "description_of_interface": "Better Auth passkey plugin endpoints as configured in src/auth/config.ts and guarded by requireAdministrator.",
    },
    "REQ-1794159215-svv": {
        "title": "Authentication abuse-control settings",
        "description": "Database-backed rate limiting with per-endpoint windows (sign-in five per minute, passkey verification ten per minute), generic invalid-credential errors and no credential material in any log line.",
        "description_of_interface": "Better Auth rateLimit and error-response behavior configured in src/auth/config.ts.",
    },
    "REQ-1794159215-xps": {
        "title": "Administrator authorization helper",
        "description": "requireAdministrator(context) rejects unauthenticated privileged calls with 401, non-admin role with 403, and mutating origin-less requests with 403; every admin surface routes through this single helper.",
        "description_of_interface": "export async function requireAdministrator in src/security/authorization.ts.",
    },
    "REQ-1794159216-0n3": {
        "title": "OIDC discovery and token endpoints",
        "description": "/.well-known/openid-configuration and the authorization-server discovery handlers, the built-in authorization, token and JWKS routes of the Better Auth OAuth provider, and the dynamic client registration route behind its configuration flags.",
        "description_of_interface": "oauthProviderOpenIdConfigMetadata and oauthProviderAuthServerMetadata handlers in src/auth/routes.ts over the Better Auth OAuth provider plugin.",
    },
    "REQ-1794159216-2j9": {
        "title": "Session lifecycle endpoints",
        "description": "Better Auth session creation, expiry, get-session, sign-out and the administration revocation routes; get-session answers 200 with a null body when unauthenticated, and revocation invalidates every concurrent session immediately.",
        "description_of_interface": "Better Auth session APIs over D1 as exposed under /api/auth in src/auth/config.ts; revocation evidence in scripts/session-revocation-smoke.ts.",
    },
    "REQ-1794159216-8c1": {
        "title": "SAML identity-provider endpoints",
        "description": "GET /saml/sso runs the gated chain (enabled registration, certificate-derived trusted key, redirect-binding RSA-SHA256 signature over received octets, allowlisted request validation, freshness, destination, ACS, one-time claim) and delivers a canonically signed Response via POST binding; GET /saml/metadata publishes the IdP metadata document.",
        "description_of_interface": "src/saml/protocol-routes.ts, src/saml/redirect-signature.ts, src/saml/request-binding.ts, src/saml/assertion.ts, src/saml/metadata.ts.",
    },
    "REQ-1794159216-c4h": {
        "title": "Outbound SCIM connector endpoints",
        "description": "POST /api/admin/scim-operations executes a single targeted create, update or deactivate through the HTTPS transport (no redirects, server-side scoped credentials) and journals the operation atomically with a single-active-operation constraint per target and user.",
        "description_of_interface": "src/scim/client.ts, src/scim/operations.ts and src/scim/routes.ts.",
    },
    "REQ-1794159216-vpc": {
        "title": "Provisioning operation journal",
        "description": "Every outbound provisioning mutation writes an operation record with status pending, in_progress, succeeded, failed or outcome_unknown; at most one unresolved operation may exist per target and user; unknown outcomes require reconciliation before any retry.",
        "description_of_interface": "scim_operations table in src/db/schema.ts plus the journal helpers in src/scim/operations.ts.",
    },
    "REQ-1794159886-as9": {
        "title": "Username and password sign-in endpoints",
        "description": "POST /api/auth/sign-in/email and /sign-in/username verify passwords with the version-tagged PBKDF2-SHA-256 scheme (600,000 iterations, per-password salt) under per-endpoint rate limits with enumeration-resistant responses.",
        "description_of_interface": "emailAndPassword configuration and custom hash/verify in src/auth/config.ts and src/auth/password.ts; latency evidence in scripts/session-revocation-smoke.ts runs and docs/feasibility/phase-0-workers-auth-engine.md.",
    },
}

CRITERIA = {
    "REQ-1794159215-r8k": {
        "title": "A passkey ceremonies pass headlessly with challenge and origin checks",
        "given": "A running local workerd instance with a generated database",
        "when": "scripts/passkey-smoke.ts performs registration and authentication with a synthetic ES256 authenticator",
        "then": "Both verification endpoints return 200 and a tampered or unrelated credential is rejected",
    },
    "REQ-1794159215-svv": {
        "title": "Brute-force attempts are rate limited per endpoint",
        "given": "A running local workerd instance",
        "when": "More sign-in attempts than the configured five-per-minute window arrive for one identifier",
        "then": "Attempts beyond the window are rejected and responses do not reveal whether the account exists",
    },
    "REQ-1794159215-xps": {
        "title": "Privileged surfaces reject calls without the admin gate",
        "given": "The administrator surfaces under /api/admin",
        "when": "An anonymous caller reads, or an administrator mutates without the exact Origin, or a non-admin queries",
        "then": "The calls are rejected with 401 or 403 respectively, matching scripts/directory-smoke.ts checks",
    },
    "REQ-1794159216-0n3": {
        "title": "Authorization codes are single use and PKCE-bound",
        "given": "A registered public client with an HTTPS callback",
        "when": "Eight parallel token requests redeem one authorization code, or one sequential reuse arrives",
        "then": "Exactly one 200 response and 400 for every other redemption",
    },
    "REQ-1794159216-2j9": {
        "title": "Revocation invalidates concurrent sessions immediately",
        "given": "Two signed-in sessions for one administrator on a local workerd instance",
        "when": "An authorized administrator revokes the user's sessions",
        "then": "Both cookies stop authorizing immediately and a fresh sign-in still succeeds",
    },
    "REQ-1794159216-8c1": {
        "title": "A signed round trip verifies against published metadata only",
        "given": "A local workerd instance with a generated IdP signing key and an enabled SP registration",
        "when": "scripts/saml-sso-smoke.ts signs an AuthnRequest and verifies the returned POST-bound Response",
        "then": "SignatureValue and DigestValue verify, replay, tampering and unregistered issuers are rejected, and the issuance is audited",
    },
    "REQ-1794159216-c4h": {
        "title": "Outbound operations are single-active and reconciled",
        "given": "An enabled SCIM target configured server-side",
        "when": "An operation runs or its outcome is unknown after a timeout or server error",
        "then": "The journal records the outcome class and further operations block until reconciliation",
    },
    "REQ-1794159216-vpc": {
        "title": "No duplicate downstream mutation without reconciliation",
        "given": "One target and user with a pending, in-progress or outcome-unknown operation",
        "when": "Another operation is attempted for the same pair",
        "then": "The attempt is refused by the atomic journal constraint",
    },
    "REQ-1794159886-as9": {
        "title": "Password verification performs identical work on both outcomes",
        "given": "One stored password record",
        "when": "Sign-in is attempted with a wrong and with the correct password",
        "then": "Both paths derive the same 600,000-iteration PBKDF2 work and complete in comparable time",
    },
}

def run_json(args):
    result = subprocess.run(args, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        print("FAILED parsing:", " ".join(args), file=sys.stderr)
        print(result.stdout, result.stderr, file=sys.stderr)
        raise SystemExit(1)

created = []
for req, iface in INTERFACES.items():
    added = run_json([
        "spec-graph", "entity", "add", "--type", "interface",
        "--title", iface["title"],
        "--description", iface["description"],
        "--status", "active",
        "--metadata", json.dumps({
            "kind": "api_contract",
            "description_of_interface": iface["description_of_interface"],
        }),
    ])
    api_id = added["entity"]["id"]
    created.append(api_id)
    run_json(["spec-graph", "relation", "add", "--from", api_id, "--to", req, "--type", "implements"])
    criterion = run_json([
        "spec-graph", "entity", "add", "--type", "criterion",
        "--title", CRITERIA[req]["title"],
        "--metadata", json.dumps({
            "given": CRITERIA[req]["given"],
            "when": CRITERIA[req]["when"],
            "then": CRITERIA[req]["then"],
        }),
    ])
    criterion_id = criterion["entity"]["id"]
    created.append(criterion_id)
    run_json(["spec-graph", "relation", "add", "--from", req, "--to", criterion_id, "--type", "has_criterion"])
    print(f"wired {req} -> {api_id} (implements), {criterion_id} (criterion)")

print("done:", len(created), "entities created")
