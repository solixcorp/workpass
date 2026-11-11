/**
 * SAML SSO protocol route: verify, claim, authenticate, issue a signed
 * Response. No stage is skippable; a provider that is not enabled or an IdP
 * that has no signing key configured can never produce an assertion, so no
 * partially verified login path exists.
 */

import { Hono } from "hono";
import { locationGate } from "../security/location-gate";
import type { Context } from "hono";
import type { Env } from "../env";
import { createAuth } from "../auth/config";
import { auditStandaloneOperation } from "../audit/store";
import { verifySamlRedirectSignature } from "./redirect-signature";
import { inflateSamlMessage, parseSamlAuthnRequest } from "./request-binding";
import { claimVerifiedSamlRequest } from "./request-claims";
import {
  evaluateAppAccess,
  hasRecentAppIssuance,
  loadAppAccessPolicy,
  recordAppIssuance,
  policyTtlSeconds,
} from "../access/policies";
import { sessionSatisfiesRequireMfa } from "../mfa/second-factor";
import { userMustUseMfa } from "../mfa/policy";
import { getEnabledSamlServiceProviderByEntityId } from "./service-providers";
import { importSamlIdpPrivateKey, importSamlServiceProviderTrustedKey } from "./certificates";
import { buildSignedSamlResponse, type SamlSigningMaterial } from "./assertion";
import { buildSamlIdpMetadata } from "./metadata";
import { samlAttributeRelease } from "../claims/protocol-claims";
import { cachedProtocolDocument, storeProtocolDocument } from "../web/protocol-cache";
import { redirectToSignIn } from "../pages/sso-login";

export const SAML_SSO_PATH = "/saml/sso";

/** Maximum age of an AuthnRequest IssueInstant once clock skew is allowed. */
const ISSUE_INSTANT_MAX_AGE_MS = 5 * 60_000;
/** Allowed clock skew between us and the SP. */
const ISSUE_INSTANT_SKEW_MS = 2 * 60_000;

const GENERIC_REJECTION = "The authentication request cannot be processed";
const UNAVAILABLE = "SAML single sign-on is not available";

export const samlProtocolRoutes = new Hono<{ Bindings: Env }>();

samlProtocolRoutes.get(SAML_SSO_PATH, async (context) => {
  const now = new Date();
  try {
    // Stage 0: the IdP must be able to sign at all before anything else.
    const signing = await loadSamlIdpSigningMaterial(context.env);
    if (!signing) {
      console.error("SAML SSO rejected: signing material is not configured");
      return context.json({ error: UNAVAILABLE }, 503);
    }

    // Stage 1: decode and parse untrusted bytes to find a candidate issuer.
    const query = new URL(context.req.url).searchParams;
    const encodedRequest = query.get("SAMLRequest");
    if (!encodedRequest) return reject(context, "missing-message");
    let provisional;
    try {
      provisional = parseSamlAuthnRequest(await inflateSamlMessage(encodedRequest));
    } catch {
      return reject(context, "invalid-message");
    }

    // Stage 2: select the trusted key of the registered, enabled SP.
    const provider = await getEnabledSamlServiceProviderByEntityId(context.env, provisional.issuer);
    if (!provider) {
      console.error("SAML SSO rejected: issuer is not an enabled registration", { stage: "unregistered-issuer" });
      return context.json({ error: GENERIC_REJECTION }, 401);
    }
    const trustedKey = await importSamlServiceProviderTrustedKey(provider.signingCertificate);

    // Stage 3: verify the redirect binding signature over the received bytes.
    const verified = await verifySamlRedirectSignature(context.req.url, trustedKey);
    if (!verified || verified.samlRequest !== encodedRequest) {
      return reject(context, "binding-signature");
    }

    // Stage 4: revalidate the verified bytes fully.
    const request = parseSamlAuthnRequest(await inflateSamlMessage(verified.samlRequest));
    if (request.id.length === 0 || request.issuer !== provider.entityId) {
      return reject(context, "verified-mismatch");
    }
    if (
      now.getTime() - request.issueInstant.getTime() > ISSUE_INSTANT_MAX_AGE_MS + ISSUE_INSTANT_SKEW_MS ||
      request.issueInstant.getTime() - now.getTime() > ISSUE_INSTANT_SKEW_MS
    ) {
      return reject(context, "stale-request");
    }
    const expectedDestination = expectedSsoDestination(context.env);
    if (request.destination !== null && request.destination !== expectedDestination) {
      return reject(context, "destination");
    }
    if (request.acsUrl !== null && request.acsUrl !== provider.acsUrl) {
      return reject(context, "acs-mismatch");
    }
    // We cannot assert fresh authentication until a reauthentication flow exists.
    if (request.forceAuthn) return reject(context, "force-authn-unsupported");

    // Stage 5: an Issuer-visible user session is mandatory before claiming.
    // With no session the login page is rendered for this verified request;
    // after sign-in the same URL reloads and the full chain runs again.
    const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
    if (!session) {
      if (request.isPassive) return reject(context, "passive-session-unavailable");
      // Prior-success bypass: a session is still required, but a signed-in
      // skip never applies here; the login page always gates unauthenticated users.
      return redirectToSignIn(context);
    }
    // The per-application access policy: group gating plus per-app MFA
    // requirement, evaluated against the signed-in user.
    if (userMustUseMfa(context.env, session.user as { role?: unknown }) && !(await sessionSatisfiesRequireMfa(context.env, session))) {
      return reject(context, "mfa-required");
    }
    const policySubject = `saml:${provider.entityId}`;
    const location = await locationGate(context.env, { request: context.req.raw, userId: session.user.id, path: context.req.path, subject: policySubject });
    if (!location.allowed) return context.redirect(`${new URL(context.env.AUTH_BASE_URL).origin}/api/auth/error?error=access_denied`, 302);
    const policy = await loadAppAccessPolicy(context.env, policySubject);
    if (policy) {
      if (policy.requireMfa) {
        const satisfied = await sessionSatisfiesRequireMfa(context.env, session);
        if (!satisfied) return reject(context, "mfa-required");
      }
      const evaluation = await evaluateAppAccess(context.env, policy, session.user.id);
      if (!evaluation.allowed) {
        return reject(context, "app-policy-denied");
      }
    }
    const email = session.user.email;
    if (!email || email.length > 256) return reject(context, "no-nameid");
    const authenticatedAt = new Date(session.session.createdAt);
    if (!Number.isFinite(authenticatedAt.getTime()) || authenticatedAt.getTime() > now.getTime() + ISSUE_INSTANT_SKEW_MS) {
      return reject(context, "invalid-session-time");
    }

    // Stages 6 and 7 are one audited unit: the claim, the signing and the
    // delivered POST page either all happen behind one audit event or none of
    // them run.
    return auditStandaloneOperation(context.env, "saml.assertion.issue", SAML_SSO_PATH, async () => {
      const claimed = await claimVerifiedSamlRequest({
        env: context.env,
        providerId: provider.id,
        requestId: request.id,
        // Keep the claim for the entire period in which this request is accepted.
        expiresAt: new Date(request.issueInstant.getTime() + ISSUE_INSTANT_MAX_AGE_MS + ISSUE_INSTANT_SKEW_MS + 1000),
      });
      if (!claimed) {
        console.error("SAML SSO rejected", { stage: "replayed-request" });
        return { response: Response.json({ error: GENERIC_REJECTION }, { status: 400 }), actorUserId: session.user.id, targetUserId: provider.id };
      }
      // Attribute release fails closed on the operator flags; disabled flags
      // yield an empty list and an assertion without an AttributeStatement.
      const attributes = await samlAttributeRelease(
        context.env,
        protocolSessionToken(session),
        sessionUserId(session),
        session.user.id,
        `saml:${provider.entityId}`,
      );
      const issued = await buildSignedSamlResponse({
        requestId: request.id,
        acsUrl: provider.acsUrl,
        serviceProviderEntityId: provider.entityId,
        relayState: verified.relayState,
        subject: { nameId: email, sessionId: sessionUserId(session), authenticatedAt },
        signing,
        lifetimeSeconds: policy ? policyTtlSeconds(policy, 5 * 60) : undefined,
        attributes: attributes.length > 0 ? attributes : undefined,
      });
      await recordAppIssuance(
        context.env,
        policySubject,
        session.user.id,
        "saml",
        policy?.enforcementMode ?? "enforce",
      );
      const acsOrigin = new URL(provider.acsUrl).origin;
      return {
        response: new Response(issued.postPage, {
          status: 200,
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": `default-src 'none'; script-src 'unsafe-inline'; form-action ${acsOrigin}; frame-ancestors 'none'; base-uri 'none'`,
          },
        }),
        actorUserId: session.user.id,
        targetUserId: provider.id,
      };
    });
  } catch (error) {
    console.error("SAML SSO rejected: unexpected failure", {
      stage: "unexpected",
      name: error instanceof Error ? error.name : "UnknownError",
    });
    return context.json({ error: GENERIC_REJECTION }, 500);
  }
});

/** Public, unsigned protocol metadata for service provider configuration. */
samlProtocolRoutes.get("/saml/metadata", async (context) => {
  const url = new URL(context.req.url);
  const edgeCached = await cachedProtocolDocument(url);
  if (edgeCached) return edgeCached;
  const signing = await loadSamlIdpSigningMaterial(context.env);
  if (!signing) {
    return context.json({ error: UNAVAILABLE }, 503);
  }
  context.header("Cache-Control", "no-store");
  context.header("Content-Type", "application/samlmetadata+xml; charset=utf-8");
  const metadata = buildSamlIdpMetadata({
    entityId: signing.entityId,
    certificate: signing.certificate,
    ssoUrl: expectedSsoDestination(context.env),
    previousCertificate: signing.previousCertificate,
  });
  await storeProtocolDocument(url, new Response(metadata, {
    status: 200,
    headers: { "Content-Type": "application/samlmetadata+xml; charset=utf-8" },
  }));
  return context.body(metadata, 200);
});

function reject(
  context: Context<{ Bindings: Env }>,
  stage: string,
  status: 400 | 401 = 400,
) {
  console.error("SAML SSO rejected", { stage });
  return context.json({ error: GENERIC_REJECTION }, status);
}

type SamlSession = Awaited<ReturnType<ReturnType<typeof createAuth>["api"]["getSession"]>>;

function sessionUserId(session: NonNullable<SamlSession>): string {
  const inner = (session as { session?: { id?: unknown } }).session;
  return typeof inner?.id === "string" && inner.id.length > 0 ? inner.id : crypto.randomUUID();
}

/** The switch context is keyed by the raw session token. */
function protocolSessionToken(session: NonNullable<SamlSession>): string | null {
  const inner = (session as { session?: { token?: unknown } }).session;
  return typeof inner?.token === "string" && inner.token.length > 0 ? inner.token : null;
}

export function expectedSsoDestination(env: Env): string {
  const base = new URL(env.AUTH_BASE_URL);
  return `${base.origin}${SAML_SSO_PATH}`;
}

/**
 * Load the IdP signing pair from configuration, with rotation support: the
 * previous key pair stays valid during the overlap window, so tokens signed
 * by either key verify against the published pair set. Private material is
 * kept in WebCrypto only. SAML_IDP_PREVIOUS_SIGNING_CERTIFICATE and
 * SAML_IDP_PREVIOUS_SIGNING_PRIVATE_KEY are optional during a rotation.
 */
export async function loadSamlIdpSigningMaterial(env: Env): Promise<SamlSigningMaterial | null> {
  const entityId = env.SAML_IDP_ENTITY_ID;
  if (!entityId) {
    console.error("SAML IdP signing material cannot be used without SAML_IDP_ENTITY_ID");
    return null;
  }
  const active = await loadKeyPair(env, env.SAML_IDP_SIGNING_CERTIFICATE, env.SAML_IDP_SIGNING_PRIVATE_KEY);
  if (!active) return null;
  const previous = await loadKeyPair(env, env.SAML_IDP_PREVIOUS_SIGNING_CERTIFICATE, env.SAML_IDP_PREVIOUS_SIGNING_PRIVATE_KEY);
  if (previous) {
    return { entityId, certificate: active.certificate, privateKey: active.privateKey, previousCertificate: previous.certificate };
  }
  return { entityId, certificate: active.certificate, privateKey: active.privateKey };
}

async function loadKeyPair(env: Env, certificate: string | undefined, privateKeyPem: string | undefined): Promise<SamlSigningMaterial | null> {
  if (!certificate || !privateKeyPem) return null;
  try {
    const privateKey = await importSamlIdpPrivateKey(privateKeyPem);
    const publicKey = await importSamlServiceProviderTrustedKey(certificate);
    const probe = new TextEncoder().encode("SAML IdP signing key check");
    const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", privateKey, probe);
    if (!await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, signature, probe)) {
      console.error("SAML IdP signing material failed the private-key/certificate match check");
      return null;
    }
    return { entityId: "", certificate, privateKey };
  } catch (error) {
    console.error("SAML IdP signing material is configured but unusable", {
      name: error instanceof Error ? error.name : "UnknownError",
      message: error instanceof Error ? error.message : "no message",
    });
    return null;
  }
}
