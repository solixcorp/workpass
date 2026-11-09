/**
 * WS-Federation administration and protocol routes. The administration
 * lifecycle mirrors the SAML provider lifecycle (disabled creation, deliberate
 * enablement, two-step retirement); the protocol side implements only the
 * narrowly documented passive sign-in profile in docs/design/wsfed-profile.md.
 */

import { Hono } from "hono";
import type { Context } from "hono";
import { requireAdministrator } from "../security/authorization";
import { createAuth } from "../auth/config";
import type { Env } from "../env";
import { auditStandaloneOperation } from "../audit/store";
import {
  createWsfedRelyingParty,
  getEnabledWsfedRelyingPartyByRealm,
  getWsfedRelyingParty,
  setWsfedRelyingPartyEnabled,
  validateWsfedRelyingParty,
} from "./relying-parties";
import { buildWsfedSignInResult } from "./token";
import { buildSsoLoginPage } from "../saml/sso-login";
import { loadSamlIdpSigningMaterial } from "../saml/protocol-routes";

export const WSFED_SIGNIN_PATH = "/wsfed/signin";
export const WSFED_METADATA_PATH = "/wsfed/metadata";

const GENERIC_REJECTION = "The single sign-on request cannot be processed";
const UNAVAILABLE = "WS-Federation single sign-on is not available";
const MAX_CTX_BYTES = 256;
const WA_SIGNIN = "wsignin1.0";
const WA_SIGNOUT = "wsignout1.0";

export const wsfedAdminRoutes = new Hono<{ Bindings: Env }>();

wsfedAdminRoutes.get("/wsfed-relying-parties", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const result = await context.env.DB.prepare(
    "SELECT id, realm, reply_url AS replyUrl, enabled FROM wsfed_relying_parties ORDER BY id ASC LIMIT 200",
  ).all<{ id: string; realm: string; replyUrl: string; enabled: number }>();
  return context.json({
    parties: result.results.map((row) => ({ ...row, enabled: row.enabled === 1 })),
  });
});

wsfedAdminRoutes.post("/wsfed-relying-parties", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  let body: unknown;
  try { body = await context.req.json(); } catch { return context.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object" || Array.isArray(body)) return context.json({ error: "Invalid body" }, 400);
  const value = body as Record<string, unknown>;
  if (typeof value.realm !== "string" || typeof value.replyUrl !== "string") {
    return context.json({ error: "realm and replyUrl are required" }, 400);
  }
  const party = { id: crypto.randomUUID(), realm: value.realm, replyUrl: value.replyUrl };
  try { validateWsfedRelyingParty({ ...party, enabled: false }); } catch { return context.json({ error: "Invalid relying party" }, 400); }
  return auditStandaloneOperation(context.env, "wsfed.relying_party.create", "/api/admin/wsfed-relying-parties", async () => {
    const inserted = await createWsfedRelyingParty(context.env, { ...party, createdBy: actor.userId });
    return {
      response: inserted
        ? Response.json({ party: { ...party, enabled: false } }, { status: 201 })
        : Response.json({ error: "A relying party with this realm already exists" }, { status: 409 }),
      actorUserId: actor.userId,
    };
  });
});

wsfedAdminRoutes.post("/wsfed-relying-parties/:id/enable", async (context) => {
  return withRelyingParty(context, "wsfed.relying_party.enable", true);
});

wsfedAdminRoutes.post("/wsfed-relying-parties/:id/disable", async (context) => {
  return withRelyingParty(context, "wsfed.relying_party.disable", false);
});

async function withRelyingParty(
  context: Context<{ Bindings: Env }>,
  eventType: string,
  enabled: boolean,
): Promise<Response> {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const id = context.req.param("id");
  if (!id || id.length > 128) return context.json({ error: "Invalid relying party" }, 400);
  const party = await getWsfedRelyingParty(context.env, id);
  if (!party) return context.json({ error: "Relying party not found" }, 404);
  return auditStandaloneOperation(context.env, eventType, context.req.path, async () => {
    const changed = await setWsfedRelyingPartyEnabled(context.env, id, enabled);
    return {
      response: changed
        ? Response.json({ party: { id: party.id, realm: party.realm, replyUrl: party.replyUrl, enabled } })
        : Response.json({ error: "Relying party not found" }, { status: 404 }),
      actorUserId: actor.userId,
      targetUserId: id,
    };
  });
}

wsfedAdminRoutes.delete("/wsfed-relying-parties/:id", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const id = context.req.param("id");
  if (!id || id.length > 128) return context.json({ error: "Invalid relying party" }, 400);
  return auditStandaloneOperation(context.env, "wsfed.relying_party.delete", context.req.path, async () => {
    const party = await getWsfedRelyingParty(context.env, id);
    if (!party) return { response: Response.json({ error: "Relying party not found" }, { status: 404 }), actorUserId: actor.userId };
    if (party.enabled) {
      return { response: Response.json({ error: "Disable the relying party before deleting it" }, { status: 409 }), actorUserId: actor.userId, targetUserId: id };
    }
    const removed = await context.env.DB.prepare(
      "DELETE FROM wsfed_relying_parties WHERE id = ? AND enabled = 0",
    ).bind(id).run();
    return {
      response: removed.meta.changes === 1
        ? Response.json({ deleted: true })
        : Response.json({ error: "Relying party not found" }, { status: 404 }),
      actorUserId: actor.userId,
      targetUserId: id,
    };
  });
});

export const wsfedProtocolRoutes = new Hono<{ Bindings: Env }>();

wsfedProtocolRoutes.get(WSFED_SIGNIN_PATH, async (context) => {
  const now = new Date();
  try {
    // Stage 0: the shared IdP signing pair must be ready.
    const signing = await loadSamlIdpSigningMaterial(context.env);
    if (!signing) {
      console.error("WS-Fed sign-in rejected: signing material is not configured");
      return context.json({ error: UNAVAILABLE }, 503);
    }
    const query = new URL(context.req.url).searchParams;
    const wa = query.get("wa");
    if (wa === WA_SIGNOUT) {
      // The narrow profile returns a simple local cleanup page.
      context.header("Cache-Control", "no-store");
      return context.body(
        "<!DOCTYPE html><html><body><p>Signed out of the identity provider.</p></body></html>",
        200,
        { "Content-Type": "text/html; charset=utf-8" },
      );
    }
    if (wa !== WA_SIGNIN) return rejectSignin(context, "unrecognized-wa");

    // Stage 1: select the enabled relying party from the untrusted realm.
    const realm = query.get("wtrealm") ?? "";
    const party = await getEnabledWsfedRelyingPartyByRealm(context.env, realm);
    if (!party) {
      console.error("WS-Fed sign-in rejected: realm is not an enabled registration", { stage: "unregistered-realm" });
      return context.json({ error: GENERIC_REJECTION }, 401);
    }

    // Stage 2: the reply URL must match the registered reply exactly.
    const reply = query.get("wreply");
    if (reply !== null && reply !== party.replyUrl) return rejectSignin(context, "reply-mismatch");

    // Stage 3: a mandatory session; passive sign-in carries no signed request.
    const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
    if (!session) {
      context.header("Cache-Control", "no-store");
      context.header("Referrer-Policy", "no-referrer");
      context.header(
        "Content-Security-Policy",
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; form-action 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
      );
      return context.body(
        buildSsoLoginPage({
          title: "Sign in to continue",
          hint: "This application sent you here to sign in. Authenticate to continue to it.",
        }),
        200,
        { "Content-Type": "text/html; charset=utf-8" },
      );
    }
    const email = session.user.email;
    if (!email || email.length > 256) return rejectSignin(context, "no-nameid");
    const authenticatedAt = new Date(session.session?.createdAt);
    if (!Number.isFinite(authenticatedAt.getTime()) || authenticatedAt.getTime() > now.getTime() + 2 * 60_000) {
      return rejectSignin(context, "invalid-session-time");
    }

    // Stage 4: issue and deliver the signed token via POST binding.
    const wctx = query.get("wctx") ?? null;
    if (wctx !== null && new TextEncoder().encode(wctx).length > MAX_CTX_BYTES) {
      return rejectSignin(context, "oversized-context");
    }
    const issued = await buildWsfedSignInResult({
      wctx,
      realm: party.realm,
      replyUrl: party.replyUrl,
      identity: { nameId: email },
      signing,
      now,
    });
    const replyOrigin = new URL(party.replyUrl).origin;
    return auditStandaloneOperation(context.env, "wsfed.token.issue", WSFED_SIGNIN_PATH, async () => ({
      response: new Response(issued.postPage, {
        status: 200,
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store",
          "Referrer-Policy": "no-referrer",
          "Content-Security-Policy": `default-src 'none'; script-src 'unsafe-inline'; form-action ${replyOrigin}; frame-ancestors 'none'; base-uri 'none'`,
        },
      }),
      actorUserId: session.user.id,
      targetUserId: party.id,
    }));
  } catch (error) {
    console.error("WS-Fed sign-in rejected: unexpected failure", {
      name: error instanceof Error ? error.name : "UnknownError",
    });
    return context.json({ error: GENERIC_REJECTION }, 500);
  }
});

function rejectSignin(context: Context<{ Bindings: Env }>, stage: string, status: 400 | 401 = 400) {
  console.error("WS-Fed sign-in rejected", { stage });
  return context.json({ error: GENERIC_REJECTION }, status);
}

/** Federation metadata for reliance by legacy applications. */
wsfedProtocolRoutes.get(WSFED_METADATA_PATH, async (context) => {
  const signing = await loadSamlIdpSigningMaterial(context.env);
  if (!signing) return context.json({ error: UNAVAILABLE }, 503);
  context.header("Cache-Control", "no-store");
  context.header("Content-Type", "application/xml; charset=utf-8");
  return context.body(buildFederationMetadata(context.env, signing), 200);
});

function buildFederationMetadata(env: Env, signing: NonNullable<Awaited<ReturnType<typeof loadSamlIdpSigningMaterial>>>): string {
  const certificateBase64 = pemCertificateBody(signing.certificate);
  const previousBase64 = signing.previousCertificate ? pemCertificateBody(signing.previousCertificate) : null;
  const baseUrl = new URL(env.AUTH_BASE_URL);
  const metadataEntity = `${baseUrl.origin}${WSFED_METADATA_PATH}`;
  return [
    '<?xml version="1.0" encoding="utf-8"?>',
    `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${metadataEntity}">`,
    '<md:IDPSSODescriptor protocolSupportEnumeration="http://schemas.xmlsoap.org/ws/2005/02/trust/13">',
    '<md:KeyDescriptor use="signing">',
    '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">',
    '<ds:X509Data><ds:X509Certificate>' + certificateBase64 + '</ds:X509Certificate></ds:X509Data>',
    '</ds:KeyInfo>',
    '</md:KeyDescriptor>',
    ...(previousBase64
      ? ['<md:KeyDescriptor use="signing">',
         '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">',
         '<ds:X509Data><ds:X509Certificate>' + previousBase64 + '</ds:X509Certificate></ds:X509Data>',
         '</ds:KeyInfo>',
         '</md:KeyDescriptor>']
      : []),
    '<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>',
    '<md:PassiveRequestorEndpoint>',
    `<wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing"><wsa:Address>${baseUrl.origin}${WSFED_SIGNIN_PATH}</wsa:Address></wsa:EndpointReference>`,
    '</md:PassiveRequestorEndpoint>',
    '</md:IDPSSODescriptor>',
    '</md:EntityDescriptor>',
  ].join("");
}

function pemCertificateBody(certificatePem: string): string {
  const header = certificatePem.indexOf("-----BEGIN CERTIFICATE-----");
  const footer = certificatePem.lastIndexOf("-----END CERTIFICATE-----");
  if (header < 0 || footer < 0 || footer < header) throw new Error("certificate is not PEM");
  return certificatePem.slice(header + "-----BEGIN CERTIFICATE-----".length, footer).replace(/\s+/g, "");
}
