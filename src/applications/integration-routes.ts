/**
 * What sits behind an application and who may open it: the protocol provider
 * (OIDC client, SAML service provider, WS-Federation relying party, SWA
 * origin) and the group assignment. Kept next to the application registry so
 * the console can show and change one app in one place.
 */

import { appAudience, notifyUsers } from "../users/notifications";
import { Hono } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import { auditStandaloneOperation } from "../audit/store";
import { getApplication, type ApplicationRow } from "./store";
import { loadOidcClient } from "./oidc-clients";
import { workpassClientId } from "../auth/workpass";
import { loadAppAccessPolicy, upsertAppAccessPolicy } from "../access/policies";
import {
  getSamlServiceProvider,
  setSamlServiceProviderEnabled,
  validateSamlServiceProvider,
} from "../saml/service-providers";
import { importSamlServiceProviderTrustedKey } from "../saml/certificates";
import { setWsfedRelyingPartyEnabled, validateWsfedRelyingParty } from "../wsfed/relying-parties";
import { setSwaApplicationEnabled } from "../swa/applications";

export const integrationRoutes = new Hono<{ Bindings: Env }>();

integrationRoutes.use("/applications/*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

/** The subject the protocol's own access gate reads, if the app has a provider. */
export function protocolSubject(app: Pick<ApplicationRow, "protocol" | "binding">): string | null {
  if (!app.binding || app.protocol === "bookmark") return null;
  return `${app.protocol}:${app.binding}`;
}

async function samlByEntity(env: Env, entityId: string) {
  const row = await env.DB.prepare("SELECT id FROM saml_service_providers WHERE entity_id = ?").bind(entityId).first<{ id: string }>();
  return row ? getSamlServiceProvider(env, row.id) : null;
}

/** Turn the provider behind an app on or off with the app. Returns an error message, or null. */
export async function syncProvider(env: Env, app: ApplicationRow, enabled: boolean): Promise<string | null> {
  if (!app.binding) return null;
  if (app.protocol === "oidc") {
    if (enabled === false && app.binding === (await workpassClientId(env))) return null;
    await env.DB.prepare('UPDATE "oauthClient" SET disabled = ?, updatedAt = ? WHERE clientId = ?')
      .bind(enabled ? 0 : 1, new Date().toISOString(), app.binding).run();
    return null;
  }
  if (app.protocol === "saml") {
    const provider = await samlByEntity(env, app.binding);
    if (!provider) return "SAML 서비스 제공자를 찾을 수 없습니다.";
    if (enabled) {
      try {
        await importSamlServiceProviderTrustedKey(provider.signingCertificate);
      } catch {
        return "저장된 서명 인증서를 쓸 수 없습니다. RSA 인증서(PEM)를 다시 넣으세요.";
      }
    }
    await setSamlServiceProviderEnabled(env, provider.id, enabled);
    return null;
  }
  if (app.protocol === "wsfed") {
    const row = await env.DB.prepare("SELECT id FROM wsfed_relying_parties WHERE realm = ?").bind(app.binding).first<{ id: string }>();
    if (!row) return "WS-Fed 신뢰 당사자를 찾을 수 없습니다.";
    await setWsfedRelyingPartyEnabled(env, row.id, enabled);
    return null;
  }
  if (app.protocol === "swa") {
    const row = await env.DB.prepare("SELECT id FROM swa_applications WHERE origin = ?").bind(app.binding).first<{ id: string }>();
    if (!row) return "SWA 앱을 찾을 수 없습니다.";
    await setSwaApplicationEnabled(env, row.id, enabled);
  }
  return null;
}

/** Remove the provider an app owned. The default dashboard client is never touched. */
export async function removeProvider(env: Env, app: ApplicationRow): Promise<void> {
  if (!app.binding) return;
  const shared = await env.DB.prepare("SELECT slug FROM applications WHERE protocol = ? AND binding = ? AND slug != ? LIMIT 1")
    .bind(app.protocol, app.binding, app.slug).first();
  if (shared) return;
  if (app.protocol === "oidc") {
    if (app.binding === (await workpassClientId(env))) return;
    await env.DB.prepare('DELETE FROM "oauthClient" WHERE clientId = ?').bind(app.binding).run();
  } else if (app.protocol === "saml") {
    await env.DB.prepare("DELETE FROM saml_service_providers WHERE entity_id = ?").bind(app.binding).run();
  } else if (app.protocol === "wsfed") {
    await env.DB.prepare("DELETE FROM wsfed_relying_parties WHERE realm = ?").bind(app.binding).run();
  } else if (app.protocol === "swa") {
    await env.DB.prepare("DELETE FROM swa_applications WHERE origin = ?").bind(app.binding).run();
  }
  const subject = protocolSubject(app);
  if (subject) {
    await env.DB.prepare("DELETE FROM app_access_policies WHERE subject = ?").bind(subject).run();
    await env.DB.prepare("DELETE FROM app_policy_groups WHERE subject = ?").bind(subject).run();
  }
}

integrationRoutes.get("/applications/:slug/integration", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const app = await getApplication(context.env, context.req.param("slug"));
  if (!app) return context.json({ error: "앱을 찾을 수 없습니다." }, 404);
  const origin = new URL(context.env.AUTH_BASE_URL).origin;
  const base = { protocol: app.protocol, binding: app.binding, issuer: origin };

  if (app.protocol === "oidc" && app.binding) {
    return context.json({ ...base, oidc: await loadOidcClient(context.env, app.binding) });
  }
  if (app.protocol === "saml" && app.binding) {
    const provider = await samlByEntity(context.env, app.binding);
    return context.json({
      ...base,
      saml: provider && { entityId: provider.entityId, acsUrl: provider.acsUrl, signingCertificate: provider.signingCertificate },
      endpoints: { metadata: `${origin}/saml/metadata`, sso: `${origin}/saml/sso` },
    });
  }
  if (app.protocol === "wsfed" && app.binding) {
    const row = await context.env.DB.prepare("SELECT realm, reply_url AS replyUrl FROM wsfed_relying_parties WHERE realm = ?")
      .bind(app.binding).first<{ realm: string; replyUrl: string }>();
    return context.json({ ...base, wsfed: row, endpoints: { metadata: `${origin}/wsfed/metadata`, signin: `${origin}/wsfed/signin` } });
  }
  if (app.protocol === "swa" && app.binding) {
    const row = await context.env.DB.prepare("SELECT name, origin FROM swa_applications WHERE origin = ?")
      .bind(app.binding).first<{ name: string; origin: string }>();
    return context.json({ ...base, swa: row });
  }
  return context.json(base);
});

/** Change the provider settings that can change in place. Other changes mean a new registration. */
integrationRoutes.put("/applications/:slug/integration", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const app = await getApplication(context.env, context.req.param("slug"));
  if (!app || !app.binding) return context.json({ error: "앱을 찾을 수 없습니다." }, 404);
  const body = (await context.req.json().catch(() => null)) as Record<string, unknown> | null;
  if (!body || typeof body !== "object") return context.json({ error: "요청 형식이 올바르지 않습니다." }, 400);

  if (app.protocol === "saml") {
    const provider = await samlByEntity(context.env, app.binding);
    if (!provider) return context.json({ error: "SAML 서비스 제공자를 찾을 수 없습니다." }, 404);
    const next = {
      ...provider,
      acsUrl: typeof body.acsUrl === "string" ? body.acsUrl.trim() : provider.acsUrl,
      signingCertificate: typeof body.signingCertificate === "string" ? body.signingCertificate.trim() : provider.signingCertificate,
    };
    try {
      validateSamlServiceProvider(next);
      await importSamlServiceProviderTrustedKey(next.signingCertificate);
    } catch {
      return context.json({ error: "ACS 주소는 https여야 하고, 서명 인증서는 RSA 인증서(PEM)여야 합니다." }, 400);
    }
    return auditStandaloneOperation(context.env, "saml.service_provider.update", context.req.path, async () => {
      await context.env.DB.prepare("UPDATE saml_service_providers SET acs_url = ?, signing_certificate = ? WHERE id = ?")
        .bind(next.acsUrl, next.signingCertificate, provider.id).run();
      return { response: Response.json({ updated: true }), actorUserId: admin.userId, targetUserId: provider.id };
    });
  }
  if (app.protocol === "wsfed") {
    const row = await context.env.DB.prepare("SELECT id, realm FROM wsfed_relying_parties WHERE realm = ?")
      .bind(app.binding).first<{ id: string; realm: string }>();
    if (!row) return context.json({ error: "WS-Fed 신뢰 당사자를 찾을 수 없습니다." }, 404);
    const replyUrl = typeof body.replyUrl === "string" ? body.replyUrl.trim() : "";
    try {
      validateWsfedRelyingParty({ id: row.id, realm: row.realm, replyUrl, enabled: false });
    } catch {
      return context.json({ error: "회신 주소는 https 주소여야 합니다." }, 400);
    }
    return auditStandaloneOperation(context.env, "wsfed.relying_party.update", context.req.path, async () => {
      await context.env.DB.prepare("UPDATE wsfed_relying_parties SET reply_url = ? WHERE id = ?").bind(replyUrl, row.id).run();
      return { response: Response.json({ updated: true }), actorUserId: admin.userId, targetUserId: row.id };
    });
  }
  return context.json({ error: "이 방식은 여기서 바꿀 수 있는 설정이 없습니다." }, 409);
});

/** Who gets the app: everyone who signs in, or members of chosen groups. */
integrationRoutes.get("/applications/:slug/assignment", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const app = await getApplication(context.env, context.req.param("slug"));
  if (!app) return context.json({ error: "앱을 찾을 수 없습니다." }, 404);
  const policy = await loadAppAccessPolicy(context.env, `app:${app.slug}`).catch(() => null);
  const groupIds = policy?.groups ?? [];
  const groups = groupIds.length
    ? (await context.env.DB.prepare(
        `SELECT id, name FROM directory_groups WHERE id IN (${groupIds.map(() => "?").join(",")}) ORDER BY name ASC`,
      ).bind(...groupIds).all<{ id: string; name: string }>()).results
    : [];
  return context.json({ mode: groupIds.length ? "groups" : "everyone", groups, mfaMethods: policy?.mfaMethods ?? [] });
});

integrationRoutes.put("/applications/:slug/assignment", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const app = await getApplication(context.env, context.req.param("slug"));
  if (!app) return context.json({ error: "앱을 찾을 수 없습니다." }, 404);
  const body = (await context.req.json().catch(() => null)) as { mode?: unknown; groups?: unknown } | null;
  const mode = body?.mode === "groups" ? "groups" : body?.mode === "everyone" ? "everyone" : null;
  if (!mode) return context.json({ error: "mode는 everyone 또는 groups여야 합니다." }, 400);
  const groups = mode === "groups" && Array.isArray(body?.groups)
    ? [...new Set((body!.groups as unknown[]).filter((g): g is string => typeof g === "string" && g.length <= 128))]
    : [];
  if (mode === "groups" && groups.length === 0) {
    return context.json({ error: "그룹을 하나 이상 고르세요. 아무도 열지 못하게 하려면 앱을 끄세요." }, 400);
  }
  if (groups.length) {
    const found = await context.env.DB.prepare(`SELECT id FROM directory_groups WHERE id IN (${groups.map(() => "?").join(",")})`)
      .bind(...groups).all<{ id: string }>();
    if (found.results.length !== groups.length) return context.json({ error: "없는 그룹이 있습니다." }, 400);
  }
  const before = new Set(await appAudience(context.env, app.slug));
  return auditStandaloneOperation(context.env, "app.assignment.update", context.req.path, async () => {
    // The dashboard card and the protocol's own gate read different subjects;
    // both follow the same groups so an assignment cannot be bypassed by a direct link.
    for (const subject of [`app:${app.slug}`, protocolSubject(app)]) {
      if (!subject) continue;
      const existing = await loadAppAccessPolicy(context.env, subject).catch(() => null);
      await upsertAppAccessPolicy(context.env, {
        subject,
        allowedMethods: existing?.allowedMethods ?? "password,passkey",
        sessionTtlSeconds: existing?.sessionTtlSeconds ?? null,
        bypassWindowSeconds: existing?.bypassWindowSeconds ?? 28800,
        enforcementMode: existing?.enforcementMode ?? "enforce",
        requireMfa: existing?.requireMfa ?? false,
        mfaMethods: existing?.mfaMethods ?? [],
        groups,
        requiredAccount: existing?.requiredAccount ?? null,
      }, admin.userId);
    }
    if (app.enabled) {
      const gained = (await appAudience(context.env, app.slug)).filter((id) => !before.has(id));
      await notifyUsers(context.env, gained, { kind: "app_assigned", title: "새 앱이 할당되었습니다", body: `${app.name}을(를) 이제 열 수 있습니다.`, link: "/" });
    }
    return { response: Response.json({ mode, groups }), actorUserId: admin.userId, targetUserId: app.slug };
  });
});
