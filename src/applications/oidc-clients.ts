/**
 * Administrator API for OAuth 2.0 / OpenID Connect clients that sit behind an
 * application. The provider's own dynamic registration stays off; clients are
 * created here, with a random id, and shown their secret once. Secrets are
 * stored as the provider stores them: SHA-256, base64url, no padding.
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import { auditStandaloneOperation } from "../audit/store";
import { STANDARD_SCOPES, workpassClientId } from "../auth/workpass";
import { isSafeBackchannelUri } from "../oauth/backchannel-uri";

export const oidcClientRoutes = new Hono<{ Bindings: Env }>();

export const CLIENT_TYPES = ["web", "spa", "native", "service"] as const;
export type ClientType = (typeof CLIENT_TYPES)[number];

/** What the administrator picks, and the grant-type string the provider stores for it. */
export const GRANTS = {
  authorization_code: "authorization_code",
  refresh_token: "refresh_token",
  client_credentials: "client_credentials",
  device_code: "urn:ietf:params:oauth:grant-type:device_code",
  ciba: "urn:openid:params:grant-type:ciba",
} as const;
export type GrantKey = keyof typeof GRANTS;

const GRANT_BY_URN = new Map<string, GrantKey>(
  (Object.entries(GRANTS) as Array<[GrantKey, string]>).map(([key, urn]) => [urn, key]),
);
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

function randomId(length: number): string {
  let id = "";
  while (id.length < length) {
    for (const byte of crypto.getRandomValues(new Uint8Array(length))) {
      if (byte < 248 && id.length < length) id += ALPHABET[byte % 62];
    }
  }
  return id;
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function hashSecret(secret: string): Promise<string> {
  return base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret))));
}

function newSecret(): string {
  return base64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export interface ClientInput {
  name: string;
  applicationType: ClientType;
  grants: GrantKey[];
  redirectUris: string[];
  postLogoutRedirectUris: string[];
  scopes: string[];
  requirePkce: boolean;
  dpop: boolean;
  backchannelLogoutUri?: string | null;
  backchannelLogoutSessionRequired?: boolean;
}

const CONTROL = /[\u0000-\u001f\u007f]/;
const SERVICE_SCOPE = /^[A-Za-z0-9._:-]{1,100}$/;

function uriList(value: unknown, label: string, type: ClientType, max = 10): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > max) throw new Error(`${label}는 ${max}개까지 넣을 수 있습니다.`);
  const seen = new Set<string>();
  for (const entry of value) {
    if (typeof entry !== "string" || entry.length === 0 || entry.length > 2048 || CONTROL.test(entry)) {
      throw new Error(`${label} 형식이 올바르지 않습니다.`);
    }
    let url: URL;
    try {
      url = new URL(entry);
    } catch {
      throw new Error(`${label}가 올바른 주소가 아닙니다: ${entry}`);
    }
    if (url.hash || url.username || url.password) throw new Error(`${label}에는 #이나 계정 정보를 넣을 수 없습니다.`);
    const web = url.protocol === "https:" || url.protocol === "http:";
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (web) {
      if (url.protocol === "http:" && !loopback) throw new Error(`${label}는 https여야 합니다. http는 localhost만 됩니다.`);
    } else if (type !== "native") {
      throw new Error(`${label}는 https 주소여야 합니다.`);
    } else if (/^(javascript|data|file|vbscript):$/i.test(url.protocol)) {
      throw new Error(`${label}에 쓸 수 없는 방식입니다.`);
    }
    if (entry.includes("*")) throw new Error(`${label}에는 와일드카드(*)를 쓸 수 없습니다.`);
    seen.add(entry);
  }
  return [...seen];
}

export function validateClientInput(raw: unknown, mode: "create" | "patch"): Partial<ClientInput> {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("요청 형식이 올바르지 않습니다.");
  const value = { ...(raw as Record<string, unknown>) };
  if (value.backchannelLogoutUri === undefined && value.backchannel_logout_uri !== undefined) value.backchannelLogoutUri = value.backchannel_logout_uri;
  if (value.backchannelLogoutSessionRequired === undefined && value.backchannel_logout_session_required !== undefined) value.backchannelLogoutSessionRequired = value.backchannel_logout_session_required;
  const out: Partial<ClientInput> = {};

  if (mode === "create" || value.name !== undefined) {
    if (typeof value.name !== "string" || !value.name.trim() || value.name.trim().length > 128 || CONTROL.test(value.name)) {
      throw new Error("이름은 1자에서 128자 사이여야 합니다.");
    }
    out.name = value.name.trim();
  }
  if (mode === "create") {
    if (typeof value.applicationType !== "string" || !(CLIENT_TYPES as readonly string[]).includes(value.applicationType)) {
      throw new Error("앱 유형은 web, spa, native, service 중 하나여야 합니다.");
    }
    out.applicationType = value.applicationType as ClientType;
  }
  const type = out.applicationType ?? (value.applicationType as ClientType | undefined) ?? "web";

  if (value.grants !== undefined) {
    if (!Array.isArray(value.grants) || value.grants.some((g) => typeof g !== "string" || !(g in GRANTS))) {
      throw new Error("지원하지 않는 부여 방식이 있습니다.");
    }
    out.grants = [...new Set(value.grants as GrantKey[])];
  } else if (mode === "create") {
    out.grants = type === "service" ? ["client_credentials"] : ["authorization_code"];
  }
  if (out.grants) {
    if (type === "service") {
      if (out.grants.join() !== "client_credentials") throw new Error("API 서비스 앱은 클라이언트 자격 증명만 쓸 수 있습니다.");
    } else {
      if (out.grants.includes("client_credentials")) throw new Error("이 유형의 앱은 클라이언트 자격 증명을 쓸 수 없습니다.");
      if (!out.grants.includes("authorization_code") && !out.grants.includes("device_code") && !out.grants.includes("ciba")) {
        throw new Error("로그인 방식(인증 코드, 기기 코드, CIBA)을 하나 이상 고르세요.");
      }
      if (out.grants.includes("refresh_token") && !out.grants.includes("authorization_code") && !out.grants.includes("device_code") && !out.grants.includes("ciba")) {
        throw new Error("리프레시 토큰은 다른 부여 방식과 함께 써야 합니다.");
      }
      if (type === "spa" && (out.grants.includes("ciba"))) throw new Error("SPA 앱은 CIBA를 쓸 수 없습니다.");
    }
  }

  if (value.redirectUris !== undefined || mode === "create") {
    out.redirectUris = uriList(value.redirectUris, "로그인 리다이렉트 주소", type);
    const needsRedirect = out.grants ? out.grants.includes("authorization_code") : type !== "service";
    if (needsRedirect && out.redirectUris.length === 0 && type !== "service") {
      throw new Error("로그인 리다이렉트 주소를 하나 이상 넣으세요.");
    }
  }
  if (value.postLogoutRedirectUris !== undefined) out.postLogoutRedirectUris = uriList(value.postLogoutRedirectUris, "로그아웃 리다이렉트 주소", type);
  if (mode === "create" && out.postLogoutRedirectUris === undefined) out.postLogoutRedirectUris = [];

  if (value.scopes !== undefined) {
    if (!Array.isArray(value.scopes) || value.scopes.length > 20 || value.scopes.some((s) => typeof s !== "string")) {
      throw new Error("범위 형식이 올바르지 않습니다.");
    }
    const scopes = [...new Set(value.scopes as string[])];
    if (type === "service") {
      if (scopes.some((s) => !SERVICE_SCOPE.test(s))) throw new Error("범위는 영문, 숫자, . _ : - 만 쓸 수 있습니다.");
    } else if (scopes.some((s) => !(STANDARD_SCOPES as readonly string[]).includes(s))) {
      throw new Error("사용할 수 없는 범위가 있습니다.");
    }
    out.scopes = scopes;
  }
  if (typeof value.requirePkce === "boolean") out.requirePkce = value.requirePkce;
  if (typeof value.dpop === "boolean") out.dpop = value.dpop;
  if (value.backchannelLogoutUri !== undefined) {
    if (value.backchannelLogoutUri === null || value.backchannelLogoutUri === "") out.backchannelLogoutUri = null;
    else {
      if (typeof value.backchannelLogoutUri !== "string" || !isSafeBackchannelUri(value.backchannelLogoutUri)) throw new Error("로그아웃 주소는 공개 HTTPS 주소여야 합니다.");
      out.backchannelLogoutUri = value.backchannelLogoutUri;
    }
  }
  if (value.backchannelLogoutSessionRequired !== undefined) {
    if (typeof value.backchannelLogoutSessionRequired !== "boolean") throw new Error("세션 필요 설정이 올바르지 않습니다.");
    out.backchannelLogoutSessionRequired = value.backchannelLogoutSessionRequired;
  }
  return out;
}

interface Row {
  id: string;
  clientId: string;
  name: string | null;
  redirectUris: string | null;
  postLogoutRedirectUris: string | null;
  scopes: string | null;
  clientCredentialsScopes: string | null;
  grantTypes: string | null;
  tokenEndpointAuthMethod: string | null;
  applicationType: string | null;
  requirePKCE: number | null;
  dpopBoundAccessTokens: number | null;
  disabled: number | null;
  createdAt: string | number | null;
  backchannelLogoutUri: string | null;
  backchannelLogoutSessionRequired: number | null;
}

function parseList(value: string | null): string[] {
  if (!value) return [];
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((entry): entry is string => typeof entry === "string") : [];
  } catch {
    return [];
  }
}

const SELECT = `SELECT id, clientId, name, redirectUris, postLogoutRedirectUris, scopes, clientCredentialsScopes,
  grantTypes, tokenEndpointAuthMethod, applicationType, requirePKCE, dpopBoundAccessTokens, disabled, createdAt,
  backchannelLogoutUri, backchannelLogoutSessionRequired
  FROM "oauthClient"`;

function present(row: Row) {
  const grants = parseList(row.grantTypes).map((urn) => GRANT_BY_URN.get(urn)).filter((g): g is GrantKey => g !== undefined);
  const confidential = row.tokenEndpointAuthMethod !== "none";
  const service = grants.includes("client_credentials");
  const type: ClientType = service ? "service" : row.applicationType === "native" ? "native" : confidential ? "web" : "spa";
  return {
    clientId: row.clientId,
    name: row.name ?? row.clientId,
    applicationType: type,
    confidential,
    grants,
    redirectUris: parseList(row.redirectUris),
    postLogoutRedirectUris: parseList(row.postLogoutRedirectUris),
    scopes: service ? parseList(row.clientCredentialsScopes) : parseList(row.scopes),
    requirePkce: row.requirePKCE === 1,
    dpop: row.dpopBoundAccessTokens === 1,
    disabled: row.disabled === 1,
    backchannelLogoutUri: row.backchannelLogoutUri ?? null,
    backchannelLogoutSessionRequired: row.backchannelLogoutSessionRequired === 1,
    backchannel_logout_uri: row.backchannelLogoutUri ?? null,
    backchannel_logout_session_required: row.backchannelLogoutSessionRequired === 1,
  };
}

export async function loadOidcClient(env: Env, clientId: string) {
  const row = await env.DB.prepare(`${SELECT} WHERE clientId = ?`).bind(clientId).first<Row>();
  return row ? present(row) : null;
}

function columnsFor(input: ClientInput) {
  const service = input.applicationType === "service";
  const grants = [...new Set(input.grants)];
  // Refresh tokens are issued only to clients that were granted offline_access.
  const scopes = new Set(input.scopes.length ? input.scopes : ["openid", "profile", "email"]);
  if (!service) {
    scopes.add("openid");
    if (grants.includes("refresh_token")) scopes.add("offline_access");
    else scopes.delete("offline_access");
  }
  const responseTypes = grants.includes("authorization_code") ? ["code"] : [];
  return {
    scopes: JSON.stringify(service ? ["openid"] : [...scopes]),
    clientCredentialsScopes: service ? JSON.stringify([...scopes]) : null,
    grantTypes: JSON.stringify(grants.map((g) => GRANTS[g])),
    responseTypes: JSON.stringify(responseTypes),
    redirectUris: JSON.stringify(input.redirectUris),
    postLogoutRedirectUris: JSON.stringify(input.postLogoutRedirectUris),
    tokenEndpointAuthMethod: input.applicationType === "web" || service ? "client_secret_basic" : "none",
    applicationType: input.applicationType === "native" ? "native" : "web",
    requirePKCE: service ? 0 : input.requirePkce || input.applicationType === "spa" || input.applicationType === "native" ? 1 : 0,
    dpop: input.dpop ? 1 : 0,
  };
}

oidcClientRoutes.use("/oidc-clients*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

oidcClientRoutes.get("/oidc-clients/:clientId", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const client = await loadOidcClient(context.env, context.req.param("clientId"));
  return client ? context.json({ client }) : context.json({ error: "클라이언트를 찾을 수 없습니다." }, 404);
});

oidcClientRoutes.post("/oidc-clients", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const body = await context.req.json().catch(() => null);
  let input: ClientInput;
  try {
    const partial = validateClientInput(body, "create");
    input = {
      name: partial.name!,
      applicationType: partial.applicationType!,
      grants: partial.grants!,
      redirectUris: partial.redirectUris ?? [],
      postLogoutRedirectUris: partial.postLogoutRedirectUris ?? [],
      scopes: partial.scopes ?? [],
      requirePkce: partial.requirePkce ?? true,
      dpop: partial.dpop ?? false,
      backchannelLogoutUri: partial.backchannelLogoutUri ?? null,
      backchannelLogoutSessionRequired: partial.backchannelLogoutSessionRequired ?? false,
    };
  } catch (error) {
    return context.json({ error: error instanceof Error ? error.message : "요청이 올바르지 않습니다." }, 400);
  }
  return auditStandaloneOperation(context.env, "oauth.client.create", "/api/admin/oidc-clients", async () => {
    if (input.backchannelLogoutUri && !await context.env.DB.prepare("SELECT 1 FROM oidc_logout_uri_approvals WHERE uri = ?").bind(input.backchannelLogoutUri).first()) {
      return { response: Response.json({ error: "승인되지 않은 로그아웃 주소입니다." }, { status: 400 }), actorUserId: admin.userId, targetUserId: null };
    }
    const clientId = randomId(24);
    const confidential = input.applicationType === "web" || input.applicationType === "service";
    const secret = confidential ? newSecret() : null;
    const cols = columnsFor(input);
    const now = new Date().toISOString();
    await context.env.DB.prepare(
      `INSERT INTO "oauthClient"
         (id, clientId, clientSecret, name, redirectUris, postLogoutRedirectUris, scopes, clientCredentialsScopes,
          grantTypes, responseTypes, tokenEndpointAuthMethod, applicationType, skipConsent, requirePKCE,
          dpopBoundAccessTokens, enableEndSession, disabled, createdAt, updatedAt, backchannelLogoutUri, backchannelLogoutSessionRequired)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, 1, 1, ?, ?, ?, ?)`,
    ).bind(
      crypto.randomUUID(), clientId, secret ? await hashSecret(secret) : null, input.name,
      cols.redirectUris, cols.postLogoutRedirectUris, cols.scopes, cols.clientCredentialsScopes,
      cols.grantTypes, cols.responseTypes, cols.tokenEndpointAuthMethod, cols.applicationType,
      cols.requirePKCE, cols.dpop, now, now, input.backchannelLogoutUri, input.backchannelLogoutSessionRequired ? 1 : 0,
    ).run();
    const client = await loadOidcClient(context.env, clientId);
    return {
      response: Response.json({ client, clientSecret: secret }, { status: 201 }),
      actorUserId: admin.userId,
      targetUserId: clientId,
    };
  });
});

oidcClientRoutes.patch("/oidc-clients/:clientId", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const clientId = context.req.param("clientId");
  if (clientId === (await workpassClientId(context.env))) {
    return context.json({ error: "WorkPass Dashboard의 클라이언트는 바꿀 수 없습니다." }, 409);
  }
  const current = await loadOidcClient(context.env, clientId);
  if (!current) return context.json({ error: "클라이언트를 찾을 수 없습니다." }, 404);
  const body = await context.req.json().catch(() => null);
  let merged: ClientInput;
  try {
    const patch = validateClientInput(body && typeof body === "object" ? { ...body, applicationType: current.applicationType } : body, "patch");
    merged = {
      name: patch.name ?? current.name,
      applicationType: current.applicationType,
      grants: patch.grants ?? current.grants,
      redirectUris: patch.redirectUris ?? current.redirectUris,
      postLogoutRedirectUris: patch.postLogoutRedirectUris ?? current.postLogoutRedirectUris,
      scopes: patch.scopes ?? current.scopes,
      requirePkce: patch.requirePkce ?? current.requirePkce,
      dpop: patch.dpop ?? current.dpop,
      backchannelLogoutUri: patch.backchannelLogoutUri === undefined ? current.backchannelLogoutUri : patch.backchannelLogoutUri,
      backchannelLogoutSessionRequired: patch.backchannelLogoutSessionRequired ?? current.backchannelLogoutSessionRequired,
    };
    // Re-run the cross-field rules on the merged result.
    validateClientInput({ ...merged, grants: merged.grants, redirectUris: merged.redirectUris, applicationType: merged.applicationType }, "create");
  } catch (error) {
    return context.json({ error: error instanceof Error ? error.message : "요청이 올바르지 않습니다." }, 400);
  }
  return auditStandaloneOperation(context.env, "oauth.client.update", context.req.path, async () => {
    if (merged.backchannelLogoutUri && !await context.env.DB.prepare("SELECT 1 FROM oidc_logout_uri_approvals WHERE uri = ?").bind(merged.backchannelLogoutUri).first()) {
      return { response: Response.json({ error: "승인되지 않은 로그아웃 주소입니다." }, { status: 400 }), actorUserId: admin.userId, targetUserId: clientId };
    }
    const cols = columnsFor(merged);
    await context.env.DB.prepare(
      `UPDATE "oauthClient" SET name = ?, redirectUris = ?, postLogoutRedirectUris = ?, scopes = ?,
         clientCredentialsScopes = ?, grantTypes = ?, responseTypes = ?, requirePKCE = ?,
          dpopBoundAccessTokens = ?, updatedAt = ?, backchannelLogoutUri = ?, backchannelLogoutSessionRequired = ? WHERE clientId = ?`,
    ).bind(
      merged.name, cols.redirectUris, cols.postLogoutRedirectUris, cols.scopes, cols.clientCredentialsScopes,
      cols.grantTypes, cols.responseTypes, cols.requirePKCE, cols.dpop, new Date().toISOString(), merged.backchannelLogoutUri, merged.backchannelLogoutSessionRequired ? 1 : 0, clientId,
    ).run();
    return {
      response: Response.json({ client: await loadOidcClient(context.env, clientId) }),
      actorUserId: admin.userId,
      targetUserId: clientId,
    };
  });
});

oidcClientRoutes.post("/oidc-clients/:clientId/rotate-secret", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const clientId = context.req.param("clientId");
  const client = await loadOidcClient(context.env, clientId);
  if (!client) return context.json({ error: "클라이언트를 찾을 수 없습니다." }, 404);
  if (!client.confidential) return context.json({ error: "공개 클라이언트에는 비밀키가 없습니다." }, 409);
  return auditStandaloneOperation(context.env, "oauth.client.secret_rotate", context.req.path, async () => {
    const secret = newSecret();
    await context.env.DB.prepare('UPDATE "oauthClient" SET clientSecret = ?, updatedAt = ? WHERE clientId = ?')
      .bind(await hashSecret(secret), new Date().toISOString(), clientId).run();
    return { response: Response.json({ clientSecret: secret }), actorUserId: admin.userId, targetUserId: clientId };
  });
});

oidcClientRoutes.delete("/oidc-clients/:clientId", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) return admin;
  const clientId = context.req.param("clientId");
  if (clientId === (await workpassClientId(context.env))) {
    return context.json({ error: "WorkPass Dashboard의 클라이언트는 삭제할 수 없습니다." }, 409);
  }
  if (!(await loadOidcClient(context.env, clientId))) return context.json({ error: "클라이언트를 찾을 수 없습니다." }, 404);
  const inUse = await context.env.DB.prepare("SELECT slug FROM applications WHERE protocol = 'oidc' AND binding = ? LIMIT 1")
    .bind(clientId).first<{ slug: string }>();
  if (inUse) return context.json({ error: "앱이 이 클라이언트를 쓰고 있습니다. 앱을 먼저 지우세요." }, 409);
  return auditStandaloneOperation(context.env, "oauth.client.delete", context.req.path, async () => {
    await context.env.DB.prepare('DELETE FROM "oauthClient" WHERE clientId = ?').bind(clientId).run();
    return { response: Response.json({ deleted: true }), actorUserId: admin.userId, targetUserId: clientId };
  });
});
