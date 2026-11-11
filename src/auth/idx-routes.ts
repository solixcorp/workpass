/**
 * Remediation-driven identification for the WorkPass sign-in screen.
 *
 *   POST /api/v1/internal/device/nonce   -> { nonce, expiresAt }
 *   POST /idp/idx/introspect             -> stateHandle + identify remediation
 *   POST /idp/idx/identify               -> stateHandle + authenticator remediation
 *   POST /idp/idx/challenge              -> stateHandle + challenge for one authenticator
 *   POST /idp/idx/cancel                 -> restart
 *
 * Every response is a state machine step: `remediation` names what the client
 * must do next (identify, select-authenticator-authenticate,
 * challenge-authenticator) and the sign-in screen renders from it.
 *   GET  /api/config/login               -> public, non-secret browser config
 *
 * The stateHandle is a sealed (AEAD) blob, so the flow state lives in the
 * client and the server stays stateless (no D1 writes on the free plan).
 *
 * Authenticator lists come from the admin policy for the WorkPass client
 * (`oidc:workpass` allowed_methods) intersected with what the account has
 * enrolled. Account existence must not be observable: an unknown identifier
 * receives a deterministic, plausible list derived from an HMAC of the
 * identifier, and `password` is offered to everyone because the OPAQUE
 * handshake already answers identically for known and unknown accounts.
 * The password step itself is OPAQUE (/api/opaque/*); it never travels here.
 */

import { evaluateLocation, loadLocationPolicy } from "../security/location-policy";
import { Hono } from "hono";
import type { Context } from "hono";
import type { Env } from "../env";
import { sealString, unsealString } from "../crypto/sealed";
import { loadAppAccessPolicy } from "../access/policies";
import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";
import { fingerprintMode } from "../security/fingerprint";
import { WORKPASS_CLIENT_NAME, WORKPASS_SCOPES, WORKPASS_SLUG, workpassClientId } from "./workpass";
import { passkeyAllowed } from "../mfa/policy";
import { organizationName } from "../settings/registry";
import { getApplication } from "../applications/store";
import { iconDisplayPath } from "../applications/icons";
import { issueActivationLink, activationUrl, markActivationDelivered } from "../security/account-activation";
import { sendTransactionEmail, transactionEmailAvailable } from "../mail/send";
import { insertAuditEvent } from "../audit/store";

export const idxRoutes = new Hono<{ Bindings: Env }>();

const STATE_TTL_MS = 10 * 60 * 1000;
const NONCE_TTL_MS = 5 * 60 * 1000;
const MAX_IDENTIFIER_LENGTH = 256;
const ION = "application/ion+json; version=1.0.0";
const ACCEPTS = "application/json; version=1.0.0";

type AuthenticatorKey = "password" | "webauthn";

interface AuthenticatorDefinition {
  key: AuthenticatorKey;
  type: "password" | "security_key";
  displayName: string;
  description?: string;
  icon: "password" | "passkey";
  id: string;
  methodType: string;
}

const CATALOG: Record<AuthenticatorKey, AuthenticatorDefinition> = {
  password: { key: "password", type: "password", displayName: "비밀번호", icon: "password", id: "autPasswordWorkPass0001", methodType: "password" },
  webauthn: { key: "webauthn", type: "security_key", displayName: "패스키", description: "기기 잠금 또는 보안 키 사용", icon: "passkey", id: "autWebauthnWorkPass0002", methodType: "webauthn" },
};

/** Copy for outcomes that resolve on other endpoints (OPAQUE, WebAuthn). */
const OUTCOME_MESSAGES = {
  invalid_credentials: "비밀번호가 올바르지 않습니다.",
  passkey_failed: "패스키 인증이 취소되었거나 실패했습니다.",
  rate_limited: "시도가 너무 많습니다. 잠시 후 다시 시도하세요.",
  denied: "이 계정으로는 로그인할 수 없습니다. 관리자에게 문의하세요.",
  unavailable: "지금은 로그인할 수 없습니다. 잠시 후 다시 시도하세요.",
  forbidden_app: "이 앱에 접근할 권한이 없습니다.",
  incomplete: "로그인을 완료하지 못했습니다. 다시 시도하세요.",
  link_sent: "해당 계정이 있으면 비밀번호를 설정할 수 있는 링크를 메일로 보냈습니다. 메일함을 확인하세요.",
  link_unavailable: "지금은 링크를 보낼 수 없습니다. 잠시 후 다시 시도하세요.",
  location_denied: "허용된 장소 밖에서는 로그인할 수 없습니다. 지정된 장소 근처에서 다시 시도하세요.",
  location_outside: "지금 위치는 허용된 장소 근처가 아닙니다.",
  location_inaccurate: "위치가 충분히 정확하지 않습니다. 위치 서비스를 켜고 다시 시도하세요.",
  location_blocked: "브라우저가 위치 공유를 허용하지 않았습니다. 주소창의 위치 권한을 허용한 뒤 다시 시도하세요.",
} as const;

const POLICY_METHOD_TO_KEY: Record<string, AuthenticatorKey> = {
  password: "password",
  passkey: "webauthn",
};

interface StatePayload {
  v: 1;
  exp: number;
  identifier?: string;
}

const encoder = new TextEncoder();

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function hmac(env: Env, label: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(env.AUTH_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(label)));
}

function clientIp(context: Context<{ Bindings: Env }>): string {
  return context.req.header("cf-connecting-ip")
    ?? context.req.header("x-forwarded-for")?.split(",")[0]?.trim()
    ?? "127.0.0.1";
}

async function withinRateLimit(context: Context<{ Bindings: Env }>): Promise<boolean> {
  const nowMinute = Math.floor(Date.now() / 60_000);
  const row = await context.env.DB.prepare(
    `INSERT INTO fingerprint_lookup_limits (budget_key, window_start, request_count)
     VALUES (?, ?, 1)
     ON CONFLICT(budget_key) DO UPDATE SET
       request_count = CASE WHEN fingerprint_lookup_limits.window_start = excluded.window_start
                            THEN fingerprint_lookup_limits.request_count + 1 ELSE 1 END,
       window_start = excluded.window_start
     RETURNING request_count`,
  ).bind(`idx:${clientIp(context)}`, nowMinute).first<{ request_count: number }>().catch(() => null);
  return (row?.request_count ?? Number.POSITIVE_INFINITY) <= 60;
}

function errorBody(summary: string, status: 400 | 401 | 429) {
  return {
    status,
    body: {
      errorSummary: summary,
      messages: { type: "array", value: [{ message: summary, class: "ERROR" }] },
    },
  };
}

async function sealState(env: Env, payload: Omit<StatePayload, "v" | "exp">): Promise<{ handle: string; expiresAt: string }> {
  const exp = Date.now() + STATE_TTL_MS;
  const sealed = await sealString(env, JSON.stringify({ v: 1, exp, ...payload } satisfies StatePayload), "idx:state");
  return { handle: `02.id.${sealed}`, expiresAt: new Date(exp).toISOString() };
}

async function openState(env: Env, handle: unknown): Promise<StatePayload | null> {
  if (typeof handle !== "string" || !handle.startsWith("02.id.") || handle.length > 2048) return null;
  try {
    const parsed = JSON.parse(await unsealString(env, handle.slice("02.id.".length), "idx:state")) as StatePayload;
    if (parsed.v !== 1 || typeof parsed.exp !== "number" || parsed.exp < Date.now()) return null;
    return parsed;
  } catch {
    return null;
  }
}

async function policyAuthenticators(env: Env): Promise<AuthenticatorKey[]> {
  const policy = await loadAppAccessPolicy(env, `oidc:${await workpassClientId(env)}`).catch(() => null);
  const configured = (policy?.allowedMethods ?? "password,passkey")
    .split(",")
    .map((method) => POLICY_METHOD_TO_KEY[method.trim()])
    .filter((key): key is AuthenticatorKey => key !== undefined);
  const unique = [...new Set(configured)].filter((key) => key !== "webauthn" || passkeyAllowed(env));
  return unique.length > 0 ? unique : ["password"];
}

async function authenticatorsFor(env: Env, identifier: string): Promise<AuthenticatorKey[]> {
  const allowed = await policyAuthenticators(env);
  const user = await env.DB.prepare('SELECT id FROM "user" WHERE lower(email) = ? LIMIT 1')
    .bind(identifier).first<{ id: string }>().catch(() => null);

  let hasPasskey: boolean;
  if (user) {
    const passkeys = await env.DB.prepare('SELECT COUNT(*) AS count FROM "passkey" WHERE userId = ?')
      .bind(user.id).first<{ count: number }>().catch(() => null);
    hasPasskey = (passkeys?.count ?? 0) > 0;
  } else {
    hasPasskey = ((await hmac(env, `idx-fake:${identifier}`))[0]! & 1) === 1;
  }

  const result = allowed.filter((key) => key === "password" || hasPasskey);
  return result.length > 0 ? result : [allowed[0]!];
}

function formField(name: string, extra: Record<string, unknown> = {}) {
  return { name, ...extra };
}

function stateHandleField(handle: string) {
  return formField("stateHandle", { required: true, value: handle, visible: false, mutable: false });
}

function authenticatorView(definition: AuthenticatorDefinition) {
  return {
    displayName: definition.displayName,
    type: definition.type,
    key: definition.key,
    id: definition.id,
    methods: [{ type: definition.methodType }],
  };
}

function enrollmentView(definition: AuthenticatorDefinition, index: number) {
  return {
    ...authenticatorView(definition),
    profile: undefined,
    relatesTo: `$.authenticatorEnrollments.value[${index}]`,
  };
}

const REQUEST_KEYS = [
  "scope", "response_type", "redirect_uri", "state", "code_challenge_method",
  "code_challenge", "nonce", "prompt", "max_age",
] as const;

/** The authorization request this transaction belongs to, from a verified signed query. */
async function authorizationRequest(env: Env, oauthQuery: unknown): Promise<Record<string, string> | null> {
  if (typeof oauthQuery !== "string" || oauthQuery.length === 0 || oauthQuery.length > 16384) return null;
  if (!(await verifyOAuthQueryParams(oauthQuery, env.AUTH_SECRET).catch(() => false))) return null;
  const params = new URLSearchParams(oauthQuery);
  if (params.get("client_id") !== (await workpassClientId(env))) return null;
  const request: Record<string, string> = {};
  for (const key of REQUEST_KEYS) {
    const value = params.get(key);
    if (value) request[key] = value;
  }
  return request;
}

/**
 * What the sign-in screen shows for one remediation. The client renders this
 * as-is: it owns no titles, labels, fields or button text. `action` names the
 * protocol step the primary button performs; the client only implements the
 * protocols themselves (OPAQUE, WebAuthn) and posts to the hrefs given here.
 */
type UiAction = "identify" | "select-authenticator" | "opaque-password" | "passkey" | "share-location" | "request-link";

interface RemediationUi {
  title: string;
  description?: string;
  badge?: "password" | "passkey";
  fields: Array<{ name: string; kind: "email" | "password"; label: string; autocomplete: string; required: boolean }>;
  options: Array<{ id: string; label: string; description?: string; icon: "password" | "passkey" }>;
  submit?: { label: string };
  action: UiAction;
  alternatives: Array<{
    label: string;
    icon?: "passkey";
    action: "passkey" | "switch-method" | "cancel" | "skip-location" | "request-link";
    placement: "before" | "after";
    variant: "outline" | "link";
  }>;
  separator?: string;
  messages: typeof OUTCOME_MESSAGES;
}

function ui(partial: Omit<RemediationUi, "fields" | "options" | "alternatives" | "messages"> & Partial<RemediationUi>): RemediationUi {
  return { fields: [], options: [], alternatives: [], messages: OUTCOME_MESSAGES, ...partial };
}

const CANCEL_ALTERNATIVE = {
  label: "로그인 화면으로 돌아가기",
  action: "cancel" as const,
  placement: "after" as const,
  variant: "link" as const,
};

async function baseEnvelope(env: Env, handle: string, expiresAt: string, request?: Record<string, string> | null) {
  const clientId = await workpassClientId(env);
  const origin = new URL(env.AUTH_BASE_URL).origin;
  return {
    version: "1.0.0",
    stateHandle: handle,
    expiresAt,
    intent: "LOGIN",
    cancel: {
      rel: ["create-form"],
      name: "cancel",
      href: `${origin}/idp/idx/cancel`,
      method: "POST",
      produces: ION,
      value: [stateHandleField(handle)],
      accepts: ACCEPTS,
    },
    app: {
      type: "object",
      value: { name: "workpass", label: WORKPASS_CLIENT_NAME, id: clientId },
    },
    authentication: {
      type: "object",
      value: {
        protocol: "OAUTH2.0",
        issuer: { name: organizationName(env), uri: origin },
        request: request ?? { scope: ["openid", "profile", "email", ...WORKPASS_SCOPES].join(" "), response_type: "code" },
      },
    },
  };
}

async function identifyResponse(env: Env, handle: string, expiresAt: string, request?: Record<string, string> | null) {
  const origin = new URL(env.AUTH_BASE_URL).origin;
  // The passkey shortcut exists only while the admin policy allows passkeys.
  const passkeyAllowed = (await policyAuthenticators(env)).includes("webauthn");
  return {
    ...(await baseEnvelope(env, handle, expiresAt, request)),
    remediation: {
      type: "array",
      value: [{
        rel: ["create-form"],
        name: "identify",
        href: `${origin}/idp/idx/identify`,
        method: "POST",
        produces: ION,
        value: [
          formField("identifier", { label: "이메일", required: true }),
          stateHandleField(handle),
        ],
        accepts: ACCEPTS,
        ui: ui({
          title: "이메일을 입력하세요",
          action: "identify",
          fields: [{ name: "identifier", kind: "email", label: "이메일", autocomplete: "username webauthn", required: true }],
          submit: { label: "다음" },
          alternatives: passkeyAllowed
            ? [{ label: "패스키로 로그인", icon: "passkey", action: "passkey", placement: "before", variant: "outline" }]
            : [],
          separator: passkeyAllowed ? "또는" : undefined,
        }),
      }],
    },
  };
}

/** Asks the browser to share where it is, when the organization limits sign-in to certain places. */
async function locationResponse(env: Env, handle: string, expiresAt: string, request?: Record<string, string> | null) {
  const origin = new URL(env.AUTH_BASE_URL).origin;
  return {
    ...(await baseEnvelope(env, handle, expiresAt, request)),
    remediation: {
      type: "array",
      value: [{
        rel: ["create-form"],
        name: "verify-location",
        href: `${origin}/api/location/proof`,
        method: "POST",
        produces: ION,
        value: [stateHandleField(handle)],
        accepts: ACCEPTS,
        ui: ui({
          title: "위치를 확인하세요",
          description: "이 조직은 지정된 장소 근처에서만 로그인할 수 있습니다. 브라우저에서 내 위치를 공유해 주세요. 위치는 저장하지 않고, 허용된 장소 안인지만 확인합니다.",
          action: "share-location",
          submit: { label: "내 위치 공유" },
          alternatives: [{ label: "지금은 건너뛰기", action: "skip-location", placement: "after", variant: "link" }],
        }),
      }],
    },
  };
}

function challengeRemediation(
  origin: string,
  handle: string,
  definition: AuthenticatorDefinition,
  identifier: string,
  canSwitch: boolean,
) {
  const switchAlternative = canSwitch
    ? [{ label: "다른 방법으로 확인", action: "switch-method" as const, placement: "after" as const, variant: "link" as const }]
    : [];
  const common = {
    rel: ["create-form"],
    name: "challenge-authenticator",
    relatesTo: ["$.currentAuthenticatorEnrollment"],
    method: "POST",
    produces: ION,
    accepts: ACCEPTS,
  };
  if (definition.key === "webauthn") {
    return {
      ...common,
      href: `${origin}/api/auth/passkey/verify-authentication`,
      value: [
        formField("credentials", { type: "object", required: true, form: { value: [formField("response", { required: true })] } }),
        stateHandleField(handle),
      ],
      ui: ui({
        title: "패스키로 확인",
        badge: "passkey",
        action: "passkey",
        submit: { label: "패스키 사용" },
      alternatives: [...switchAlternative, CANCEL_ALTERNATIVE],
      }),
    };
  }
  // The password is never sent: the client runs the OPAQUE exchange against
  // this endpoint, which carries protocol messages only.
  return {
    ...common,
    href: `${origin}/api/opaque/auth/start`,
    protocol: "opaque",
    value: [
      formField("identifier", { value: identifier, visible: false, mutable: false }),
      formField("credentials", { type: "object", required: true, form: { value: [formField("passcode", { label: definition.displayName, secret: true })] } }),
      stateHandleField(handle),
    ],
    ui: ui({
      title: "비밀번호로 확인",
      badge: "password",
      action: "opaque-password",
      fields: [{ name: "passcode", kind: "password", label: "비밀번호", autocomplete: "current-password", required: true }],
      submit: { label: "확인" },
      alternatives: [
        ...switchAlternative,
        { label: "비밀번호 설정·재설정 링크 받기", action: "request-link", placement: "after", variant: "link" },
        CANCEL_ALTERNATIVE,
      ],
    }),
  };
}

async function authenticatorResponse(
  env: Env,
  handle: string,
  expiresAt: string,
  identifier: string,
  keys: AuthenticatorKey[],
  options: { selected?: AuthenticatorKey; forceSelect?: boolean; request?: Record<string, string> | null } = {},
) {
  const origin = new URL(env.AUTH_BASE_URL).origin;
  const definitions = keys.map((key) => CATALOG[key]);
  const enrollments = definitions.map(enrollmentView);
  const base = await baseEnvelope(env, handle, expiresAt, options.request);

  // One available method needs no choice: go straight to its challenge.
  const currentIndex = options.forceSelect
    ? -1
    : options.selected
      ? definitions.findIndex((definition) => definition.key === options.selected)
      : definitions.length === 1 ? 0 : -1;

  const selectRemediation = {
    rel: ["create-form"],
    name: "select-authenticator-authenticate",
    href: `${origin}/idp/idx/challenge`,
    method: "POST",
    produces: ION,
    value: [
      formField("authenticator", {
        type: "object",
        options: definitions.map((definition, index) => ({
          label: definition.displayName,
          value: {
            form: {
              value: [
                formField("id", { required: true, value: definition.id, mutable: false }),
                formField("methodType", { required: false, value: definition.methodType, mutable: false }),
              ],
            },
          },
          relatesTo: `$.authenticatorEnrollments.value[${index}]`,
        })),
      }),
      stateHandleField(handle),
    ],
    accepts: ACCEPTS,
    ui: ui({
      title: "본인 확인 방법 선택",
      description: "다음 중 하나로 본인을 확인하세요.",
      action: "select-authenticator",
      options: definitions.map((definition) => ({
        id: definition.id,
        label: definition.displayName,
        description: definition.description,
        icon: definition.icon,
      })),
      alternatives: [CANCEL_ALTERNATIVE],
    }),
  };

  const remediation = currentIndex >= 0
    ? [challengeRemediation(origin, handle, definitions[currentIndex]!, identifier, definitions.length > 1)]
    : [selectRemediation];

  return {
    ...base,
    remediation: { type: "array", value: remediation },
    ...(currentIndex >= 0
      ? { currentAuthenticatorEnrollment: { type: "object", value: enrollments[currentIndex] } }
      : {}),
    authenticators: { type: "array", value: definitions.map(authenticatorView) },
    authenticatorEnrollments: { type: "array", value: enrollments },
    user: { type: "object", value: { identifier } },
  };
}

function normalizeIdentifier(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const identifier = value.trim().toLowerCase();
  return identifier.length > 0 && identifier.length <= MAX_IDENTIFIER_LENGTH ? identifier : null;
}

async function jsonBody(context: Context<{ Bindings: Env }>): Promise<Record<string, unknown>> {
  try {
    const body = await context.req.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : {};
  } catch {
    return {};
  }
}

idxRoutes.use("/idp/idx/*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});
idxRoutes.use("/api/v1/internal/device/*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

idxRoutes.post("/api/v1/internal/device/nonce", async (context) => {
  if (!(await withinRateLimit(context))) {
    const failure = errorBody(OUTCOME_MESSAGES.rate_limited, 429);
    return context.json(failure.body, failure.status);
  }
  const expires = Date.now() + NONCE_TTL_MS;
  const random = base64Url(crypto.getRandomValues(new Uint8Array(15)));
  const signature = base64Url((await hmac(context.env, `idx-nonce:${random}:${expires}`)).slice(0, 12));
  return context.json({
    nonce: `${random}.${expires.toString(36)}.${signature}`,
    expiresAt: new Date(expires).toISOString(),
  });
});

idxRoutes.post("/idp/idx/introspect", async (context) => {
  if (!(await withinRateLimit(context))) {
    const failure = errorBody(OUTCOME_MESSAGES.rate_limited, 429);
    return context.json(failure.body, failure.status);
  }
  const body = await jsonBody(context);
  const request = await authorizationRequest(context.env, body.oauthQuery);
  const { handle, expiresAt } = await sealState(context.env, {});
  // The same for everyone (nothing here depends on an account), so it reveals nothing about one.
  if (body.skipLocation !== true) {
    const policy = await loadLocationPolicy(context.env);
    if (policy.mode === "enforce" && policy.signal !== "network" &&
      !(await evaluateLocation(context.env, { request: context.req.raw, userId: null })).pass) {
      return context.json(await locationResponse(context.env, handle, expiresAt, request));
    }
  }
  return context.json(await identifyResponse(context.env, handle, expiresAt, request));
});

idxRoutes.post("/idp/idx/cancel", async (context) => {
  const { handle, expiresAt } = await sealState(context.env, {});
  return context.json(await identifyResponse(context.env, handle, expiresAt));
});

idxRoutes.post("/idp/idx/identify", async (context) => {
  if (!(await withinRateLimit(context))) {
    const failure = errorBody(OUTCOME_MESSAGES.rate_limited, 429);
    return context.json(failure.body, failure.status);
  }
  const body = await jsonBody(context);
  const state = await openState(context.env, body.stateHandle);
  if (!state) {
    const failure = errorBody("세션이 만료되었습니다. 처음부터 다시 시도하세요.", 401);
    return context.json(failure.body, failure.status);
  }
  const identifier = normalizeIdentifier(body.identifier);
  if (!identifier) {
    const failure = errorBody("이메일을 입력하세요.", 400);
    return context.json(failure.body, failure.status);
  }
  const keys = await authenticatorsFor(context.env, identifier);
  const next = await sealState(context.env, { identifier });
  return context.json(await authenticatorResponse(context.env, next.handle, next.expiresAt, identifier, keys));
});

idxRoutes.post("/idp/idx/challenge", async (context) => {
  if (!(await withinRateLimit(context))) {
    const failure = errorBody(OUTCOME_MESSAGES.rate_limited, 429);
    return context.json(failure.body, failure.status);
  }
  const body = await jsonBody(context);
  const state = await openState(context.env, body.stateHandle);
  if (!state?.identifier) {
    const failure = errorBody("세션이 만료되었습니다. 처음부터 다시 시도하세요.", 401);
    return context.json(failure.body, failure.status);
  }
  const keys = await authenticatorsFor(context.env, state.identifier);
  const next = await sealState(context.env, { identifier: state.identifier });

  // No authenticator chosen: present the choice again ("try another way").
  const chosen = body.authenticator && typeof body.authenticator === "object"
    ? (body.authenticator as { id?: unknown }).id
    : undefined;
  if (chosen === undefined) {
    return context.json(await authenticatorResponse(context.env, next.handle, next.expiresAt, state.identifier, keys, { forceSelect: true }));
  }
  const selected = keys.find((key) => CATALOG[key].id === chosen);
  if (!selected) {
    const failure = errorBody("사용할 수 없는 로그인 방법입니다.", 400);
    return context.json(failure.body, failure.status);
  }
  return context.json(await authenticatorResponse(context.env, next.handle, next.expiresAt, state.identifier, keys, { selected }));
});

idxRoutes.post("/idp/idx/request-link", async (context) => {
  if (!(await withinRateLimit(context))) {
    const failure = errorBody(OUTCOME_MESSAGES.rate_limited, 429);
    return context.json(failure.body, failure.status);
  }
  const body = await jsonBody(context);
  const state = await openState(context.env, body.stateHandle);
  if (!state?.identifier) {
    const failure = errorBody("세션이 만료되었습니다. 처음부터 다시 시도하세요.", 401);
    return context.json(failure.body, failure.status);
  }

  // Account lookup, link issuance and delivery are deferred where Workers
  // provide waitUntil so response behavior does not depend on account state.
  const work = async () => {
    const db = context.env.DB;
    const account = await db.prepare(
      'SELECT id, email, name, COALESCE(banned, 0) AS banned FROM "user" WHERE lower(email) = ? LIMIT 1',
    ).bind(state.identifier).first<{ id: string; email: string; name: string; banned: number }>().catch(() => null);
    try {
      if (account && account.banned !== 1) {
        const locked = await db.prepare(
          "SELECT 1 AS present FROM account_lockdowns WHERE user_id = ? AND lifted_at IS NULL LIMIT 1",
        ).bind(account.id).first<{ present: number }>().catch(() => null);
        if (!locked && await linkRequestBudget(db, account.id) && transactionEmailAvailable(context.env)) {
          const link = await issueActivationLink({ env: context.env, userId: account.id, actorUserId: account.id, deliveredTo: account.email });
          await sendTransactionEmail(context.env, {
            to: account.email,
            subject: "WorkPass 비밀번호 설정·재설정 링크",
            text: [
              `${account.name}님, 안녕하세요.`, "",
              "로그인 화면에서 요청하신 비밀번호 설정·재설정 링크입니다. 링크는 한 번만 사용할 수 있고 만료됩니다.", "",
              activationUrl(context.env, link.token), "",
              "요청하지 않으셨다면 이 메일을 무시하셔도 됩니다.",
            ].join("\n"),
          });
          await markActivationDelivered(context.env, link.token);
        }
      }
    } catch {
      // Delivery and issuance failures are deliberately indistinguishable to the requester.
    }
    await insertAuditEvent(context.env, {
      id: crypto.randomUUID(), actor_user_id: null, target_user_id: account?.id ?? null,
      event_type: "identity.user.link_requested", outcome: "success",
      request_path: "/idp/idx/request-link", client_ip: clientIp(context),
    }).catch(() => undefined);
  };
  const execution = (context as unknown as { executionCtx?: { waitUntil?: (promise: Promise<unknown>) => void } }).executionCtx;
  if (execution?.waitUntil) execution.waitUntil(work());
  else await work();
  return context.json({ sent: true });
});

/** One link per account per hour window, with the first three requests allowed. */
async function linkRequestBudget(db: Env["DB"], userId: string): Promise<boolean> {
  const hour = Math.floor(Date.now() / 3_600_000);
  const row = await db.prepare(
    `INSERT INTO fingerprint_lookup_limits (budget_key, window_start, request_count)
     VALUES (?, ?, 1)
     ON CONFLICT(budget_key) DO UPDATE SET
       request_count = CASE WHEN fingerprint_lookup_limits.window_start = excluded.window_start
                            THEN fingerprint_lookup_limits.request_count + 1 ELSE 1 END,
       window_start = excluded.window_start
     RETURNING request_count`,
  ).bind(`idx:link:${userId}`, hour).first<{ request_count: number }>().catch(() => null);
  return (row?.request_count ?? Number.POSITIVE_INFINITY) <= 3;
}

/** The Fingerprint custom subdomain the browser agent should talk to (https origin only). */
function fingerprintEndpoint(env: Env): string | null {
  const raw = env.FINGERPRINT_ENDPOINT?.trim();
  if (!raw) return null;
  try {
    const url = new URL(raw);
    return url.protocol === "https:" && !url.username && !url.password ? url.origin : null;
  } catch {
    return null;
  }
}

/** Public, non-secret configuration the sign-in screen needs before login. */
idxRoutes.get("/api/config/login", async (context) => {
  let mode: ReturnType<typeof fingerprintMode> = "disabled";
  try {
    mode = fingerprintMode(context.env);
  } catch {
    mode = "disabled";
  }
  const publicKey = context.env.FINGERPRINT_PUBLIC_API_KEY?.trim();
  context.header("Cache-Control", "no-store");
  const row = await getApplication(context.env, WORKPASS_SLUG).catch(() => null);
  return context.json({
    app: {
      id: await workpassClientId(context.env),
      name: WORKPASS_CLIENT_NAME,
      signInTitle: `${WORKPASS_CLIENT_NAME}에 로그인`,
      icon: (row ? iconDisplayPath(row) : null) ?? "/workpass.svg",
    },
    organization: { name: organizationName(context.env) },
    login: { passkey: passkeyAllowed(context.env) },
    fingerprint: mode !== "disabled" && publicKey
      ? { publicKey, region: context.env.FINGERPRINT_REGION ?? "us", endpoint: fingerprintEndpoint(context.env) }
      : null,
  });
});
