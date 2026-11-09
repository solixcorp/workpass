/** Minimal outbound SCIM 2.0 transport. Credentials and target selection stay with the caller. */
export interface ScimTarget {
  baseUrl: string;
  bearerToken: string;
}

export interface ScimUserInput {
  externalId: string;
  userName: string;
  displayName?: string;
  email?: string;
  active: boolean;
}

export interface ScimUserReference {
  id: string;
  externalId?: string;
}

export type ScimResult<T> =
  | { ok: true; value: T }
  | { ok: false; kind: "invalid_configuration" | "remote_error" | "invalid_response" | "outcome_unknown"; status?: number };

const USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
const PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

function usersUrl(target: ScimTarget): URL | null {
  try {
    const base = new URL(target.baseUrl);
    if (base.protocol !== "https:" || base.username || base.password || base.search || base.hash || !target.bearerToken.trim()) {
      return null;
    }
    base.pathname = `${base.pathname.replace(/\/+$/, "")}/Users`;
    return base;
  } catch {
    return null;
  }
}

function parseUser(value: unknown): ScimUserReference | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const user = value as Record<string, unknown>;
  if (typeof user.id !== "string" || !user.id || user.id.length > 512) return null;
  if (user.externalId !== undefined && typeof user.externalId !== "string") return null;
  return { id: user.id, ...(typeof user.externalId === "string" ? { externalId: user.externalId } : {}) };
}

async function send(target: ScimTarget, url: URL, method: "POST" | "PATCH", body: unknown): Promise<ScimResult<Response>> {
  try {
    const response = await fetch(url, {
      method,
      redirect: "manual",
      headers: {
        Authorization: `Bearer ${target.bearerToken}`,
        Accept: "application/scim+json",
        "Content-Type": "application/scim+json",
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) {
      // A server error may follow a committed mutation; do not blindly retry it.
      return {
        ok: false,
        kind: response.status >= 500 ? "outcome_unknown" : "remote_error",
        status: response.status,
      };
    }
    return { ok: true, value: response };
  } catch {
    // A network failure can occur after the service has applied a mutation.
    return { ok: false, kind: "outcome_unknown" };
  }
}

/** Create requests are deliberately not retried: an uncertain response needs reconciliation. */
export async function createScimUser(target: ScimTarget, user: ScimUserInput): Promise<ScimResult<ScimUserReference>> {
  const url = usersUrl(target);
  if (!url || !user.externalId || !user.userName) return { ok: false, kind: "invalid_configuration" };
  const response = await send(target, url, "POST", {
    schemas: [USER_SCHEMA],
    externalId: user.externalId,
    userName: user.userName,
    ...(user.displayName !== undefined ? { displayName: user.displayName } : {}),
    ...(user.email !== undefined ? { emails: [{ value: user.email, primary: true }] } : {}),
    active: user.active,
  });
  if (!response.ok) return response;
  if (response.value.status !== 201) return { ok: false, kind: "invalid_response", status: response.value.status };
  try {
    const created = parseUser(await response.value.json());
    if (!created || (created.externalId !== undefined && created.externalId !== user.externalId)) {
      return { ok: false, kind: "invalid_response", status: response.value.status };
    }
    return { ok: true, value: created };
  } catch {
    return { ok: false, kind: "invalid_response", status: response.value.status };
  }
}

/** Replace supported user attributes or deactivate a previously mapped external user. */
export async function patchScimUser(
  target: ScimTarget,
  externalUserId: string,
  changes: { userName?: string; displayName?: string; email?: string; active?: boolean },
): Promise<ScimResult<void>> {
  const url = usersUrl(target);
  if (
    !url || !externalUserId || externalUserId.length > 512 ||
    externalUserId === "." || externalUserId === ".." || /[\/\\%\u0000-\u001f\u007f]/.test(externalUserId)
  ) {
    return { ok: false, kind: "invalid_configuration" };
  }
  url.pathname = `${url.pathname}/${encodeURIComponent(externalUserId)}`;
  const value = {
    ...(changes.userName !== undefined ? { userName: changes.userName } : {}),
    ...(changes.displayName !== undefined ? { displayName: changes.displayName } : {}),
    ...(changes.email !== undefined ? { emails: [{ value: changes.email, primary: true }] } : {}),
    ...(changes.active !== undefined ? { active: changes.active } : {}),
  };
  if (Object.keys(value).length === 0) return { ok: false, kind: "invalid_configuration" };
  const response = await send(target, url, "PATCH", {
    schemas: [PATCH_SCHEMA],
    Operations: [{ op: "replace", value }],
  });
  if (!response.ok) return response;
  if (response.value.status !== 200 && response.value.status !== 204) {
    return { ok: false, kind: "invalid_response", status: response.value.status };
  }
  return { ok: true, value: undefined };
}
