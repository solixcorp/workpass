import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";
import type { Env } from "../env";
import type { AuthInstance } from "../auth/config";
import { evaluateAppAccess, loadAppAccessPolicy } from "./policies";
import { sessionSatisfiesRequireMfa } from "../mfa/second-factor";

/** Check every external authorization continuation, not just the consent UI. */
export async function enforceOidcPolicy(request: Request, env: Env, auth: AuthInstance): Promise<Response | null> {
  const path = new URL(request.url).pathname;
  if (!["/api/auth/oauth2/authorize", "/api/auth/oauth2/consent", "/api/auth/oauth2/continue"].includes(path)) return null;
  try {
    const session = await auth.api.getSession({ headers: request.headers });
    if (!session) return null; // The provider requires authentication itself.
    let params: URLSearchParams;
    if (request.method === "GET" && path === "/api/auth/oauth2/authorize") {
      params = new URL(request.url).searchParams;
    } else if (request.method === "POST") {
      const type = request.headers.get("content-type") ?? "";
      let query: unknown;
      if (type.includes("application/json")) {
        const body = await request.clone().json() as Record<string, unknown>;
        query = body?.oauth_query;
      } else if (type.includes("application/x-www-form-urlencoded")) {
        const body = new URLSearchParams(await request.clone().text());
        if (body.getAll("oauth_query").length !== 1) return Response.json({ error: "invalid_request" }, { status: 400 });
        query = body.get("oauth_query");
      }
      if (typeof query !== "string" || query.length > 16384 || !(await verifyOAuthQueryParams(query, env.AUTH_SECRET))) {
        return Response.json({ error: "invalid_request" }, { status: 400 });
      }
      params = new URLSearchParams(query);
    } else {
      return null;
    }
    if (params.getAll("client_id").length !== 1 || !params.get("client_id")) return Response.json({ error: "invalid_request" }, { status: 400 });
    const policy = await loadAppAccessPolicy(env, `oidc:${params.get("client_id")}`);
    if (policy) {
      if (policy.requireMfa && !(await sessionSatisfiesRequireMfa(env, session))) {
        return Response.json({ error: "access_denied" }, { status: 403 });
      }
      if (!(await evaluateAppAccess(env, policy, session.user.id)).allowed) {
        return Response.json({ error: "access_denied" }, { status: 403 });
      }
    }
    return null;
  } catch {
    return Response.json({ error: "Authorization policy unavailable" }, { status: 503 });
  }
}
