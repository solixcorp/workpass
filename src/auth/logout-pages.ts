import type { Env } from "../env";

const LOGOUT_PATHS = new Set(["/api/auth/oauth2/end-session", "/api/auth/oauth2/end-session/confirm"]);

/**
 * RP-initiated logout answers a browser with small English HTML pages. The
 * provider keeps the whole decision (signed confirmation cookie, session end,
 * registered redirect); only the page the person sees is swapped: the answer
 * is turned into a redirect to the matching screen of the web app, with the
 * provider's cookies kept.
 */
export async function logoutScreenRedirect(request: Request, env: Env, response: Response): Promise<Response> {
  if (!LOGOUT_PATHS.has(new URL(request.url).pathname)) return response;
  if (!(response.headers.get("content-type") ?? "").includes("text/html")) return response;
  const html = await response.clone().text();
  let screen: string;
  if (html.includes("data-oidc-logout-confirmation")) screen = "/logout";
  else if (html.includes('data-oidc-logout-state="logged-out"')) screen = html.includes("not registered") ? "/logged-out?redirect=invalid" : "/logged-out";
  else if (html.includes('data-oidc-logout-state="error"')) screen = "/logged-out?error=1";
  else return response;

  const headers = new Headers(response.headers);
  for (const name of ["content-type", "content-length", "content-security-policy"]) headers.delete(name);
  headers.set("Location", new URL(screen, env.AUTH_BASE_URL).toString());
  headers.set("Cache-Control", "no-store");
  return new Response(null, { status: 303, headers });
}
