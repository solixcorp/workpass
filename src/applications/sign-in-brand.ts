import type { Env } from "../env";
import { iconDisplayPath } from "./icons";

/** What the sign-in card shows for the application that asked for the sign-in. */
export interface SignInBrand {
  name: string;
  signInTitle: string;
  icon: string | null;
}

/** The registered application behind an OIDC client id, or the bare client's own name. */
export async function signInBrandForClient(env: Env, clientId: string): Promise<SignInBrand | null> {
  try {
    const app = await env.DB.prepare(
      "SELECT slug, name, icon_url AS iconUrl, icon_key AS iconKey FROM applications WHERE protocol = 'oidc' AND binding = ? LIMIT 1",
    ).bind(clientId).first<{ slug: string; name: string; iconUrl: string | null; iconKey: string | null }>();
    if (app) return { name: app.name, signInTitle: `${app.name}에 로그인`, icon: iconDisplayPath(app) };
    const client = await env.DB.prepare('SELECT name FROM "oauthClient" WHERE clientId = ? LIMIT 1')
      .bind(clientId).first<{ name: string | null }>();
    return client?.name ? { name: client.name, signInTitle: `${client.name}에 로그인`, icon: null } : null;
  } catch {
    return null;
  }
}
