import { Hono } from "hono";
import type { Env } from "../env";
import { oidcIssuer } from "../auth/config";

const ISSUER_RELATION = "http://openid.net/specs/connect/1.0/issuer";

export const webfingerRoutes = new Hono<{ Bindings: Env }>();

webfingerRoutes.options("/webfinger", (context) =>
  new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Accept, Content-Type",
      "Access-Control-Max-Age": "600",
    },
  }),
);

webfingerRoutes.get("/webfinger", (context) => {
  const configuredDomain = normalizeDomain(context.env.OIDC_EMAIL_DOMAIN);
  if (!configuredDomain) return context.notFound();

  const requestUrl = new URL(context.req.url);
  if (normalizeDomain(requestUrl.hostname) !== configuredDomain) {
    return context.notFound();
  }

  const resource = requestUrl.searchParams.get("resource");
  if (!resource?.startsWith("acct:")) {
    return context.json({ error: "Unsupported WebFinger resource" }, 400);
  }

  const address = resource.slice("acct:".length);
  const separator = address.lastIndexOf("@");
  if (separator <= 0 || separator === address.length - 1) {
    return context.json({ error: "Invalid account resource" }, 400);
  }

  const accountDomain = normalizeDomain(address.slice(separator + 1));
  if (accountDomain !== configuredDomain) return context.notFound();

  const requestedRelation = requestUrl.searchParams.get("rel");
  const links = requestedRelation && requestedRelation !== ISSUER_RELATION
    ? []
    : [{ rel: ISSUER_RELATION, href: oidcIssuer(context.env) }];

  return new Response(
    JSON.stringify({
      subject: `acct:${address.slice(0, separator)}@${configuredDomain}`,
      links,
    }),
    {
      status: 200,
      headers: {
        "Content-Type": "application/jrd+json; charset=utf-8",
        "Cache-Control": "public, max-age=300",
        "Access-Control-Allow-Origin": "*",
        Vary: "Origin",
      },
    },
  );
});

function normalizeDomain(value: string | null | undefined): string | null {
  if (!value) return null;
  const domain = value.trim().toLowerCase().replace(/\.$/, "");
  if (
    domain.length > 253 ||
    !domain.includes(".") ||
    domain.split(".").some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
  ) {
    return null;
  }
  return domain;
}
