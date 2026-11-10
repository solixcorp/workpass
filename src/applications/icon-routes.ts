/**
 * Public application icon serving: `GET /application/{slug}/icon`. Icons are
 * not sensitive, so the route is public; a missing bucket binding or object
 * responds 404/503 as documented. SVG bodies ship with a restrictive CSP so
 * the served image can never obtain a script execution context.
 */

import { Hono } from "hono";
import type { Env } from "../env";
import { getApplicationIcon } from "./icons";

export const applicationIconRoutes = new Hono<{ Bindings: Env }>();

applicationIconRoutes.get("/application/:slug/icon", async (context) => {
  const slug = context.req.param("slug");
  if (!slug || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(slug)) return context.json({ error: "Not found" }, 404);
  const icon = await getApplicationIcon(context.env, slug);
  if (!icon) return context.json({ error: "Not found" }, 404);
  const headers: Record<string, string> = {
    "Content-Type": icon.contentType,
    "Cache-Control": "public, max-age=300",
    "X-Content-Type-Options": "nosniff",
  };
  if (icon.contentType === "image/svg+xml") {
    headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; sandbox img-only";
  }
  // A native Response accepts the R2 stream/n-body directly, keeping the
  // streaming path intact.
  return new Response(icon.body, { status: 200, headers });
});
