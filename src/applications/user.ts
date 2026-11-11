/**
 * User-facing launch surface: the applications visible to the acting user.
 * Reads are session-gated and not audited, matching the other user reads.
 */

import { Hono } from "hono";
import { createAuth, oidcIssuer } from "../auth/config";
import type { Env } from "../env";
import { listVisibleApplications } from "./store";
import { iconDisplayPath } from "./icons";

export const applicationUserRoutes = new Hono<{ Bindings: Env }>();

applicationUserRoutes.use("/api/applications*", async (context, next) => {
  context.header("Cache-Control", "no-store");
  await next();
});

applicationUserRoutes.get("/api/applications", async (context) => {
  const session = await createAuth(context.env).api.getSession({ headers: context.req.raw.headers });
  if (!session) return context.json({ error: "Unauthorized" }, 401);
  const applications = await listVisibleApplications(context.env, session.user.id);
  return context.json({
    applications: applications.map((application) => {
      const launchInitiatesLogin = application.protocol === "oidc" && application.slug !== "workpass-dashboard" && Boolean(application.launchUrl);
      let launchUrl = application.launchUrl;
      if (launchInitiatesLogin && launchUrl) {
        const url = new URL(launchUrl);
        url.searchParams.set("iss", oidcIssuer(context.env));
        launchUrl = url.toString();
      }
      return {
        slug: application.slug,
        name: application.name,
        description: application.description,
        protocol: application.protocol,
        launchUrl,
        launchInitiatesLogin,
        categoryGroup: application.categoryGroup,
        icon: iconDisplayPath(application),
      };
    }),
  });
});
