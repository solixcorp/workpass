import { Hono } from "hono";
import type { Env } from "./env";
import { adminRoutes } from "./admin/routes";
import { bootstrapRoutes } from "./admin/bootstrap";
import { migrationRoutes } from "./admin/migrations";
import { inboundScimRoutes } from "./scim/server";
import { authRoutes } from "./auth/routes";
import { webfingerRoutes } from "./oidc/webfinger";
import { trustedDeviceRoutes } from "./security/trusted-device-routes";
import { cleanupFingerprintData } from "./security/fingerprint-retention";
import { cleanupSamlRequestClaims } from "./saml/request-claims";
import { cleanupSwaGrants } from "./swa/applications";
import { samlProtocolRoutes } from "./saml/protocol-routes";
import { wsfedProtocolRoutes } from "./wsfed/routes";
import { consentRoutes } from "./pages/consent";
import { oidcSignInRoutes } from "./pages/sign-in";
import { swaUserRoutes } from "./swa/routes";
import { mfaRoutes } from "./mfa/duo-routes";
import { opaqueRoutes } from "./auth/opaque-routes";

const app = new Hono<{ Bindings: Env }>();

app.onError((error, context) => {
  console.error("Unhandled Worker request error", {
    name: error.name,
    path: new URL(context.req.url).pathname,
  });
  return context.json({ error: "Internal server error" }, 500);
});

app.get("/health", (context) =>
  context.json({ status: "ok", runtime: "cloudflare-workers" }),
);

app.get("/", (context) =>
  context.json({
    service: "Internal Auth",
    status: "ready",
    documentation:
      "https://github.com/solixcorp/internal-auth/blob/main/docs/api/backend-api-v1.md",
    openidConfiguration: "/.well-known/openid-configuration",
  }),
);

app.route("/", authRoutes);
app.route("/", samlProtocolRoutes);
app.route("/", wsfedProtocolRoutes);
app.route("/", consentRoutes);
app.route("/", oidcSignInRoutes);
app.route("/", swaUserRoutes);
// The MFA sub-router declares /mfa/... paths; the public surface is /api/mfa/...,
// matching every caller, audit record, and document.
app.route("/api", mfaRoutes);
app.route("/", opaqueRoutes);
app.route("/.well-known", webfingerRoutes);
app.route("/api/admin", adminRoutes);
app.route("/api/admin", bootstrapRoutes);
app.route("/api/security", trustedDeviceRoutes);
app.route("/_internal", migrationRoutes);
app.route("/", inboundScimRoutes);

async function scheduled(
  controller: ScheduledController,
  env: Env,
  _context: ExecutionContext,
): Promise<void> {
  try {
    // Cleanup runs even while the related features are disabled.
    await cleanupFingerprintData(env, new Date(controller.scheduledTime));
    await cleanupSamlRequestClaims(env, new Date(controller.scheduledTime));
    await cleanupSwaGrants(env, new Date(controller.scheduledTime));
  } catch (error) {
    console.error("Scheduled security cleanup failed", {
      cron: controller.cron,
      name: error instanceof Error ? error.name : "UnknownError",
    });
    throw error;
  }
}

export default {
  fetch: app.fetch,
  scheduled,
} satisfies ExportedHandler<Env>;
