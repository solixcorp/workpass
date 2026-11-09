import { Hono } from "hono";
import type { Env } from "./env";
import { adminRoutes } from "./admin/routes";
import { bootstrapRoutes } from "./admin/bootstrap";
import { migrationRoutes } from "./admin/migrations";
import { authRoutes } from "./auth/routes";
import { webfingerRoutes } from "./oidc/webfinger";
import { trustedDeviceRoutes } from "./security/trusted-device-routes";
import { cleanupFingerprintData } from "./security/fingerprint-retention";
import { cleanupSamlRequestClaims } from "./saml/request-claims";
import { samlProtocolRoutes } from "./saml/protocol-routes";
import { wsfedProtocolRoutes } from "./wsfed/routes";

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
app.route("/.well-known", webfingerRoutes);
app.route("/api/admin", adminRoutes);
app.route("/api/admin", bootstrapRoutes);
app.route("/api/security", trustedDeviceRoutes);
app.route("/_internal", migrationRoutes);

async function scheduled(
  controller: ScheduledController,
  env: Env,
  _context: ExecutionContext,
): Promise<void> {
  try {
    // Cleanup runs even while the related features are disabled.
    await cleanupFingerprintData(env, new Date(controller.scheduledTime));
    await cleanupSamlRequestClaims(env, new Date(controller.scheduledTime));
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
