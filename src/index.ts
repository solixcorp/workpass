import { Hono } from "hono";
import type { Env } from "./env";
import { adminRoutes } from "./admin/routes";
import { bootstrapRoutes } from "./admin/bootstrap";
import { migrationRoutes } from "./admin/migrations";
import { inboundScimRoutes } from "./scim/server";
import { authRoutes } from "./auth/routes";
import { webfingerRoutes } from "./oidc/webfinger";
import { trustedDeviceRoutes } from "./security/trusted-device-routes";
import { lockdownRoutes } from "./security/lockdown-routes";
import { stepUpRoutes } from "./security/step-up-routes";
import { cleanupStepUpChallenges } from "./security/step-up";
import { recoveryRoutes } from "./security/account-recovery-routes";
import { cleanupRecoveryTokens } from "./security/account-recovery";
import { cleanupFingerprintData } from "./security/fingerprint-retention";
import { cleanupSessionNetworkBindings } from "./security/session-geo-binding";
import { cleanupSamlRequestClaims } from "./saml/request-claims";
import { cleanupSwaGrants } from "./swa/applications";
import { samlProtocolRoutes } from "./saml/protocol-routes";
import { wsfedProtocolRoutes } from "./wsfed/routes";
import { consentRoutes } from "./pages/consent";
import { oidcSignInRoutes } from "./pages/sign-in";
import { swaUserRoutes } from "./swa/routes";
import { mfaRoutes } from "./mfa/duo-routes";
import { opaqueRoutes } from "./auth/opaque-routes";
import { cleanupSessionMfaProofs } from "./mfa/second-factor";
import { oauth1Routes } from "./oauth1/routes";
import { cleanupOAuth1Temporaries } from "./oauth1/store";
import { ssfReceiverRoutes } from "./ssf/routes";
import { ssfSenderRoutes, cleanupSsfDeliveries } from "./ssf/sender-routes";
import { cleanupSsfInbox } from "./ssf/inbox";
import { attemptPendingSSFDispatch } from "./ssf/dispatch";
import { accountRoutes } from "./accounts/routes";
import { cleanupAccountSessionContexts } from "./accounts/store";
import { accessRequestAdminRoutes, accessRequestUserRoutes } from "./access/request-routes";
import { cleanupAccessRequests } from "./access/requests";
import { backupAuditEvents } from "./audit/backup";

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
// OPAQUE sessions issue only after the login gate (banned accounts and the
// shared device-risk pipeline) passes; see src/auth/opaque-login.ts.
app.route("/", opaqueRoutes);
app.route("/.well-known", webfingerRoutes);
app.route("/api/admin", adminRoutes);
app.route("/api/admin", bootstrapRoutes);
app.route("/api/security", trustedDeviceRoutes);
// Account lockdown: self-service and administrator emergency actions at
// /api/security/account-lockdown; see src/security/account-lockdown.ts.
app.route("/api/security", lockdownRoutes);
// Step-up challenge status for the acting session (second factor required
// after a risky decision); see src/security/step-up.ts.
app.route("/api/security", stepUpRoutes);
// Admin-issued one-time recovery links and redemption for locked accounts;
// see src/security/account-recovery.ts.
app.route("/api/security", recoveryRoutes);
app.route("/_internal", migrationRoutes);
app.route("/", inboundScimRoutes);
// OAuth 1.0a and SSF routers fail closed on every request; they are reachable
// only when their feature flags are set.
app.route("/", oauth1Routes);
app.route("/", ssfReceiverRoutes);
app.route("/", ssfSenderRoutes);
app.route("/", accountRoutes);
app.route("/api/admin", accessRequestAdminRoutes);
app.route("/", accessRequestUserRoutes);

async function scheduled(
  controller: ScheduledController,
  env: Env,
  _context: ExecutionContext,
): Promise<void> {
  try {
    // Cleanup runs even while the related features are disabled.
    await cleanupFingerprintData(env, new Date(controller.scheduledTime));
    await cleanupSessionNetworkBindings(env, new Date(controller.scheduledTime));
    await cleanupStepUpChallenges(env, new Date(controller.scheduledTime));
    await cleanupRecoveryTokens(env, new Date(controller.scheduledTime));
    await cleanupSamlRequestClaims(env, new Date(controller.scheduledTime));
    await cleanupSwaGrants(env, new Date(controller.scheduledTime));
    await cleanupSessionMfaProofs(env, new Date(controller.scheduledTime));
    await cleanupOAuth1Temporaries(env, controller.scheduledTime);
    await cleanupSsfInbox(env.DB, controller.scheduledTime);
    await cleanupSsfDeliveries(env, controller.scheduledTime);
    await attemptPendingSSFDispatch(env, controller.scheduledTime);
    await cleanupAccountSessionContexts(env, new Date(controller.scheduledTime));
    await cleanupAccessRequests(env, controller.scheduledTime);
    try {
      // Independent audit backup: watermark-guarded R2 export; fails safe
      // without the AUDIT_BACKUP binding and never blocks other cleanups.
      await backupAuditEvents(env, controller.scheduledTime);
    } catch (error) {
      console.error("Audit backup export failed", {
        name: error instanceof Error ? error.name : "UnknownError",
      });
    }
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
