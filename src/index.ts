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
import { mfaEnrollRoutes } from "./mfa/enroll-routes";
import { opaqueRoutes } from "./auth/opaque-routes";
import { idxRoutes } from "./auth/idx-routes";
import { workpassRoutes } from "./auth/workpass-routes";
import { activationRoutes } from "./auth/activation-routes";
import { cleanupActivationTokens } from "./security/account-activation";
import { cleanupSessionMfaProofs } from "./mfa/second-factor";
import { oauth1Routes } from "./oauth1/routes";
import { cleanupOAuth1Temporaries } from "./oauth1/store";
import { deviceFlowRoutes } from "./oauth/device-routes";
import { cibaRoutes } from "./oauth/ciba-routes";
import { cleanupDeviceGrants } from "./oauth/device-flow";
import { cleanupCibaRequests } from "./oauth/ciba";
import { ssfReceiverRoutes } from "./ssf/routes";
import { ssfSenderRoutes, cleanupSsfDeliveries } from "./ssf/sender-routes";
import { cleanupSsfInbox } from "./ssf/inbox";
import { attemptPendingSSFDispatch } from "./ssf/dispatch";
import { accountRoutes } from "./accounts/routes";
import { applicationUserRoutes } from "./applications/user";
import { applicationIconRoutes } from "./applications/icon-routes";
import { cleanupAccountSessionContexts, cleanupAccountInvitations } from "./accounts/store";
import { dispatchPendingScimOperations } from "./scim/executor";
import { expireScimLeases } from "./scim/operations";
import { devMockRoutes } from "./dev/mock-mail";
import { accessRequestAdminRoutes, accessRequestUserRoutes } from "./access/request-routes";
import { cleanupAccessRequests } from "./access/requests";
import { backupAuditEvents } from "./audit/backup";
import { dispatchPendingEventNotifications } from "./policies/notifications";
import { applySettings } from "./settings/store";

import { meRoutes } from "./users/me-routes";
import { appSessionsRoutes } from "./users/app-sessions-routes";
import { locationPublicRoutes } from "./security/location-routes";
const app = new Hono<{ Bindings: Env }>();
import { auditContextForRequest, auditRequestContext } from "./audit/request-context";

app.use("*", (context, next) => auditRequestContext.run(auditContextForRequest(context.req.raw), next));

// individual handlers) is preserved; these are the common baseline that does
// not depend on the rendered content.
app.use("*", async (context, next) => {
  await next();
  context.header("X-Content-Type-Options", "nosniff");
  context.header("X-Frame-Options", "DENY");
  context.header("X-Robots-Tag", "noindex, nofollow");
  context.header("X-XSS-Protection", "0");
  context.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  context.header("Referrer-Policy", context.res.headers.get("Referrer-Policy") ?? "no-referrer");
});

// Admin-stored settings take the place of the matching deployment variables
// for the rest of the request (cached for 30 seconds per isolate).
app.use("*", async (context, next) => {
  if (context.req.path !== "/health") context.env = await applySettings(context.env);
  await next();
});

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

// Device-flow and CIBA routers claim their /api/auth/... protocol paths
// BEFORE authRoutes: the audit middleware at src/auth/routes.ts consumes every
// /api/auth/* request (it proxies unknown paths straight into better-auth's
// 404), so these must be matched first. Their inner handlers audit and
// authenticate themselves (src/oauth/*-routes.ts).
app.route("/", deviceFlowRoutes);
app.route("/", cibaRoutes);
app.route("/", authRoutes);
app.route("/", samlProtocolRoutes);
app.route("/", wsfedProtocolRoutes);
app.route("/", consentRoutes);
app.route("/", oidcSignInRoutes);
app.route("/", swaUserRoutes);
// The MFA sub-router declares /mfa/... paths; the public surface is /api/mfa/...,
// matching every caller, audit record, and document.
app.route("/api", mfaRoutes);
app.route("/api", mfaEnrollRoutes);
// OPAQUE sessions issue only after the login gate (banned accounts and the
// shared device-risk pipeline) passes; see src/auth/opaque-login.ts.
app.route("/", opaqueRoutes);
// Remediation-driven identify flow + public login config, and the WorkPass
// authorization-code round trip (BFF; tokens never reach the browser).
app.route("/", idxRoutes);
app.route("/", workpassRoutes);
app.route("/", activationRoutes);
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
app.route("/", applicationUserRoutes);
app.route("/", applicationIconRoutes);
app.route("/", devMockRoutes);
app.route("/api/admin", accessRequestAdminRoutes);
app.route("/", accessRequestUserRoutes);
app.route("/", meRoutes);
app.route("/", appSessionsRoutes);
app.route("/", locationPublicRoutes);

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
    await cleanupActivationTokens(env, new Date(controller.scheduledTime));
    await cleanupSamlRequestClaims(env, new Date(controller.scheduledTime));
    await cleanupSwaGrants(env, new Date(controller.scheduledTime));
    await cleanupSessionMfaProofs(env, new Date(controller.scheduledTime));
    await cleanupOAuth1Temporaries(env, controller.scheduledTime);
    // Extended grant stores: expired and decided rows are dead weight (the
    // flags do not gate cleanup — data dies with its expiry either way).
    await cleanupDeviceGrants(env, new Date(controller.scheduledTime));
    await cleanupCibaRequests(env, new Date(controller.scheduledTime));
    await cleanupSsfInbox(env.DB, controller.scheduledTime);
    await cleanupSsfDeliveries(env, controller.scheduledTime);
    await attemptPendingSSFDispatch(env, controller.scheduledTime);
    await cleanupAccountSessionContexts(env, new Date(controller.scheduledTime));
    await cleanupAccountInvitations(env, new Date(controller.scheduledTime));
    await dispatchPendingScimOperations(env);
    try {
      // Policy notification rules drain from their queue; a failed attempt
      // retries on the next run with an attempt cap.
      await dispatchPendingEventNotifications(env, controller.scheduledTime);
    } catch (error) {
      console.error("Notification dispatch failed", {
        name: error instanceof Error ? error.name : "UnknownError",
      });
    }
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
