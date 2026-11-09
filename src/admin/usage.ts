/**
 * The usage snapshot for the plan's budget review: row counts per bounded
 * surface, read-only and administrator-gated. Numbers only; no content.
 */
import { requireAdministrator } from "../security/authorization";
import type { Env } from "../env";
import { Hono } from "hono";

export const usageRoutes = new Hono<{ Bindings: Env }>();

const COUNTED = [
  "user",
  "session",
  "audit_events",
  "oauthClient",
  "oauthAccessToken",
  "oauthRefreshToken",
  "oauthConsent",
  "swa_applications",
  "swa_grants",
  "saml_service_providers",
  "wsfed_relying_parties",
  "directory_groups",
  "directory_group_members",
  "scim_operations",
  "scim_user_mappings",
  "trusted_devices",
  "fingerprint_event_claims",
] as const;

usageRoutes.get("/usage-snapshot", async (context) => {
  const actor = await requireAdministrator(context);
  if (actor instanceof Response) return actor;
  const counts: Record<string, number> = {};
  for (const table of COUNTED) {
    try {
      const row = await context.env.DB.prepare(`SELECT COUNT(*) AS count FROM "${table}"`).first<{ count: number }>();
      counts[table] = row?.count ?? 0;
    } catch {
      counts[table] = -1; // table not migrated yet on this deployment
    }
  }
  context.header("Cache-Control", "no-store");
  return context.json({
    capturedAt: new Date().toISOString(),
    counts,
  });
});
