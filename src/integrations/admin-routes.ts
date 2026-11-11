import { Hono } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import { ensureSsfDispatchTables } from "../ssf/dispatch";
import { ensureSsfInboxTable } from "../ssf/inbox";
import { parseSsfStreams } from "../ssf/streams";

export const integrationsAdminRoutes = new Hono<{ Bindings: Env }>();

integrationsAdminRoutes.use("*", async (context, next) => {
  if (["/api/admin/integrations/status", "/api/admin/scim-operations", "/api/admin/ssf/streams", "/api/admin/ssf/events", "/api/admin/claim-release-policies"].includes(context.req.path) && context.req.method === "GET") {
    context.header("Cache-Control", "no-store");
  }
  await next();
});

function host(value: string | undefined): string | null {
  try { return value ? new URL(value).hostname || null : null; } catch { return null; }
}

function paging(pageValue: string | undefined, limitValue: string | undefined) {
  const parse = (value: string | undefined, fallback: number) => value === undefined ? fallback : /^\d+$/.test(value) ? Number(value) : NaN;
  const page = parse(pageValue, 1);
  const limit = parse(limitValue, 20);
  if (!Number.isSafeInteger(page) || page < 1 || !Number.isSafeInteger(limit) || limit < 1 || limit > 100 || !Number.isSafeInteger((page - 1) * limit)) return null;
  return { page, limit, offset: (page - 1) * limit };
}

function receiverConfig(env: Env) {
  try { return { valid: true, streams: parseSsfStreams(env.SSF_STREAMS) }; }
  catch { return { valid: false, streams: [] }; }
}

function scimConfigured(env: Env): boolean {
  try {
    const url = new URL(env.SCIM_BASE_URL ?? "");
    return Boolean(env.SCIM_TARGET_ID && /^[A-Za-z0-9_-]{1,128}$/.test(env.SCIM_TARGET_ID) && env.SCIM_BEARER_TOKEN?.trim() &&
      (url.protocol === "https:" || (env.SCIM_DEV_LOOPBACK_TARGET === "true" && url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname))) &&
      !url.username && !url.password && !url.search && !url.hash);
  } catch { return false; }
}

async function ssfTables(env: Env) {
  await Promise.all([ensureSsfDispatchTables(env.DB), ensureSsfInboxTable(env.DB)]);
}

integrationsAdminRoutes.get("/integrations/status", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) { admin.headers.set("Cache-Control", "no-store"); return admin; }
  const env = context.env;
  await ssfTables(env);
  const receiver = receiverConfig(env);
  const [counts, activity, senderCount, senderActivity, receiverActivity, inboundActivity, claimActivity, appTargets] = await Promise.all([
    env.DB.prepare("SELECT status, COUNT(*) AS count FROM scim_operations GROUP BY status").all<{ status: string; count: number }>(),
    env.DB.prepare("SELECT MAX(updated_at) AS time FROM scim_operations").first<{ time: string | null }>(),
    env.DB.prepare("SELECT COUNT(*) AS count FROM ssf_recipients").first<{ count: number }>(),
    env.DB.prepare("SELECT MAX(updated_at) AS time FROM ssf_deliveries").first<{ time: number | null }>(),
    env.DB.prepare("SELECT MAX(received_at) AS time FROM ssf_inbox").first<{ time: number | null }>(),
    env.DB.prepare("SELECT MAX(occurred_at) AS time FROM audit_events WHERE event_type LIKE 'scim.inbound.%'").first<{ time: string | null }>(),
    env.DB.prepare("SELECT MAX(updated_at) AS time FROM claim_release_policies").first<{ time: string | null }>(),
    env.DB.prepare("SELECT COUNT(*) AS configured, COALESCE(SUM(enabled), 0) AS enabled FROM app_provisioning_targets").first<{ configured: number; enabled: number }>(),
  ]);
  const operationCounts: Record<string, number> = { pending: 0, in_progress: 0, succeeded: 0, failed: 0, outcome_unknown: 0 };
  for (const row of counts.results) operationCounts[row.status] = row.count;
  return context.json({
    scimOutbound: { enabled: env.ENABLE_SCIM_PROVISIONING === "true", configured: scimConfigured(env), baseUrlHost: host(env.SCIM_BASE_URL), operationCounts, lastActivityAt: activity?.time ?? null },
    scimApplicationTargets: { configured: appTargets?.configured ?? 0, enabled: appTargets?.enabled ?? 0 },
    scimInbound: { enabled: env.ENABLE_INBOUND_SCIM === "true", configured: (env.INBOUND_SCIM_BEARER_TOKEN?.length ?? 0) >= 32, lastActivityAt: inboundActivity?.time ?? null },
    ssfSender: { enabled: env.ENABLE_SSF_SENDER === "true", configured: Boolean(env.SSF_MANAGEMENT_TOKEN && env.AEAD_SEALING_KEY), streamCount: senderCount?.count ?? 0, lastActivityAt: senderActivity?.time ? new Date(senderActivity.time).toISOString() : null },
    ssfReceiver: { enabled: env.ENABLE_SSF_RECEIVER === "true", configured: receiver.valid && receiver.streams.length > 0, streamCount: receiver.streams.length, lastActivityAt: receiverActivity?.time ? new Date(receiverActivity.time * 1000).toISOString() : null },
    claims: { accountClaimsEnabled: env.ENABLE_ACCOUNT_CLAIMS === "true", attributeClaimsEnabled: env.ENABLE_ATTRIBUTE_CLAIMS === "true", scimAttributeReleaseEnabled: env.ENABLE_SCIM_ATTRIBUTE_RELEASE === "true", lastPolicyUpdateAt: claimActivity?.time ?? null },
  });
});

integrationsAdminRoutes.get("/scim-operations", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) { admin.headers.set("Cache-Control", "no-store"); return admin; }
  const pagination = paging(context.req.query("page"), context.req.query("limit"));
  const status = context.req.query("status");
  const userId = context.req.query("userId");
  const applicationSlug = context.req.query("applicationSlug");
  if (!pagination || (status !== undefined && !["pending", "in_progress", "succeeded", "failed", "outcome_unknown"].includes(status)) || (userId !== undefined && (!userId || userId.length > 256)) || (applicationSlug !== undefined && !/^[a-z0-9][a-z0-9-]{0,63}$/.test(applicationSlug))) return context.json({ error: "검색 조건을 확인해 주세요." }, 400);
  const clauses: string[] = [];
  const values: string[] = [];
  if (status) { clauses.push("o.status = ?"); values.push(status); }
  if (userId) { clauses.push("o.user_id = ?"); values.push(userId); }
  if (applicationSlug) { clauses.push("o.target_id = ?"); values.push(`app:${applicationSlug}`); }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const [total, rows] = await Promise.all([
    context.env.DB.prepare(`SELECT COUNT(*) AS count FROM scim_operations o ${where}`).bind(...values).first<{ count: number }>(),
    context.env.DB.prepare(`SELECT o.id, o.target_id, o.user_id, o.operation, o.status, o.remote_status, o.created_at, o.updated_at, u.name AS user_name, u.email AS user_email, a.name AS applicationName FROM scim_operations o LEFT JOIN "user" u ON u.id = o.user_id LEFT JOIN applications a ON o.target_id = 'app:' || a.slug ${where} ORDER BY o.created_at DESC, o.id DESC LIMIT ? OFFSET ?`).bind(...values, pagination.limit, pagination.offset).all(),
  ]);
  return context.json({ operations: rows.results, total: total?.count ?? 0, page: pagination.page, limit: pagination.limit });
});

integrationsAdminRoutes.get("/ssf/streams", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) { admin.headers.set("Cache-Control", "no-store"); return admin; }
  const env = context.env;
  await ssfTables(env);
  const [senders, received] = await Promise.all([
    env.DB.prepare(`SELECT r.id, r.endpoint, r.disabled, r.created_at, MAX(d.updated_at) AS last_event_at, SUM(CASE WHEN d.state = 'delivered' THEN 1 ELSE 0 END) AS delivered, SUM(CASE WHEN d.state IN ('failed', 'abandoned') THEN 1 ELSE 0 END) AS failed FROM ssf_recipients r LEFT JOIN ssf_deliveries d ON d.recipient_id = r.id GROUP BY r.id ORDER BY r.id`).all<{ id: string; endpoint: string; disabled: number; created_at: number; last_event_at: number | null; delivered: number; failed: number }>(),
    env.DB.prepare("SELECT stream_id, MAX(received_at) AS last_event_at FROM ssf_inbox GROUP BY stream_id").all<{ stream_id: string; last_event_at: number }>(),
  ]);
  const receiveTimes = new Map(received.results.map((row) => [row.stream_id, row.last_event_at]));
  const streams = [
    ...senders.results.map((row) => ({ id: row.id, direction: "sender", deliveryMethod: "push", endpointHost: host(row.endpoint), status: row.disabled ? "disabled" : "enabled", createdAt: new Date(row.created_at).toISOString(), lastEventAt: row.last_event_at ? new Date(row.last_event_at).toISOString() : null, eventsDelivered: row.delivered, eventsFailed: row.failed })),
    ...receiverConfig(env).streams.map((stream) => ({ id: stream.id, direction: "receiver", deliveryMethod: "push", endpointHost: host(env.AUTH_BASE_URL), status: env.ENABLE_SSF_RECEIVER === "true" ? "enabled" : "disabled", createdAt: null, lastEventAt: receiveTimes.has(stream.id) ? new Date(receiveTimes.get(stream.id)! * 1000).toISOString() : null, eventsDelivered: null, eventsFailed: null })),
  ];
  return context.json({ streams });
});

integrationsAdminRoutes.get("/ssf/events", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) { admin.headers.set("Cache-Control", "no-store"); return admin; }
  const pagination = paging(context.req.query("page"), context.req.query("limit"));
  if (!pagination) return context.json({ error: "페이지를 확인해 주세요." }, 400);
  await ssfTables(context.env);
  const union = `SELECT id, recipient_id AS streamId, 'sender' AS direction, state, attempts, last_status AS httpStatus, created_at AS time FROM ssf_deliveries UNION ALL SELECT jti AS id, stream_id AS streamId, 'receiver' AS direction, state, NULL AS attempts, NULL AS httpStatus, received_at * 1000 AS time FROM ssf_inbox`;
  const [total, rows] = await Promise.all([
    context.env.DB.prepare(`SELECT COUNT(*) AS count FROM (${union})`).first<{ count: number }>(),
    context.env.DB.prepare(`SELECT * FROM (${union}) ORDER BY time DESC, direction ASC, streamId ASC, id ASC LIMIT ? OFFSET ?`).bind(pagination.limit, pagination.offset).all<{ id: string; streamId: string; direction: string; state: string; attempts: number | null; httpStatus: number | null; time: number }>(),
  ]);
  return context.json({ events: rows.results.map(({ time, ...row }) => ({ ...row, occurredAt: new Date(time).toISOString() })), total: total?.count ?? 0, page: pagination.page, limit: pagination.limit });
});

integrationsAdminRoutes.get("/claim-release-policies", async (context) => {
  const admin = await requireAdministrator(context);
  if (admin instanceof Response) { admin.headers.set("Cache-Control", "no-store"); return admin; }
  const [apps, policyRows] = await Promise.all([
    context.env.DB.prepare("SELECT slug, name, protocol, binding FROM applications ORDER BY name, slug").all<{ slug: string; name: string; protocol: string; binding: string | null }>(),
    context.env.DB.prepare("SELECT subject, allow_account_claims, allow_user_attributes, attribute_allowlist, allow_account_attributes, allow_group_attributes FROM claim_release_policies ORDER BY subject").all<{ subject: string; allow_account_claims: number; allow_user_attributes: number; attribute_allowlist: string | null; allow_account_attributes: number | null; allow_group_attributes: number | null }>(),
  ]);
  const policies = policyRows.results.map((row) => {
    let attributeAllowlist: string[] | null = null;
    try {
      const value: unknown = row.attribute_allowlist ? JSON.parse(row.attribute_allowlist) : null;
      if (Array.isArray(value) && value.length <= 32 && value.every((key) => typeof key === "string" && /^[A-Za-z0-9_.:-]{1,64}$/.test(key))) attributeAllowlist = [...new Set(value as string[])];
    } catch { /* Match the existing policy reader's handling of corrupt rows. */ }
    return { subject: row.subject, allowAccountClaims: row.allow_account_claims === 1, allowUserAttributes: row.allow_user_attributes === 1, attributeAllowlist, allowAccountAttributes: row.allow_account_attributes == null || row.allow_account_attributes === 1, allowGroupAttributes: row.allow_group_attributes == null || row.allow_group_attributes === 1 };
  });
  const subjectFor = (app: typeof apps.results[number]) => app.binding && ["oidc", "saml", "wsfed"].includes(app.protocol) && /^[A-Za-z0-9_.:\/-]{1,2000}$/.test(app.binding) ? `${app.protocol}:${app.binding}` : null;
  const resolve = (subject: string) => apps.results.find((app) => subjectFor(app) === subject || subject === `app:${app.slug}` || subject === `bookmark:${app.slug}`);
  const subjects = new Set(policyRows.results.map((policy) => policy.subject));
  const defaults = { allowAccountClaims: context.env.ENABLE_ACCOUNT_CLAIMS === "true", allowUserAttributes: context.env.ENABLE_ATTRIBUTE_CLAIMS === "true", allowAccountAttributes: context.env.ENABLE_ACCOUNT_CLAIMS === "true", allowGroupAttributes: context.env.ENABLE_ATTRIBUTE_CLAIMS === "true", attributeAllowlist: null };
  return context.json({
    policies: policies.map((policy) => { const app = resolve(policy.subject); return { ...policy, applicationName: app?.name ?? null, applicationSlug: app?.slug ?? null }; }),
    applicationsWithoutPolicy: apps.results.flatMap((app) => { const subject = subjectFor(app); return subject && !subjects.has(subject) ? [{ subject, applicationName: app.name, applicationSlug: app.slug, defaults }] : []; }),
  });
});
