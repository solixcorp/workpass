import { Hono } from "hono";
import type { Env } from "../env";
import { requireAdministrator } from "../security/authorization";
import { auditStandaloneOperation } from "../audit/store";
import { isSafeBackchannelUri } from "./backchannel-uri";

export const logoutApprovalRoutes = new Hono<{ Bindings: Env }>();
const path = "/oidc-logout-approvals";
logoutApprovalRoutes.use(path, async (c, next) => { await next(); c.header("Cache-Control", "no-store"); });

logoutApprovalRoutes.get(path, async (c) => {
  const admin = await requireAdministrator(c); if (admin instanceof Response) { admin.headers.set("Cache-Control", "no-store"); return admin; }
  const [approvals, clients] = await Promise.all([
    c.env.DB.prepare("SELECT uri FROM oidc_logout_uri_approvals ORDER BY uri").all<{ uri: string }>(),
    c.env.DB.prepare('SELECT "backchannelLogoutUri" AS uri, "clientId" AS clientId, name AS applicationName FROM "oauthClient" WHERE "backchannelLogoutUri" IS NOT NULL ORDER BY "clientId"').all<{ uri: string; clientId: string; applicationName: string }>(),
  ]);
  return c.json({ approvals: approvals.results.map(({ uri }) => ({ uri, inUseBy: clients.results.filter((client) => client.uri === uri).map(({ clientId, applicationName }) => ({ clientId, applicationName })) })) });
});

logoutApprovalRoutes.post(path, async (c) => {
  const admin = await requireAdministrator(c); if (admin instanceof Response) { admin.headers.set("Cache-Control", "no-store"); return admin; }
  const body = await c.req.json().catch(() => null) as { uri?: unknown } | null;
  if (typeof body?.uri !== "string" || !isSafeBackchannelUri(body.uri)) return c.json({ error: "유효한 로그아웃 주소를 입력해 주세요." }, 400);
  const uri = body.uri;
  return auditStandaloneOperation(c.env, "oidc.logout_approval.add", c.req.path, async () => {
    const result = await c.env.DB.prepare("INSERT OR IGNORE INTO oidc_logout_uri_approvals (uri) VALUES (?)").bind(uri).run();
    return { response: result.meta.changes ? Response.json({ approval: { uri, inUseBy: [] } }) : Response.json({ error: "이미 승인된 주소입니다." }, { status: 409 }), actorUserId: admin.userId };
  });
});

logoutApprovalRoutes.delete(path, async (c) => {
  const admin = await requireAdministrator(c); if (admin instanceof Response) { admin.headers.set("Cache-Control", "no-store"); return admin; }
  const uri = c.req.query("uri");
  if (!uri) return c.json({ error: "주소를 입력해 주세요." }, 400);
  return auditStandaloneOperation(c.env, "oidc.logout_approval.remove", c.req.path, async () => {
    try {
      const result = await c.env.DB.prepare("DELETE FROM oidc_logout_uri_approvals WHERE uri = ?").bind(uri).run();
      return { response: result.meta.changes ? Response.json({ deleted: true }) : Response.json({ error: "승인된 주소를 찾을 수 없습니다." }, { status: 404 }), actorUserId: admin.userId };
    } catch (error) {
      if (String(error).includes("logout URI approval is in use")) return { response: Response.json({ error: "사용 중인 주소는 삭제할 수 없습니다." }, { status: 409 }), actorUserId: admin.userId };
      throw error;
    }
  });
});
