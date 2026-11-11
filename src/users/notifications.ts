/** In-app notifications. Never throws: a notification must not fail the action it reports. */

import type { Env } from "../env";

export interface Notice {
  kind: string;
  title: string;
  body: string;
  link?: string | null;
}

export async function notifyUsers(env: Env, userIds: string[], notice: Notice): Promise<void> {
  const unique = [...new Set(userIds)].slice(0, 1000);
  if (unique.length === 0) return;
  try {
    const now = new Date().toISOString();
    const statements = unique.map((userId) =>
      env.DB.prepare(
        "INSERT INTO user_notifications (id, user_id, kind, title, body, link, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      ).bind(crypto.randomUUID(), userId, notice.kind.slice(0, 64), notice.title.slice(0, 200), notice.body.slice(0, 1000), notice.link ?? null, now),
    );
    // D1 allows 100 statements per batch.
    for (let i = 0; i < statements.length; i += 90) await env.DB.batch(statements.slice(i, i + 90));
  } catch {
    // The table does not exist before the first migration.
  }
}

export const notifyUser = (env: Env, userId: string, notice: Notice) => notifyUsers(env, [userId], notice);

/** Security notices are deduplicated atomically, without affecting the action. */
export async function notifySecurity(env: Env, userId: string, notice: Notice): Promise<void> {
  try {
    const now = new Date();
    await env.DB.prepare(
      `INSERT INTO user_notifications (id, user_id, kind, title, body, link, created_at)
       SELECT ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (
         SELECT 1 FROM user_notifications WHERE user_id = ? AND kind = ? AND title = ? AND created_at >= ?
       )`,
    ).bind(crypto.randomUUID(), userId, notice.kind, notice.title, notice.body, notice.link ?? null, now.toISOString(),
      userId, notice.kind, notice.title, new Date(now.getTime() - 60_000).toISOString()).run();
  } catch {
    // Notifications are best effort.
  }
}

export async function adminIds(env: Env): Promise<string[]> {
  try {
    const rows = await env.DB.prepare(`SELECT id, role FROM "user" WHERE role IS NOT NULL AND (banned IS NULL OR banned = 0)`)
      .all<{ id: string; role: string }>();
    return rows.results.filter((row) => row.role.split(",").includes("admin")).map((row) => row.id);
  } catch {
    return [];
  }
}

export async function notifyAdmins(env: Env, notice: Notice): Promise<void> {
  await notifyUsers(env, await adminIds(env), notice);
}

/** The people an app is for: group members when it is assigned to groups, otherwise everyone. */
export async function appAudience(env: Env, slug: string): Promise<string[]> {
  try {
    const groups = await env.DB.prepare("SELECT group_id FROM app_policy_groups WHERE subject = ?")
      .bind(`app:${slug}`).all<{ group_id: string }>();
    if (groups.results.length > 0) {
      const ids = groups.results.map((row) => row.group_id);
      const members = await env.DB.prepare(
        `SELECT DISTINCT user_id FROM directory_group_members WHERE group_id IN (${ids.map(() => "?").join(",")})`,
      ).bind(...ids).all<{ user_id: string }>();
      return members.results.map((row) => row.user_id);
    }
    const everyone = await env.DB.prepare(`SELECT id FROM "user" WHERE banned IS NULL OR banned = 0 LIMIT 1000`).all<{ id: string }>();
    return everyone.results.map((row) => row.id);
  } catch {
    return [];
  }
}

/** A readable name for an access-policy subject such as `oidc:<client id>` or `app:<slug>`. */
export async function appNameForSubject(env: Env, subject: string): Promise<string> {
  try {
    const [protocol, ...rest] = subject.split(":");
    const key = rest.join(":");
    const row = protocol === "app" || protocol === "bookmark"
      ? await env.DB.prepare("SELECT name FROM applications WHERE slug = ?").bind(key).first<{ name: string }>()
      : await env.DB.prepare("SELECT name FROM applications WHERE protocol = ? AND binding = ?").bind(protocol, key).first<{ name: string }>();
    return row?.name ?? key;
  } catch {
    return subject;
  }
}
