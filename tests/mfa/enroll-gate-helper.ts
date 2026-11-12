/** Test-only: mark every live session as having just re-proved password and a second check. */
export async function grantEnrollGate(db: { prepare(sql: string): { all<T>(): Promise<{ results: T[] }>; bind(...values: unknown[]): { run(): Promise<unknown> } } }): Promise<void> {
  const sessions = await db.prepare('SELECT token, "userId" AS userId FROM "session"').all<{ token: string; userId: string }>();
  const now = Date.now();
  for (const row of sessions.results) {
    await db.prepare(
      `INSERT INTO mfa_enroll_gates (session_token, user_id, password_at, second_at) VALUES (?, ?, ?, ?)
       ON CONFLICT (session_token) DO UPDATE SET user_id = excluded.user_id, password_at = excluded.password_at, second_at = excluded.second_at`,
    ).bind(row.token, row.userId, now, now).run();
  }
}
