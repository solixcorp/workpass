/**
 * Built-in development mock mailbox: replaces the external invitation-email
 * receiver during headless local testing. Fail-closed — the routes 404
 * unless `ENABLE_DEV_MOCKS` is set to "true", and operators must not enable
 * the flag in production (the recorded bodies contain invitation tokens).
 */

import { Hono } from "hono";
import type { Env } from "../env";

export const devMockRoutes = new Hono<{ Bindings: Env }>();

const MOCK_PATH = "/dev/mocks/invitation-email";
const TEXT_LIMIT = 4096;
const SUBJECT_LIMIT = 256;
const TO_LIMIT = 256;
const MAX_RECORDS = 20;

function devMocksEnabled(env: Env): boolean {
  return env.ENABLE_DEV_MOCKS === "true";
}

async function ensureMockTable(env: Env): Promise<void> {
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS dev_mock_emails (
      id TEXT PRIMARY KEY NOT NULL,
      delivered_to TEXT NOT NULL,
      subject TEXT,
      body_text TEXT,
      received_at TEXT NOT NULL,
      received_pos INTEGER
    )`,
  ).run();
  // A deterministic ordering column for deployed databases; within the same
  // millisecond the random UUID tiebreak would shuffle the newest-first list.
  try {
    await env.DB.prepare("ALTER TABLE dev_mock_emails ADD COLUMN received_pos INTEGER").run();
  } catch {
    // Column already present.
  }
}

devMockRoutes.post(MOCK_PATH, async (context) => {
  if (!devMocksEnabled(context.env)) return context.notFound();
  await ensureMockTable(context.env);
  let body: Record<string, unknown>;
  try {
    body = (await context.req.json()) as Record<string, unknown>;
  } catch {
    return context.json({ error: "Invalid JSON body" }, 400);
  }
  const to = typeof body.to === "string" ? body.to : null;
  if (!to || to.length === 0 || to.length > TO_LIMIT) {
    return context.json({ error: "to is required and must be at most 256 characters" }, 400);
  }
  const subject = body.subject === undefined || body.subject === null ? null
    : typeof body.subject === "string" && body.subject.length <= SUBJECT_LIMIT ? body.subject : undefined;
  const text = body.text === undefined || body.text === null ? null
    : typeof body.text === "string" && body.text.length <= TEXT_LIMIT ? body.text : undefined;
  if (subject === undefined || text === undefined) {
    return context.json({ error: `subject must be at most ${SUBJECT_LIMIT} and text at most ${TEXT_LIMIT} characters` }, 400);
  }
  await context.env.DB.prepare(
    `INSERT INTO dev_mock_emails (id, delivered_to, subject, body_text, received_at, received_pos)
     VALUES (?, ?, ?, ?, ?, (SELECT COALESCE(MAX(received_pos), 0) + 1 FROM dev_mock_emails))`,
  ).bind(crypto.randomUUID(), to, subject, text, new Date().toISOString()).run();
  context.header("Cache-Control", "no-store");
  return context.json({ recorded: true }, 201);
});

devMockRoutes.get(MOCK_PATH, async (context) => {
  if (!devMocksEnabled(context.env)) return context.notFound();
  await ensureMockTable(context.env);
  const rows = await context.env.DB.prepare(
    `SELECT id, delivered_to AS "to", subject, body_text AS "text", received_at AS receivedAt
     FROM dev_mock_emails ORDER BY received_pos DESC, received_at DESC, id DESC LIMIT ?`,
  ).bind(MAX_RECORDS).all<{ id: string; to: string; subject: string | null; text: string | null; receivedAt: string }>();
  context.header("Cache-Control", "no-store");
  return context.json({ messages: rows.results });
});
