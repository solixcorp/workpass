import type { Env } from "../env";

export type AuditOutcome = "started" | "success" | "failure";

export interface AuditEvent {
  id: string;
  occurred_at: string;
  actor_user_id: string | null;
  target_user_id: string | null;
  event_type: string;
  outcome: AuditOutcome;
  request_path: string;
}

export async function insertAuditEvent(
  env: Env,
  event: Pick<AuditEvent, "id" | "actor_user_id" | "target_user_id" | "event_type" | "outcome" | "request_path">,
): Promise<void> {
  await env.DB.prepare(
    `INSERT INTO audit_events
      (id, occurred_at, actor_user_id, target_user_id, event_type, outcome, request_path)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      event.id,
      new Date().toISOString(),
      event.actor_user_id,
      event.target_user_id,
      event.event_type,
      event.outcome,
      event.request_path,
    )
    .run();
}

export async function updateAuditEvent(
  env: Env,
  id: string,
  update: Pick<AuditEvent, "actor_user_id" | "target_user_id" | "outcome">,
): Promise<void> {
  const result = await env.DB.prepare(
    `UPDATE audit_events
     SET actor_user_id = ?, target_user_id = ?, outcome = ?
     WHERE id = ? AND outcome = 'started'`,
  )
    .bind(update.actor_user_id, update.target_user_id, update.outcome, id)
    .run();
  if (result.meta.changes !== 1) {
    throw new Error("Audit event is missing or already finalized");
  }
}

export async function auditStandaloneOperation(
  env: Env,
  eventType: string,
  requestPath: string,
  operation: () => Promise<{
    response: Response;
    actorUserId?: string | null;
    targetUserId?: string | null;
  }>,
): Promise<Response> {
  const id = crypto.randomUUID();
  try {
    await insertAuditEvent(env, {
      id,
      actor_user_id: null,
      target_user_id: null,
      event_type: eventType,
      outcome: "started",
      request_path: requestPath,
    });
  } catch {
    return Response.json({ error: "Audit event could not be recorded" }, { status: 503 });
  }

  let result: Awaited<ReturnType<typeof operation>>;
  try {
    result = await operation();
  } catch {
    try {
      await updateAuditEvent(env, id, {
        actor_user_id: null,
        target_user_id: null,
        outcome: "failure",
      });
    } catch {
      // Keep the started event for later reconciliation.
    }
    return Response.json({ error: "Operation failed", eventId: id }, { status: 500 });
  }

  try {
    await updateAuditEvent(env, id, {
      actor_user_id: result.actorUserId ?? null,
      target_user_id: result.targetUserId ?? null,
      outcome: result.response.ok ? "success" : "failure",
    });
  } catch {
    return Response.json(
      { error: "Operation audit finalization failed", eventId: id },
      { status: 503 },
    );
  }

  return result.response;
}
