/**
 * Attribute-change SET events: the Shared Signals Framework sender gets one
 * more event kind — custom object attribute changes. The event type URN is
 * this platform's own namespace (no registry claim); a recipient only
 * receives it when its registered `event_types` include the URN, so existing
 * recipients are unaffected. Emissions are best-effort: a dispatch failure
 * logs the delivery row (bounded retry) but never blocks the attribute
 * write.
 */

import type { Env } from "../env";
import { dispatchSSFEvent, listEnabledSsfRecipients } from "./dispatch";

export const ATTRIBUTE_CHANGED_EVENT_TYPE = "urn:solixcorp:internal-auth:attributes-changed:1.0";

export interface AttributeChangedInput {
  /** Deprecated: the subject is always the affected object, never the actor. */
  userId?: string;
  objectType: "user" | "group" | "account";
  objectId: string;
  changedKeys: string[];
}

export async function emitAttributeChangedEvent(
  env: Env,
  input: AttributeChangedInput,
  send: typeof fetch = fetch,
): Promise<number> {
  if (env.ENABLE_SSF_SENDER !== "true") return 0;
  const recipients = await listEnabledSsfRecipients(env).catch(() => []);
  const targets = recipients.filter((recipient) => recipient.eventTypes.includes(ATTRIBUTE_CHANGED_EVENT_TYPE));
  let sent = 0;
  for (const recipient of targets) {
    try {
      await dispatchSSFEvent(env, {
        recipientId: recipient.id,
        eventType: ATTRIBUTE_CHANGED_EVENT_TYPE,
        subject: { [input.objectType]: { [`${input.objectType}_id`]: input.objectId } },
        description: {
          object_type: input.objectType,
          object_id: input.objectId,
          changed_keys: input.changedKeys.slice(0, 32),
        },
      }, send);
      sent += 1;
    } catch (error) {
      console.error("SSF attribute-change dispatch failed", {
        recipientId: recipient.id,
        name: error instanceof Error ? error.name : "UnknownError",
      });
    }
  }
  return sent;
}
