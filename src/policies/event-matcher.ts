/**
 * Event matcher policies and notification rules (docs/design/authentik-policies.md).
 *
 * The matcher combines fixed fields (action, app, client_ip) with an optional
 * AKQL query; every configured field must match, empty fields are wildcards.
 * Notification rules bind event_matcher policies (target
 * `notification_rule`) and dispatch matched events to transports (a webhook
 * URL or email) via the scheduled draining of a durable pending queue.
 */

import { akqlMatch } from "./akql";
import type { EventProjection } from "./types";

export type { EventProjection };

export interface EventMatcherConfig {
  action: string | null;
  app: string | null;
  clientIp: string | null;
  query: string | null;
}

export const EVENT_MATCHER_TYPE = "event_matcher";

export function validateEventMatcherConfig(config: unknown): EventMatcherConfig {
  const value = (config ?? {}) as Record<string, unknown>;
  const optionalString = (key: string, max: number, pattern?: RegExp): string | null => {
    const raw = value[key] === undefined ? value[key.replace(/([A-Z])/g, (m) => `_${m[0].toLowerCase()}`)] : value[key];
    if (raw === undefined || raw === null) return null;
    if (typeof raw !== "string" || raw.length === 0 || raw.length > max) {
      throw new Error(`${key} must be a string of at most ${max} characters`);
    }
    if (pattern && !pattern.test(raw)) throw new Error(`${key} is invalid`);
    return raw;
  };
  const action = optionalString("action", 128);
  const app = optionalString("app", 64);
  const clientIp = optionalString("clientIp", 64, /^[0-9a-fA-F.:]+$/);
  const query = optionalString("query", 4_000);
  if (action === null && app === null && clientIp === null && query === null) {
    throw new Error("event matcher requires at least one of action, app, clientIp or query");
  }
  return { action, app, clientIp, query };
}

/**
 * The event projection matches the authentik event fields: `action` from the
 * audit event type, `app` derived from its first segment, `client_ip`, the
 * acting `user` snapshot, the stored `context` JSON, and `created`.
 */
export function eventMatcherEvaluate(
  config: EventMatcherConfig,
  event: EventProjection,
): boolean {
  if (config.action !== null && event.action !== config.action) return false;
  if (config.app !== null && event.app !== config.app) return false;
  if (config.clientIp !== null && (event.client_ip ?? "") !== config.clientIp) return false;
  if (config.query !== null && !akqlMatch(config.query, event as unknown as Record<string, unknown>)) return false;
  return true;
}

export function eventContextFromRow(eventContext: string | null): Record<string, unknown> {
  if (eventContext === null) return {};
  try {
    return JSON.parse(eventContext) as Record<string, unknown>;
  } catch {
    return {};
  }
}
