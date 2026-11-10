/**
 * Shared policy engine types (docs/design/authentik-policies.md).
 */

export type BindingTarget =
  | "application"
  | "login"
  | "password_entry"
  | "user_write"
  | "notification_rule";

export type PolicyType =
  | "expression"
  | "password"
  | "password_expiry"
  | "password_uniqueness"
  | "reputation"
  | "geoip"
  | "event_matcher";

export interface PolicyRow {
  id: string;
  name: string;
  type: string;
  config: unknown;
  enabled: boolean;
  executionLogging: boolean;
}

/** A resolved user snapshot exposed to policies as `request.user`. */
export interface PolicyUserSnapshot {
  id: string;
  email: string;
  name: string;
  username: string;
  attributes: Record<string, unknown>;
  roles: string[];
}

/**
 * What a policy evaluation knows. Mutable context entries (prompt data,
 * pending user, arbitrary caller context) survive into later evaluations in
 * the same request when the caller threads the same object through.
 */
export interface PolicyEvaluationContext {
  user: PolicyUserSnapshot | null;
  clientIp: string | null;
  /** The application subject the evaluation targets, when bound to one. */
  subject: string | null;
  context: Record<string, unknown>;
  /** The candidate password at password-entry surfaces. */
  password?: string;
  requestPath?: string;
}
