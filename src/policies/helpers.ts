/**
 * Helpers exposed to expression policies (docs/design/authentik-policies.md).
 * Names keep the authentik `ak_` prefix; every helper is async-capable, reads
 * only through the platform's own surfaces, and never exposes host state.
 */

import type { Env } from "../env";
import { insertAuditEvent } from "../audit/store";
import { sendTransactionEmail } from "../mail/send";
import { evaluateTyped } from "./registry";
import type { PolicyEvaluationContext, PolicyUserSnapshot } from "./types";

interface PolicyResult { passing: boolean; messages: string[] }

export interface ExpressionLogger {
  debug: (message: string, ...parameters: unknown[]) => void;
  info: (message: string, ...parameters: unknown[]) => void;
  warning: (message: string, ...parameters: unknown[]) => void;
  error: (message: string, ...parameters: unknown[]) => void;
}

const DNS_CACHE_LIMIT = 32;
const DNS_TTL_MS = 3 * 60 * 1000;
const dnsCache = new Map<string, { value: string[]; expires: number }>();

function dnsGet(key: string): string[] | null {
  const entry = dnsCache.get(key);
  if (!entry) return null;
  if (entry.expires < Date.now()) {
    dnsCache.delete(key);
    return null;
  }
  return entry.value;
}

function dnsSet(key: string, value: string[]): void {
  if (dnsCache.size > DNS_CACHE_LIMIT) {
    const oldest = dnsCache.keys().next().value;
    if (oldest !== undefined) dnsCache.delete(oldest);
  }
  dnsCache.set(key, { value, expires: Date.now() + DNS_TTL_MS });
}

async function dohQuery(name: string, type: "A" | "AAAA" | "PTR"): Promise<Array<{ data?: string }>> {
  const url = new URL("https://cloudflare-dns.com/dns-query");
  url.searchParams.set("name", name);
  url.searchParams.set("type", type);
  const response = await fetch(url, { headers: { accept: "application/dns-json" } });
  if (!response.ok) throw new Error(`DNS lookup failed with status ${response.status}`);
  const body = (await response.json()) as { Answer?: Array<{ data?: string }> };
  return body.Answer ?? [];
}

export interface HelperRuntime {
  messages: string[];
  callPolicyByName: (name: string, kwargs: Record<string, unknown>) => Promise<{ passing: boolean; messages: string[]; rawResult?: unknown }>;
}

/**
 * Build the allowlisted globals object for one expression evaluation. Mutations
 * through the request context write into the caller's `context` object so
 * downstream bindings see them.
 */
export function buildGlobals(runtime: HelperRuntime, env: Env, context: PolicyEvaluationContext): Record<string, unknown> {
  const snapshot: PolicyUserSnapshot | null = context.user;
  const userView: Record<string, unknown> | null = snapshot
    ? Object.assign({ ...snapshot }, { pk: snapshot.id })
    : null;

  const request = {
    user: userView,
    context: context.context,
    get http_request() {
      return {
        path: context.requestPath ?? null,
        client_ip: context.clientIp,
      };
    },
    get obj() {
      return context.subject ? { subject: context.subject } : null;
    },
  };

  const messages = runtime.messages;
  const helpers = {
    ak_message: (message: unknown): boolean => {
      messages.push(String(message));
      return Boolean(message);
    },

    regex_match: (value: unknown, regex: string): boolean => {
      if (typeof regex !== "string") throw new Error("regex_match expects a string pattern");
      return new RegExp(regex).test(String(value));
    },

    regex_replace: (value: unknown, regex: string, replacement: string): string => {
      if (typeof regex !== "string" || typeof replacement !== "string") {
        throw new Error("regex_replace expects string pattern and replacement");
      }
      return String(value).replace(new RegExp(regex), String(replacement));
    },

    list_flatten: (value: unknown): unknown => {
      if (Array.isArray(value)) return value.length > 0 ? value[0] : null;
      return value;
    },

    ip_address: (value: string): string => {
      if (typeof value !== "string" || !/^[0-9a-fA-F.:]+$/.test(value)) {
        throw new Error("ip_address expects a literal IP string");
      }
      return value;
    },

    ip_network: (value: string): string => {
      if (typeof value !== "string" || !/^[0-9a-fA-F.:\/]+$/.test(value)) {
        throw new Error("ip_network expects a CIDR string");
      }
      return value;
    },

    ip_in_subnet: (address: unknown, subnet: string): boolean => {
      const ip = typeof address === "string" ? address.trim() : "";
      const network = String(subnet).trim();
      if (!ip || !network.includes("/") || !network.includes(".")) return false;
      const [rangeIp, bitsRaw] = network.split("/");
      if (rangeIp!.includes(":") || ip.includes(":")) return false; // IPv6 not supported by this helper
      const bits = Number(bitsRaw);
      if (!Number.isInteger(bits) || bits < 0 || bits > 32) throw new Error("invalid subnet mask");
      const toLong = (text: string): number => {
        const parts = text.split(".").map(Number);
        if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
          throw new Error("invalid IPv4 address");
        }
        return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
      };
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      return (toLong(ip) & mask) === (toLong(rangeIp!) & mask);
    },

    ak_is_group_member: async (user: unknown, filters: Record<string, unknown> = {}): Promise<boolean> => {
      if (!user || typeof user !== "object" || typeof (user as { id?: unknown }).id !== "string") {
        throw new Error("ak_is_group_member expects a user object");
      }
      const name = filters.name;
      const groupId = filters.id ?? filters.group_id;
      if (typeof name !== "string" && typeof groupId !== "string") {
        throw new Error("ak_is_group_member expects a group id or name filter");
      }
      const group = typeof groupId === "string"
        ? { id: groupId }
        : await env.DB.prepare("SELECT id FROM directory_groups WHERE name = ? LIMIT 1").bind(name).first<{ id: string }>();
      if (!group) return false;
      return (await env.DB.prepare(
        "SELECT 1 FROM directory_group_members WHERE group_id = ? AND user_id = ? LIMIT 1",
      ).bind(group.id, (user as { id: string }).id).first()) !== null;
    },

    ak_user_by: async (filters: Record<string, unknown> = {}): Promise<Record<string, unknown> | null> => {
      if (typeof filters.username === "string") {
        const row = await env.DB.prepare(
          `SELECT id, email, name, username, (banned IS NULL OR banned = 0) AS active FROM "user" WHERE username = ? LIMIT 1`,
        ).bind(filters.username).first<Record<string, unknown>>();
        return row ?? null;
      }
      if (typeof filters.email === "string") {
        const row = await env.DB.prepare(
          `SELECT id, email, name, username, (banned IS NULL OR banned = 0) AS active FROM "user" WHERE email = ? LIMIT 1`,
        ).bind(filters.email).first<Record<string, unknown>>();
        return row ?? null;
      }
      if (typeof filters.id === "string") {
        const row = await env.DB.prepare(
          `SELECT id, email, name, username, (banned IS NULL OR banned = 0) AS active FROM "user" WHERE id = ? LIMIT 1`,
        ).bind(filters.id).first<Record<string, unknown>>();
        return row ?? null;
      }
      throw new Error("ak_user_by expects username, email or id");
    },

    ak_user_has_authenticator: async (user: unknown, deviceType: unknown = null): Promise<boolean> => {
      if (!user || typeof user !== "object" || typeof (user as { id?: unknown }).id !== "string") {
        throw new Error("ak_user_has_authenticator expects a user object");
      }
      const userId = (user as { id: string }).id;
      const { usableSecondFactors } = await import("../security/step-up");
      const methods = await usableSecondFactors(env, userId).catch(() => [] as string[]);
      if (deviceType === null || deviceType === undefined) {
        if (methods.length > 0) return true;
        const passkey = await env.DB.prepare(
          `SELECT COUNT(*) AS count FROM "passkey" WHERE userId = ?`,
        ).bind(userId).first<{ count: number }>().catch(() => null);
        return (passkey?.count ?? 0) > 0;
      }
      const wanted = String(deviceType);
      if (wanted === "totp") return methods.includes("totp") || methods.includes("otp");
      if (wanted === "duo") return methods.includes("duo_push");
      if (wanted === "static") return methods.includes("backup_code");
      if (wanted === "webauthn") {
        const passkey = await env.DB.prepare(
          `SELECT COUNT(*) AS count FROM "passkey" WHERE userId = ?`,
        ).bind(userId).first<{ count: number }>().catch(() => null);
        return (passkey?.count ?? 0) > 0;
      }
      return methods.includes(wanted);
    },

    ak_create_event: async (action: unknown, parameters: Record<string, unknown> = {}): Promise<boolean> => {
      if (typeof action !== "string") throw new Error("ak_create_event expects an action string");
      await insertAuditEvent({
        DB: env.DB,
      } as Env, {
        id: crypto.randomUUID(),
        actor_user_id: context.user?.id ?? null,
        target_user_id: null,
        event_type: action,
        outcome: "success",
        request_path: context.requestPath ?? "/policies",
      });
      return true;
    },

    ak_send_email: async (
      address: unknown,
      subject: unknown,
      options: Record<string, unknown> = {},
    ): Promise<boolean> => {
      const recipients = Array.isArray(address) ? address : [address];
      if (recipients.length === 0 || recipients.some((r) => typeof r !== "string")) {
        throw new Error("ak_send_email expects one address or a list of addresses");
      }
      if (typeof subject !== "string" || subject.length === 0 || subject.length > 256) {
        throw new Error("ak_send_email expects a subject of at most 256 characters");
      }
      const body = typeof options.body === "string" ? options.body : null;
      if (body === null || body.length === 0 || body.length > 16_000) {
        throw new Error("ak_send_email expects a plain-text body of at most 16000 characters");
      }
      if (recipients.length > 10) throw new Error("ak_send_email supports at most 10 recipients");
      for (const recipient of recipients) {
        await sendTransactionEmail(env, {
          to: recipient as string,
          subject,
          text: body,
        });
      }
      return true;
    },

    ak_call_policy: (name: unknown, kwargs: Record<string, unknown> = {}): Promise<{ passing: boolean; messages: string[]; rawResult?: unknown }> => {
      if (typeof name !== "string") throw new Error("ak_call_policy expects a policy name");
      return runtime.callPolicyByName(name, kwargs);
    },

    resolve_dns: async (hostname: unknown, ipVersion: unknown = null): Promise<string[]> => {
      if (typeof hostname !== "string" || hostname.length === 0 || hostname.length > 253) {
        throw new Error("resolve_dns expects a hostname");
      }
      if (ipVersion !== null && ipVersion !== 4 && ipVersion !== 6) {
        throw new Error("resolve_dns expects ip_version 4 or 6");
      }
      const family = ipVersion === 4 ? "A" : ipVersion === 6 ? "AAAA" : "A";
      const cacheKey = `${family}:${hostname}`;
      const cached = dnsGet(cacheKey);
      if (cached) return cached;
      const records = await dohQuery(hostname, family as "A");
      const addresses = records.map((record) => record.data ?? "").filter(Boolean);
      dnsSet(cacheKey, addresses);
      return addresses;
    },

    reverse_dns: async (address: unknown): Promise<string> => {
      const ip = typeof address === "string" ? address.trim() : "";
      if (!ip || !/^[0-9.]+$/.test(ip)) return String(address ?? "");
      if (!ip.includes(".") || ip.split(".").length !== 4) return ip;
      const cacheKey = `PTR:${ip}`;
      const cached = dnsGet(cacheKey);
      if (cached) return cached[0] ?? ip;
      const records = await dohQuery(`${ip.split(".").reverse().join(".")}.in-addr.arpa`, "PTR");
      const name = records[0]?.data ?? ip;
      dnsSet(cacheKey, [name]);
      return name;
    },

    ak_logger: {
      debug: (message: string, ...rest: unknown[]) => console.debug(String(message), ...rest),
      info: (message: string, ...rest: unknown[]) => console.info(String(message), ...rest),
      warning: (message: string, ...rest: unknown[]) => console.warn(String(message), ...rest),
      error: (message: string, ...rest: unknown[]) => console.error(String(message), ...rest),
    } satisfies ExpressionLogger,
  };

  return {
    ...helpers,
    request,
    context: context.context,
    // Flow-style keys live in the context, but authentik recipes also read
    // pending_user directly from context["pending_user"].
    pending_user: (context.context as Record<string, unknown>).pending_user ?? null,
    prompt_data: (context.context as Record<string, unknown>).prompt_data ?? null,
    ak_client_ip: context.clientIp,
    ak_is_sso_flow: false,
    ...ALLOWED_NAMESPACES,
  };
}

const ALLOWED_NAMESPACES = {
  Math: Object.freeze({ ...Math, random: undefined }),
  JSON,
  Number,
  String,
  Boolean,
  Array,
  Object,
  Date: { now: Date.now.bind(Date), parse: Date.parse.bind(Date), UTC: Date.UTC.bind(Date) },
};
