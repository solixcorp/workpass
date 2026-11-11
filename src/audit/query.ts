import { akqlParse } from "../policies/akql";

const ordinary = ["=", "==", "!=", "<", "<=", ">", ">=", "~", "!~", "in", "not in", "startswith", "not startswith", "endswith", "not endswith"];
const personOps = ["=", "==", "!=", "~", "!~", "in", "not in", "startswith", "not startswith", "endswith", "not endswith"];
const field = (name: string, aliases: string[], description: string, operators = ordinary, examples: string[] = []) => ({ name, aliases, description, operators, examples });
export const auditQueryFields = [
  field("id", [], "감사 이벤트 ID", ordinary, ['id = "event-id"']),
  field("event_type", ["type"], "이벤트 유형", ordinary, ['type startswith "admin."']),
  field("outcome", [], "처리 결과", ordinary, ['outcome = "failure"']),
  field("client_ip", ["ip"], "클라이언트 IP 주소", ordinary, ['ip startswith "203.0.113."']),
  field("request_path", ["path"], "요청 경로", ordinary, ['path ~ "/admin/"']),
  field("time", ["occurred_at"], "발생 시각 (ISO 또는 상대 시간)", ["=", "==", "!=", "<", "<=", ">", ">=", "in", "not in"], ['time >= "-24h"']),
  field("actor", [], "수행자의 ID, 이메일 또는 이름", personOps, ['actor = "kim@example.com"']),
  field("target", [], "대상자의 ID, 이메일 또는 이름", personOps, ['target = None']),
  field("user", [], "수행자 또는 대상자", personOps, ['user = "kim@example.com"']),
  ...["actor.email", "actor.name", "target.email", "target.name"].map((n) => field(n, [], "사용자 이메일 또는 이름", ordinary, [`${n} ~ "kim"`])),
  field("context", [], "이벤트 컨텍스트 텍스트", ["~"], ['context ~ "login"']),
  ...["country", "region", "city", "asn"].map((n) => field(n, [], "Cloudflare 네트워크 위치 정보", ordinary, [`${n} = "${n === "country" ? "KR" : "Seoul"}"`])),
];
export const auditQueryExamples = [
  { title: "최근 하루 로그인 실패", query: 'type startswith "authentication." and outcome = "failure" and time >= "-24h"' },
  { title: "사용자의 모든 활동", query: 'actor = "kim@example.com"' },
  { title: "관리자 작업", query: 'type startswith "admin."' },
  { title: "수행자가 없는 이벤트", query: "actor = None" },
  { title: "특정 IP의 모든 이벤트", query: 'ip = "203.0.113.9"' },
  { title: "한국에서 발생한 실패", query: 'country = "KR" and outcome = "failure"' },
  { title: "IP 대역 검색", query: 'ip startswith "203.0.113."' },
  { title: "대상 이름 검색", query: 'target.name ~ "kim"' },
  { title: "여러 결과", query: 'outcome in ("success", "failure")' },
];

export class AuditQueryError extends Error {
  constructor(message: string, public position: number | null, public detail: string) { super(message); }
}
const fail = (message: string, position: number | null, detail: string): never => { throw new AuditQueryError(message, position, detail); };
type Token = { text: string; pos: number; kind: string };

// Validate the entire input before using the shared parser, which intentionally
// accepts trailing tokens for its legacy callers. Bound nesting before parsing.
function validate(input: string): string {
  if (input.length > 4096) fail("검색식이 너무 복잡합니다.", null, "query is too long");
  const tokens: Token[] = [];
  let i = 0;
  while (i < input.length) {
    if (/\s/.test(input[i]!)) { i++; continue; }
    const start = i, ch = input[i]!;
    if (ch === '"' || ch === "'") {
      i++;
      while (i < input.length && input[i] !== ch) { if (input[i] === "\\") i++; i++; }
      if (i >= input.length) fail("문자열이 닫히지 않았습니다.", start, "unterminated string in AKQL query");
      i++; tokens.push({ text: input.slice(start, i), pos: start, kind: "value" }); continue;
    }
    const rest = input.slice(i);
    const match = /^(?:-\d+[mhd]|\d{4}-\d\d-\d\d(?:T\d\d:\d\d:\d\d(?:\.\d{1,3})?(?:Z|[+-]\d\d:\d\d))?)(?![\w.])/.exec(rest);
    if (match) { i += match[0].length; tokens.push({ text: JSON.stringify(match[0]), pos: start, kind: "value" }); continue; }
    const number = /^-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?/.exec(rest);
    if (number) { i += number[0].length; tokens.push({ text: number[0], pos: start, kind: "value" }); continue; }
    const word = /^[A-Za-z_][A-Za-z0-9_.@]*/.exec(rest);
    if (word) { i += word[0].length; tokens.push({ text: word[0], pos: start, kind: ["True", "False", "None"].includes(word[0]) ? "value" : "word" }); continue; }
    const op = /^(?:==|!=|<=|>=|!~|[=<>~(),])/.exec(rest);
    if (!op) fail("지원하지 않는 문자가 있습니다.", start, `the AKQL character ${JSON.stringify(ch)} is not supported`);
    i += op![0].length; tokens.push({ text: op![0], pos: start, kind: "symbol" });
  }
  if (tokens.length > 250) fail("검색식이 너무 복잡합니다.", null, "too many tokens");
  let at = 0, nodes = 0;
  const peek = () => tokens[at];
  const bad = (detail: string): never => fail("검색식의 구문을 확인해 주세요.", peek()?.pos ?? input.length, detail);
  const expr = (depth: number): void => {
    if (depth > 50) fail("검색식이 너무 복잡합니다.", peek()?.pos ?? input.length, "maximum depth exceeded");
    atom(depth);
    while (peek()?.text === "and" || peek()?.text === "or") { at++; if (++nodes > 50) fail("검색식이 너무 복잡합니다.", peek()?.pos ?? input.length, "maximum nodes exceeded"); atom(depth); }
  };
  const atom = (depth: number): void => {
    if (peek()?.text === "(") { at++; expr(depth + 1); if (peek()?.text !== ")") bad("unterminated group in AKQL query"); at++; return; }
    if (++nodes > 50) fail("검색식이 너무 복잡합니다.", peek()?.pos ?? input.length, "maximum nodes exceeded");
    const f = peek(); if (!f || f.kind !== "word" || ["not", "and", "or"].includes(f.text)) bad("expected an AKQL field"); at++;
    let op = peek()?.text; at++;
    if (op === "not") { op = `not ${peek()?.text}`; at++; }
    if (![...ordinary].includes(op ?? "")) { at--; bad(`expected an AKQL operator after ${f!.text}`); }
    if (op === "in" || op === "not in") {
      if (peek()?.text !== "(") bad("in/not in expect a parenthesized list"); at++;
      if (peek()?.text !== ")") for (;;) {
        if (peek()?.kind !== "value") bad("AKQL values must be quoted strings, numbers, True/False or None"); at++;
        if (peek()?.text !== ",") break; at++;
      }
      if (peek()?.text !== ")") bad("unterminated list in AKQL query"); at++;
    } else { if (peek()?.kind !== "value") bad("AKQL values must be quoted strings, numbers, True/False or None"); at++; }
  };
  expr(0);
  if (at !== tokens.length) bad("unexpected token in AKQL query");
  return tokens.map((t) => t.text).join(" ");
}

export function compileAuditQuery(input: string, now = new Date()): { sql: string; params: (string | number)[] } {
  const normalized = validate(input);
  let root: ReturnType<typeof akqlParse>;
  try { root = akqlParse(normalized); } catch (e) { fail("검색식의 구문을 확인해 주세요.", null, e instanceof Error ? e.message : "invalid AKQL query"); }
  const params: (string | number)[] = [];
  let count = 0;
  const bind = (v: string | number) => { if (params.length >= 50) fail("검색식이 너무 복잡합니다.", null, "maximum parameters exceeded"); params.push(v); return "?"; };
  const columns: Record<string, string> = { id: "id", event_type: "event_type", outcome: "outcome", client_ip: "client_ip", request_path: "request_path", time: "occurred_at", context: "event_context" };
  for (const n of ["country", "region", "city", "asn"]) columns[n] = `CASE WHEN json_valid(audit_events.event_context) THEN CAST(json_extract(audit_events.event_context, '$.geo.${n}') AS TEXT) END`;
  const col = (name: string) => columns[name]!.startsWith("CASE") ? columns[name]! : `audit_events.${columns[name]}`;
  const compile = (node: typeof root, depth: number): string => {
    if (++count > 50 || depth > 50) fail("검색식이 너무 복잡합니다.", null, "maximum AST complexity exceeded");
    if (node.kind !== "comparison") return `(${compile(node.left!, depth + 1)} ${node.kind.toUpperCase()} ${compile(node.right!, depth + 1)})`;
    const inputField = node.field!.toLowerCase();
    const def = auditQueryFields.find((f) => f.name === inputField || f.aliases.includes(inputField));
    if (!def) fail(`알 수 없는 필드입니다. 사용 가능한 필드: ${auditQueryFields.map((f) => f.name).join(", ")}`, Math.max(0, input.toLowerCase().indexOf(inputField)), `unknown field: ${node.field}`);
    const name = def!.name, op = node.op!;
    if (!def!.operators.includes(op)) fail("이 필드에서 지원하지 않는 연산자입니다.", null, `operator ${op} is not supported for ${name}`);
    const convert = (value: unknown): string | number => {
      if (typeof value !== "string" && typeof value !== "number") fail("값의 형식이 올바르지 않습니다.", null, "expected a string or number");
      if (name !== "time") return value as string | number;
      if (typeof value !== "string") fail("시간 값이 올바르지 않습니다.", null, "expected an ISO date or relative time");
      const relative = /^-(\d+)([mhd])$/.exec(value as string);
      const date = relative ? new Date(now.getTime() - Number(relative[1]) * ({ m: 60000, h: 3600000, d: 86400000 }[relative[2]!]!)) : new Date(value as string);
      if (!relative && !/^\d{4}-\d\d-\d\d(?:T\d\d:\d\d:\d\d(?:\.\d{1,3})?(?:Z|[+-]\d\d:\d\d))?$/.test(value as string) || Number.isNaN(date.getTime())) fail("시간 값이 올바르지 않습니다.", null, "expected an ISO date or relative time");
      return date.toISOString();
    };
    const person = ["actor", "target", "user"].includes(name);
    const ids = name === "user" ? ["actor_user_id", "target_user_id"] : [`${name}_user_id`];
    if (node.value === null && !node.list) {
      if (!["=", "==", "!="].includes(op)) fail("None은 같음 또는 다름 비교에만 사용할 수 있습니다.", null, "invalid null comparison");
      if (name.includes(".")) fail("이 필드에서는 None을 사용할 수 없습니다.", null, "null is not supported for person attributes");
      const expressions = person ? ids.map((id) => `audit_events.${id} IS ${op === "!=" ? "NOT " : ""}NULL`) : [`${col(name)} IS ${op === "!=" ? "NOT " : ""}NULL`];
      return `(${expressions.join(op === "!=" ? " OR " : " AND ")})`;
    }
    const negative = ["!=", "!~", "not in", "not startswith", "not endswith"].includes(op);
    const base = op === "!=" ? "=" : op === "!~" ? "~" : op.startsWith("not ") ? op.slice(4) : op;
    const valueList = node.list?.map(convert);
    const predicate = (column: string): string => {
      if (base === "in") return valueList!.length ? `${column} IN (${valueList!.map(bind).join(", ")})` : "0";
      const value = convert(node.value);
      if (["~", "startswith", "endswith"].includes(base)) {
        const escaped = String(value).replace(/[\\%_]/g, "\\$&");
        const pattern = `${base === "~" || base === "endswith" ? "%" : ""}${escaped}${base === "~" || base === "startswith" ? "%" : ""}`;
        return `${column} LIKE ${bind(pattern)} ESCAPE '\\'`;
      }
      return `${column} ${base === "==" ? "=" : base} ${bind(value)}`;
    };
    let sql: string;
    if (person) {
      sql = ids.map((id) => {
        const matchId = base !== "~";
        const idComparison = matchId ? `${predicate(`audit_events.${id}`)} OR ` : "";
        const email = predicate("person.email"), name = predicate("person.name");
        return `(${idComparison}EXISTS (SELECT 1 FROM "user" AS person WHERE person.id = audit_events.${id} AND (${email} OR ${name})))`;
      }).join(" OR ");
    } else if (name.includes(".")) {
      const [side, attr] = name.split(".");
      sql = `EXISTS (SELECT 1 FROM "user" AS person WHERE person.id = audit_events.${side}_user_id AND ${predicate(`person.${attr}`)})`;
    } else sql = predicate(col(name));
    return negative ? `(NOT COALESCE((${sql}), 0))` : `(${sql})`;
  };
  return { sql: compile(root!, 0), params };
}
