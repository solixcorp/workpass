/**
 * AKQL subset for event matching and event search (DjangoQL benchmark):
 * `<field> <operator> <value>` combined with `and`/`or` and parentheses.
 * Operators: `=`, `!=`, `==`, `<`, `<=`, `>`, `>=`, `~`, `!~`, `in`,
 * `not in`, `startswith`, `not startswith`, `endswith`, `not endswith`.
 * Values are quoted strings, integers/floats, `True`/`False` and `None`, plus
 * parenthesized lists. Fields resolve with dot notation into the event
 * projection; a missing field is an evaluation error so miswritten matchers
 * fail through the binding's failure result.
 */

interface AkqlToken {
  type: "field" | "op" | "symbol" | "value" | "comma" | "paren" | "eof";
  value: string;
  kind?: "string" | "number" | "true" | "false" | "none" | "word";
  number?: number;
}

const WORD_OPERATORS = ["in", "startswith", "endswith"];
const NEGATED_FORMS = new Set(["in", "startswith", "endswith"]);
const SYMBOL_OPERATORS = ["==", "!=", "<=", ">=", "=", "<", ">", "~", "!~"];

function tokenize(query: string): AkqlToken[] {
  const tokens: AkqlToken[] = [];
  let index = 0;
  while (index < query.length) {
    const character = query[index];
    if (/\s/.test(character)) { index += 1; continue; }
    if (character === "(" || character === ")") {
      tokens.push({ type: "paren", value: character });
      index += 1;
      continue;
    }
    if (character === ",") {
      tokens.push({ type: "comma", value: "," });
      index += 1;
      continue;
    }
    if (character === '"' || character === "'") {
      let out = "";
      let cursor = index + 1;
      while (cursor < query.length && query[cursor] !== character) {
        if (query[cursor] === "\\") {
          const next = query[cursor + 1];
          out += next === "n" ? "\n" : next === "t" ? "\t" : next === "\r" ? "" : next;
          cursor += 2;
          continue;
        }
        out += query[cursor];
        cursor += 1;
      }
      if (cursor >= query.length) throw new Error("unterminated string in AKQL query");
      tokens.push({ type: "value", value: out, kind: "string" });
      index = cursor + 1;
      continue;
    }
    if (/[0-9]/.test(character) || (character === "-" && /[0-9]/.test(query[index + 1] ?? ""))) {
      let end = index;
      while (end < query.length && /[-0-9.eE:TZ]/.test(query[end]!)) end += 1;
      const raw = query.slice(index, end);
      const looksLikeDate = /^\d{4}-\d{2}-\d{2}/.test(raw);
      if (looksLikeDate) {
        tokens.push({ type: "value", value: raw, kind: "string" });
      } else {
        const number = Number(raw);
        if (Number.isNaN(number)) throw new Error(`the AKQL number ${raw} is invalid`);
        tokens.push({ type: "value", value: raw, kind: "number", number });
      }
      index = end;
      continue;
    }
    const three = query.slice(index, index + 3);
    if ( SYMBOL_OPERATORS.includes(three)) {
      tokens.push({ type: "symbol", value: three });
      index += 3;
      continue;
    }
    const two = query.slice(index, index + 2);
    if (SYMBOL_OPERATORS.includes(two)) {
      tokens.push({ type: "symbol", value: two });
      index += 2;
      continue;
    }
    if (SYMBOL_OPERATORS.includes(character)) {
      tokens.push({ type: "symbol", value: character });
      index += 1;
      continue;
    }
    if (/[A-Za-z0-9_.@]/.test(character)) {
      let end = index;
      while (end < query.length && /[A-Za-z0-9_.@]/.test(query[end]!)) end += 1;
      const raw = query.slice(index, end);
      if (raw === "True" || raw === "False" || raw === "None") {
        tokens.push({ type: "value", value: raw, kind: raw === "None" ? "none" : (raw === "True" ? "true" : "false") });
      } else if (SYMBOL_OPERATORS.includes(raw)) {
        tokens.push({ type: "symbol", value: raw });
      } else if (WORD_OPERATORS.includes(raw)) {
        tokens.push({ type: "op", value: raw });
      } else if (raw === "not") {
        tokens.push({ type: "op", value: "not" });
      } else if (raw === "and" || raw === "or") {
        tokens.push({ type: "op", value: raw });
      } else if (raw.includes(".")) {
        tokens.push({ type: "field", value: raw });
      } else {
        tokens.push({ type: "field", value: raw });
      }
      index = end;
      continue;
    }
    throw new Error(`the AKQL character ${JSON.stringify(character)} is not supported`);
  }
  tokens.push({ type: "eof", value: "" });
  return tokens;
}

interface AkqlNode {
  kind: "comparison" | "and" | "or";
  field?: string;
  op?: string;
  value?: unknown;
  list?: unknown[];
  left?: AkqlNode;
  right?: AkqlNode;
}

export function akqlParse(query: string): AkqlNode {
  const tokens = tokenize(query);
  let position = 0;

  const peek = (): AkqlToken => tokens[position]!;
  const next = (): AkqlToken => tokens[position++]!;

  const peekWord = (value: string): boolean =>
    peek().type === "op" && peek().value === value;

  function parseOr(): AkqlNode {
    let left = parseAnd();
    while (peekWord("or")) {
      next();
      left = { kind: "or", left, right: parseAnd() };
    }
    return left;
  }

  function parseAnd(): AkqlNode {
    let left = parseAtom();
    while (peekWord("and")) {
      next();
      left = { kind: "and", left, right: parseAtom() };
    }
    return left;
  }

  function parseAtom(): AkqlNode {
    const token = peek();
    if (token.type === "paren" && token.value === "(") {
      next();
      const inner = parseOr();
      const close = peek();
      if (close.type !== "paren" || close.value !== ")") throw new Error("unterminated group in AKQL query");
      next();
      return inner;
    }
    return parseComparison();
  }

  function parseListValues(): unknown[] {
    const valueToken = next();
    if (valueToken.type !== "paren" || valueToken.value !== "(") {
      throw new Error("in/not in expect a parenthesized list");
    }
    const values: unknown[] = [];
    for (;;) {
      const token = peek();
      if (token.type === "eof") throw new Error("unterminated list in AKQL query");
      if (token.type === "paren" && token.value === ")") { next(); break; }
      values.push(adoptValue(next()));
      if (peek().type === "comma") { next(); continue; }
      if (peek().type === "paren" && peek().value === ")") { next(); break; }
      throw new Error("AKQL list values must be separated with commas");
    }
    return values;
  }

  function adoptValue(token: AkqlToken): unknown {
    if (token.kind === "number") return token.number;
    if (token.kind === "true") return true;
    if (token.kind === "false") return false;
    if (token.kind === "none") return null;
    if (token.kind === "string") return token.value;
    throw new Error("AKQL values must be quoted strings, numbers, True/False or None");
  }

  function parseComparison(): AkqlNode {
    let negated = false;
    const fieldToken = next();
    if (fieldToken.type !== "field") {
      throw new Error(
        fieldToken.type === "op" && fieldToken.value === "not"
          ? "a bare not is not supported in AKQL; use !=, !~ or a negated list form"
          : "expected an AKQL field",
      );
    }
    const first = peek();
    let op: string;
    if (first.type === "symbol") {
      next();
      op = first.value;
    } else if (first.type === "op" && first.value === "not") {
      next();
      const after = next();
      if (!(after.type === "op" && NEGATED_FORMS.has(after.value))) {
        throw new Error("a bare not is not supported in AKQL; use !=, !~ or a negated list form");
      }
      op = after.value;
      negated = true;
    } else if (first.type === "op" && (WORD_OPERATORS.includes(first.value) || NEGATED_FORMS.has(first.value))) {
      next();
      op = first.value;
    } else if (first.type === "op" && (first.value === "and" || first.value === "or")) {
      throw new Error("expected a comparison; and/or cannot follow a field directly");
    } else {
      throw new Error(`expected an AKQL operator after ${fieldToken.value}`);
    }
    let value: unknown;
    let list: unknown[] | undefined;
    if (op === "in") {
      list = parseListValues();
      value = null;
    } else {
      value = adoptValue(next());
    }
    return {
      kind: "comparison",
      field: fieldToken.value,
      op: negated ? `not ${op}` : op,
      value,
      list,
    };
  }

  const root = parseOr();
  if (peek().type !== "eof") throw new Error("unexpected token in AKQL query");
  return root;
}

// The negated-value path above needs `op` in scope; restructure explicitly.

function resolveField(projection: Record<string, unknown>, field: string): { found: boolean; value: unknown } {
  let current: unknown = projection;
  for (const part of field.split(".")) {
    if (current === null || current === undefined || typeof current !== "object") {
      return { found: false, value: undefined };
    }
    if (!Object.prototype.hasOwnProperty.call(current, part)) return { found: false, value: undefined };
    current = (current as Record<string, unknown>)[part];
  }
  return { found: true, value: current };
}

/** AKQL evaluation against a resolved projection. Missing fields are errors. */
export function akqlEvaluate(node: AkqlNode, projection: Record<string, unknown>): boolean {
  switch (node.kind) {
    case "or": return akqlEvaluate(node.left!, projection) || akqlEvaluate(node.right!, projection);
    case "and": return akqlEvaluate(node.left!, projection) && akqlEvaluate(node.right!, projection);
    case "comparison": {
      const resolved = resolveField(projection, node.field!);
      if (!resolved.found) throw new Error(`the AKQL field ${node.field} does not exist on this event`);
      const left = resolved.value;
      const value = node.value;
      switch (node.op) {
        case "=":
        case "==": {
          if (typeof value === "string") return String(left ?? "") === value;
          return left === null || left === undefined ? value === null : left === value;
        }
        case "!=": {
          if (typeof value === "string") return String(left ?? "") !== value;
          return left === null || left === undefined ? value !== null : left !== value;
        }
        case "<":
        case "<=":
        case ">":
        case ">=": {
          if (typeof left === "string" && typeof value === "string") {
            return node.op === "<" ? left < value : node.op === "<=" ? left <= value : node.op === ">" ? left > value : left >= value;
          }
          const leftNumber = typeof left === "number" ? left : Number(left);
          const rightNumber = typeof value === "number" ? value : Number(value);
          return node.op === "<" ? leftNumber < rightNumber
            : node.op === "<=" ? leftNumber <= rightNumber
            : node.op === ">" ? leftNumber > rightNumber
            : leftNumber >= rightNumber;
        }
        case "~":
          return String(left ?? "").toLowerCase().includes(String(value ?? "").toLowerCase());
        case "!~":
          return !String(left ?? "").toLowerCase().includes(String(value ?? "").toLowerCase());
        case "startswith":
          return String(left ?? "").toLowerCase().startsWith(String(value ?? "").toLowerCase());
        case "not startswith":
          return !String(left ?? "").toLowerCase().startsWith(String(value ?? "").toLowerCase());
        case "endswith":
          return String(left ?? "").toLowerCase().endsWith(String(value ?? "").toLowerCase());
        case "not endswith":
          return !String(left ?? "").toLowerCase().endsWith(String(value ?? "").toLowerCase());
        case "in":
          return (node.list ?? []).some((entry) => String(left ?? "") === String(entry));
        case "not in":
          return !(node.list ?? []).some((entry) => String(left ?? "") === String(entry));
        default:
          throw new Error(`the AKQL operator ${node.op} is not supported`);
      }
    }
  }
}

/** Parse-once evaluate-many convenience wrapper. */
export function akqlMatch(query: string, projection: Record<string, unknown>): boolean {
  return akqlEvaluate(akqlParse(query), projection);
}
