/**
 * Safe JS-subset expression interpreter for authentik-benchmarked expression
 * policies (docs/design/authentik-policies.md). The interpreter resolves
 * identifiers only from locals, the provided context, allowlisted namespaces
 * and helpers; member access goes through a blocked-name/allowlisted-method
 * gate restricted to plain-data receivers. Every node evaluation consumes a
 * step from a strict budget, so evaluation always terminates and no host
 * global, dynamic code, or prototype trick is reachable.
 *
 * Supported syntax (mirrors the authentik example style):
 *   let/const bindings, assignments to locals and context objects, if/else,
 *   while/for with bounded steps, return, ternaries, the usual operators,
 *   object/array literals, calls to the provided helpers and to a fixed
 *   method allowlist on primitive values and plain data.
 */

const MAX_SOURCE_LENGTH = 20_000;
export const DEFAULT_STEP_BUDGET = 200_000;

const BLOCKED_MEMBERS = new Set([
  "__proto__", "prototype", "constructor", "caller", "callee", "arguments",
  "eval", "Function", "globalThis", "self", "window", "import",
]);

const ALLOWED_GLOBALS: Record<string, unknown> = {
  Math: { ...Math, random: undefined },
  JSON,
  Number,
  String,
  Boolean,
  Array,
  Object: Object,
  Date: { now: Date.now, parse: Date.parse, UTC: Date.UTC },
};

const METHOD_ALLOWLIST = new Set([
  // strings
  "includes", "indexOf", "split", "slice", "substring", "substr", "toLowerCase",
  "toUpperCase", "trim", "startsWith", "endsWith", "replace", "charAt", "charCodeAt",
  "padStart", "padEnd", "repeat", "concat", "at",
  // arrays
  "join", "map", "filter", "find", "some", "every", "includes", "indexOf", "slice",
  "concat", "push", "pop", "shift", "unshift", "at", "reduce",
  // numbers are compared as data; Date/Number handled by globals
]);

export class ExpressionStepLimit extends Error {
  constructor() {
    super("expression exceeded its execution budget");
  }
}

export interface ExpressionScope {
  /** Allowlisted helper functions plus named variables. */
  globals: Record<string, unknown>;
  stepBudget: number;
}

interface Token {
  type: "num" | "str" | "ident" | "punct" | "eof";
  value: string;
}

function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  let index = 0;
  while (index < source.length) {
    const character = source[index]!;
    if (/\s/.test(character)) { index += 1; continue; }
    if (/^\/\//.test(source.slice(index, index + 2))) {
      const end = source.indexOf("\n", index);
      index = end === -1 ? source.length : end + 1;
      continue;
    }
    if (/^\/\*/.test(source.slice(index, index + 2))) {
      const end = source.indexOf("*/", index + 2);
      if (end === -1) throw new Error("unterminated block comment");
      index = end + 2;
      continue;
    }
    if (/[0-9]/.test(character) || (character === "." && /[0-9]/.test(source[index + 1] ?? ""))) {
      let end = index;
      while (end < source.length && /[0-9.eE+\-]/.test(source[end]!)) {
        // Stop on +/- that are not exponent markers.
        if ((source[end] === "+" || source[end] === "-") && !/[eE]/.test(source[end - 1] ?? "")) break;
        end += 1;
      }
      tokens.push({ type: "num", value: source.slice(index, end) });
      index = end;
      continue;
    }
    if (character === '"' || character === "'" || character === "`") {
      let end = index + 1;
      let value = "";
      while (end < source.length && source[end] !== character) {
        if (source[end] === "\\") {
          const next = source[end + 1];
          value += next === "n" ? "\n" : next === "t" ? "\t" : next === "\r" ? "" : next;
          end += 2;
          continue;
        }
        value += source[end];
        end += 1;
      }
      if (end >= source.length) throw new Error("unterminated string literal");
      tokens.push({ type: "str", value });
      index = end + 1;
      continue;
    }
    if (/[A-Za-z_$]/.test(character)) {
      let end = index;
      while (end < source.length && /[A-Za-z0-9_$]/.test(source[end]!)) end += 1;
      tokens.push({ type: "ident", value: source.slice(index, end) });
      index = end;
      continue;
    }
    const three = source.slice(index, index + 3);
    if (three === "===" || three === "!==" || three === "<=" || three === ">=" || three === "&&" || three === "||") {
      tokens.push({ type: "punct", value: three });
      index += 3;
      continue;
    }
    const two = source.slice(index, index + 2);
    if (["==", "!=", "<=", ">=", "&&", "||", "+=", "-="].includes(two)) {
      tokens.push({ type: "punct", value: two });
      index += 2;
      continue;
    }
    if ("+-*/%<>!=()[]{};,.:?".includes(character)) {
      tokens.push({ type: "punct", value: character });
      index += 1;
      continue;
    }
    throw new Error(`unsupported character ${JSON.stringify(character)}`);
  }
  tokens.push({ type: "eof", value: "" });
  return tokens;
}

// --- parser -----------------------------------------------------------------

type Node =
  | { kind: "num"; value: number }
  | { kind: "str"; value: string }
  | { kind: "bool"; value: boolean }
  | { kind: "null" }
  | { kind: "undef" }
  | { kind: "ident"; name: string }
  | { kind: "member"; object: Node; property: string; computed: boolean }
  | { kind: "index"; object: Node; index: Node }
  | { kind: "call"; callee: Node; args: Node[] }
  | { kind: "unary"; op: string; operand: Node }
  | { kind: "binary"; op: string; left: Node; right: Node }
  | { kind: "logical"; op: string; left: Node; right: Node }
  | { kind: "assign"; op: string; target: Node; value: Node }
  | { kind: "ternary"; test: Node; consequent: Node; alternate: Node }
  | { kind: "object"; entries: Array<{ key: string; value: Node }> }
  | { kind: "array"; elements: Node[] }
  | { kind: "let"; name: string; value: Node | null }
  | { kind: "if"; test: Node; consequent: Node; alternate: Node | null }
  | { kind: "while"; test: Node; body: Node }
  | { kind: "for"; init: Node | null; test: Node | null; update: Node | null; body: Node }
  | { kind: "return"; value: Node | null }
  | { kind: "block"; body: Node[] }
  | { kind: "expr"; expression: Node };

const PUNCT = /^(\+\+|--|===|!==|<=|>=|==|!=|&&|\|\||[+\-*/%<>!=(){}\[\];,.?:])$/;
function isIdentifier(text: string): boolean {
  return /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(text);
}

class Parser {
  private position = 0;
  constructor(private readonly tokens: Token[]) {}

  private peek(): Token { return this.tokens[this.position]!; }
  private consume(): Token { return this.tokens[this.position++]!; }
  private expectPunct(value: string): void {
    const token = this.consume();
    if (token.type !== "punct" || token.value !== value) {
      throw new Error(`expected ${value}, found ${JSON.stringify(token.value || token.type)}`);
    }
  }
  private acceptPunct(value: string): boolean {
    if (this.peek().type === "punct" && this.peek().value === value) { this.consume(); return true; }
    return false;
  }

  parseProgram(): Node {
    const body: Node[] = [];
    while (this.peek().type !== "eof") body.push(this.parseStatement());
    return { kind: "block", body };
  }

  private parseStatement(): Node {
    const token = this.peek();
    if (token.type === "punct" && token.value === ";") { this.consume(); return { kind: "block", body: [] }; }
    if (token.type === "punct" && token.value === "{") return this.parseBlock();
    if (token.type === "ident") {
      if (token.value === "let" || token.value === "const" || token.value === "var") {
        this.consume();
        const name = this.consume();
        if (name.type !== "ident") throw new Error("expected a binding name");
        if (BLOCKED_MEMBERS.has(name.value)) throw new Error("blocked binding name");
        let value: Node | null = null;
        if (this.acceptPunct("=")) value = this.parseExpression();
        this.consumeSemicolon();
        return { kind: "let", name: name.value, value };
      }
      if (token.value === "if") return this.parseIf();
      if (token.value === "while") {
        this.consume();
        this.expectPunct("(");
        const test = this.parseExpression();
        this.expectPunct(")");
        return { kind: "while", test, body: this.parseStatement() };
      }
      if (token.value === "for") {
        this.consume();
        this.expectPunct("(");
        const init = this.peek().value === ";" ? null : (this.peek().value === "let" || this.peek().value === "var" ? this.parseStatement() : this.parseExpressionStatement());
        this.expectPunct(";");
        const test = this.peek().value !== ";" ? this.parseExpression() : null;
        this.expectPunct(";");
        const update = this.peek().value !== ")" ? this.parseExpression() : null;
        this.expectPunct(")");
        return { kind: "for", init, test, update, body: this.parseStatement() };
      }
      if (token.value === "return") {
        this.consume();
        if (this.acceptPunct(";")) return { kind: "return", value: null };
        const value = this.parseExpression();
        this.consumeSemicolon();
        return { kind: "return", value };
      }
    }
    return this.parseExpressionStatement();
  }

  private consumeSemicolon(): void {
    if (this.peek().type === "eof") return;
    if (this.peek().type === "punct" && this.peek().value === ";") { this.consume(); return; }
    if (this.peek().type === "punct" && this.peek().value === "}") return; // block end (lenient ASI)
    if (this.peek().type === "ident" && this.peek().value === "else") return;
    this.expectPunct(";");
  }

  private parseExpressionStatement(): Node {
    const expression = this.parseExpression();
    this.consumeSemicolon();
    return { kind: "expr", expression };
  }

  private parseBlock(): Node {
    this.expectPunct("{");
    const body: Node[] = [];
    while (!(this.peek().type === "punct" && this.peek().value === "}")) {
      if (this.peek().type === "eof") throw new Error("unterminated block");
      body.push(this.parseStatement());
    }
    this.consume();
    return { kind: "block", body };
  }

  private parseIf(): Node {
    this.consume();
    this.expectPunct("(");
    const test = this.parseExpression();
    this.expectPunct(")");
    const consequent = this.parseStatement();
    let alternate: Node | null = null;
    if (this.peek().type === "ident" && this.peek().value === "else") {
      this.consume();
      alternate = this.peek().value === "if" ? this.parseIf() : this.parseStatement();
    }
    return { kind: "if", test, consequent, alternate };
  }

  parseExpression(): Node {
    let expression = this.parseAssignment();
    while (this.acceptPunct(",")) {
      // Comma only valid inside literal contexts; reject outside by treating as error.
      throw new Error("comma expressions are not supported");
    }
    return expression;
  }

  private parseAssignment(): Node {
    const left = this.parseTernary();
    const token = this.peek();
    if (token.type === "punct" && (token.value === "=" || token.value === "+=" || token.value === "-=")) {
      this.consume();
      const value = this.parseAssignment();
      if (left.kind !== "ident" && left.kind !== "member" && left.kind !== "index") {
        throw new Error("invalid assignment target");
      }
      return { kind: "assign", op: token.value, target: left, value };
    }
    return left;
  }

  private parseTernary(): Node {
    const test = this.parseLogical();
    if (this.peek().type === "punct" && this.peek().value === "?") {
      this.consume();
      const consequent = this.parseAssignment();
      this.expectPunct(":");
      const alternate = this.parseAssignment();
      return { kind: "ternary", test, consequent, alternate };
    }
    return test;
  }

  private parseLogical(): Node {
    let left = this.parseBinary();
    while (this.peek().type === "punct" && (this.peek().value === "&&" || this.peek().value === "||")) {
      const op = this.consume().value;
      const right = this.parseBinary();
      left = { kind: "logical", op, left, right };
    }
    return left;
  }

  private parseBinary(): Node {
    const EQUALITY = ["==", "!=", "===", "!=="];
    const RELATIONAL = ["<", ">", "<=", ">="];
    const ADDITIVE = ["+", "-"];
    const MULTIPLICATIVE = ["*", "/", "%"];
    const parseTier = (operators: string[], next: () => Node): (() => Node) => {
      let recurse = next;
      return () => {
        let left = recurse();
        for (;;) {
          const token = this.peek();
          if (token.type !== "punct" || !operators.includes(token.value)) return left;
          const op = this.consume().value;
          left = { kind: "binary", op, left, right: recurse() };
        }
      };
    };
    const multiplicative = parseTier(MULTIPLICATIVE, () => this.parseUnary());
    const additive = parseTier(ADDITIVE, multiplicative);
    const relational = parseTier(RELATIONAL, additive);
    return parseTier(EQUALITY, relational)();
  }

  private parseUnary(): Node {
    const token = this.peek();
    if (token.type === "punct" && (token.value === "!" || token.value === "-" || token.value === "+")) {
      this.consume();
      return { kind: "unary", op: token.value, operand: this.parseUnary() };
    }
    return this.parsePostfix();
  }

  private parsePostfix(): Node {
    let node = this.parsePrimary();
    for (;;) {
      const token = this.peek();
      if (token.type === "punct" && token.value === ".") {
        this.consume();
        const property = this.consume();
        if (property.type !== "ident") throw new Error("expected a property name");
        node = { kind: "member", object: node, property: property.value, computed: false };
        continue;
      }
      if (token.type === "punct" && token.value === "[") {
        this.consume();
        const index = this.parseExpression();
        this.expectPunct("]");
        node = { kind: "index", object: node, index };
        continue;
      }
      if (token.type === "punct" && token.value === "(") {
        this.consume();
        const args: Node[] = [];
        while (!(this.peek().type === "punct" && this.peek().value === ")")) {
          args.push(this.parseAssignment());
          if (!this.acceptPunct(",")) break;
        }
        this.expectPunct(")");
        node = { kind: "call", callee: node, args };
        continue;
      }
      return node;
    }
  }

  private parsePrimary(): Node {
    const token = this.consume();
    if (token.type === "num") {
      const value = Number(token.value);
      if (!Number.isFinite(value)) throw new Error("invalid number literal");
      return { kind: "num", value };
    }
    if (token.type === "str") return { kind: "str", value: token.value };
    if (token.type === "ident") {
      if (token.value === "true" || token.value === "false") return { kind: "bool", value: token.value === "true" };
      if (token.value === "null") return { kind: "null" };
      if (token.value === "undefined") return { kind: "undef" };
      if (["new", "function", "typeof", "delete", "throw", "try", "catch", "eval", "import"].includes(token.value)) {
        throw new Error(`unsupported construct: ${token.value}`);
      }
      return { kind: "ident", name: token.value };
    }
    if (token.type === "punct") {
      if (token.value === "(") {
        const expression = this.parseExpression();
        this.expectPunct(")");
        return expression;
      }
      if (token.value === "{") {
        const entries: Array<{ key: string; value: Node }> = [];
        while (!(this.peek().type === "punct" && this.peek().value === "}")) {
          const key = this.consume();
          if (key.type !== "ident" && key.type !== "str") throw new Error("expected an object key");
          this.expectPunct(":");
          entries.push({ key: key.value, value: this.parseAssignment() });
          if (!this.acceptPunct(",")) break;
        }
        this.expectPunct("}");
        return { kind: "object", entries };
      }
      if (token.value === "[") {
        const elements: Node[] = [];
        while (!(this.peek().type === "punct" && this.peek().value === "]")) {
          elements.push(this.parseAssignment());
          if (!this.acceptPunct(",")) break;
        }
        this.expectPunct("]");
        return { kind: "array", elements };
      }
      if (token.value === "!") return { kind: "unary", op: "!", operand: this.parseUnary() };
    }
    throw new Error(`unexpected token ${JSON.stringify(token.value || token.type)}`);
  }
}

// --- evaluator ---------------------------------------------------------------

class StepCounter {
  private steps = 0;
  constructor(private readonly budget: number) {}
  tick(): void {
    this.steps += 1;
    if (this.steps > this.budget) throw new ExpressionStepLimit();
  }
  get used(): number { return this.steps; }
}

class Scope {
  private values = new Map<string, unknown>();
  constructor(private readonly parent: Scope | null) {}
  lookup(name: string): { found: boolean; value: unknown } {
    let scope: Scope | null = this;
    while (scope) {
      if (scope.values.has(name)) return { found: true, value: scope.values.get(name) };
      scope = scope.parent;
    }
    return { found: false, value: undefined };
  }
  declare(name: string, value: unknown): void { this.values.set(name, value); }
  assign(name: string, value: unknown): boolean {
    let scope: Scope | null = this;
    while (scope) {
      if (scope.values.has(name)) { scope.values.set(name, value); return true; }
      scope = scope.parent;
    }
    return false;
  }
  child(): Scope { return new Scope(this); }
}

interface ReturnSignal {
  __expressionReturn: true;
  value: unknown;
}

function isReturnSignal(error: unknown): error is ReturnSignal {
  return typeof error === "object" && error !== null && (error as { __expressionReturn?: unknown }).__expressionReturn === true;
}

interface ReturnFrame {
  returned: boolean;
  value: unknown;
}

interface HelperState {
  steps: number;
}

function plainData(value: unknown): boolean {
  if (value === null || typeof value !== "object") return typeof value !== "function";
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === Array.prototype;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && Object.getPrototypeOf(value) === Object.prototype;
}

class Evaluator {
  constructor(
    private readonly scope: ExpressionScope,
    private readonly counter: StepCounter,
    private readonly state: HelperState,
  ) {}

  async evaluate(node: Node, scope: Scope): Promise<unknown> {
    this.counter.tick();
    switch (node.kind) {
      case "num": return node.value;
      case "str": return node.value;
      case "bool": return node.value;
      case "null": return null;
      case "undef": return undefined;
      case "ident": {
        if (Object.prototype.hasOwnProperty.call(this.scope.globals, node.name)) {
          const global = this.scope.globals[node.name];
          if (typeof global === "function") throw new Error(`${node.name} is not callable without arguments here`);
          return global;
        }
        const found = scope.lookup(node.name);
        if (!found.found) throw new Error(`unknown identifier ${node.name}`);
        return found.value;
      }
      case "member": {
        const object = await this.evaluate(node.object, scope);
        return this.readMember(object, node.property);
      }
      case "index": {
        const object = await this.evaluate(node.object, scope);
        const key = await this.evaluate(node.index, scope);
        return this.readMember(object, String(key));
      }
      case "call": {
        if (node.callee.kind === "member") {
          const receiver = await this.evaluate(node.callee.object, scope);
          const method = node.callee.property;
          this.assertMember(method);
          const args: unknown[] = [];
          for (const argument of node.args) args.push(await this.evaluate(argument, scope));
          return this.callReceiverMethod(receiver, method, args);
        }
        if (node.callee.kind !== "ident") throw new Error("only named helpers are callable");
        const found = scope.lookup(node.callee.name);
        const helper = found.found ? found.value : this.scope.globals[node.callee.name];
        if (typeof helper !== "function") throw new Error(`${node.callee.name} is not callable`);
        const args: unknown[] = [];
        for (const argument of node.args) args.push(await this.evaluate(argument, scope));
        return await helper(...args);
      }
      case "unary": {
        const operand = await this.evaluate(node.operand, scope);
        if (node.op === "!") return !operand;
        const asNumber = typeof operand === "number" ? operand
          : typeof operand === "boolean" ? (operand ? 1 : 0)
          : typeof operand === "string" ? Number(operand)
          : Number.isNaN(Number(operand)) ? ((): never => { throw new Error("operand is not numeric"); })() : Number(operand);
        return node.op === "-" ? -asNumber : +asNumber;
      }
      case "binary": {
        const left = await this.evaluate(node.left, scope);
        const right = await this.evaluate(node.right, scope);
        return this.binary(node.op, left, right);
      }
      case "logical": {
        const left = await this.evaluate(node.left, scope);
        if (node.op === "&&") return left ? await this.evaluate(node.right, scope) : left;
        return left ? left : await this.evaluate(node.right, scope);
      }
      case "ternary": {
        return (await this.evaluate(node.test, scope))
          ? await this.evaluate(node.consequent, scope)
          : await this.evaluate(node.alternate, scope);
      }
      case "assign": {
        let value = await this.evaluate(node.value, scope);
        if (node.op !== "=") {
          const current = await this.evaluateRead(node.target, scope);
          value = this.binary(node.op === "+=" ? "+" : "-", current, value);
        }
        await this.evaluateWrite(node.target, value, scope);
        return value;
      }
      case "object": {
        const result: Record<string, unknown> = {};
        for (const entry of node.entries) result[entry.key] = await this.evaluate(entry.value, scope);
        return result;
      }
      case "array": {
        const result: unknown[] = [];
        for (const element of node.elements) result.push(await this.evaluate(element, scope));
        return result;
      }
      case "let": {
        scope.declare(node.name, node.value === null ? undefined : await this.evaluate(node.value, scope));
        return undefined;
      }
      case "if": {
        if (await this.evaluate(node.test, scope)) return await this.evaluate(node.consequent, scope);
        return node.alternate ? await this.evaluate(node.alternate, scope) : undefined;
      }
      case "while": {
        this.counter.tick();
        let guard = 0;
        while (await this.evaluate(node.test, scope)) {
          this.counter.tick();
          if (++guard > this.scope.stepBudget) throw new ExpressionStepLimit();
          const bodyStatements = node.body.kind === "block" ? node.body.body : [node.body];
          const frame = await this.evaluateStatements(bodyStatements, scope.child());
          if (frame?.returned) return frame.value;
        }
        return undefined;
      }
      case "for": {
        this.counter.tick();
        const loopScope = scope.child();
        if (node.init) await this.evaluate(node.init, loopScope);
        let guard = 0;
        while (node.test === null || await this.evaluate(node.test, loopScope)) {
          this.counter.tick();
          if (++guard > this.scope.stepBudget) throw new ExpressionStepLimit();
          const bodyStatements = node.body.kind === "block" ? node.body.body : [node.body];
          const frame = await this.evaluateStatements(bodyStatements, loopScope.child());
          if (frame?.returned) return frame.value;
          if (node.update) await this.evaluate(node.update, loopScope);
        }
        return undefined;
      }
      case "return": {
        const returnedValue = node.value === null ? undefined : await this.evaluate(node.value, scope);
        throw { __expressionReturn: true, value: returnedValue } satisfies ReturnSignal;
      }
      case "block": {
        const frame = await this.evaluateStatements(node.body, scope.child());
        if (frame?.returned) return frame.value;
        return undefined;
      }
      case "expr": return await this.evaluate(node.expression, scope);
    }
  }

  private async evaluateStatements(statements: Node[], scope: Scope): Promise<ReturnFrame | null> {
    for (const statement of statements) {
      this.counter.tick();
      try {
        await this.evaluate(statement, scope);
      } catch (error) {
        if (isReturnSignal(error)) return { returned: true, value: error.value };
        throw error;
      }
    }
    return null;
  }

  private assertMember(name: string): void {
    if (BLOCKED_MEMBERS.has(name)) throw new Error(`access to ${name} is not permitted`);
  }

  private readMember(object: unknown, property: string): unknown {
    if (object === null || object === undefined) throw new Error("cannot read properties of null");
    this.assertMember(property);
    if (!plainData(object)) throw new Error("member access is limited to plain data and helper receivers");
    if (isPlainObject(object) || Array.isArray(object)) {
      if (!Object.prototype.hasOwnProperty.call(object, property) && !(object instanceof Array && /^\d+$/.test(property))) {
        if (!(property === "length" && Array.isArray(object))) return undefined;
      }
    }
    const value = (object as Record<string, unknown>)[property];
    if (typeof value === "function") throw new Error(`${property} is not callable on plain data`);
    return value;
  }

  private callReceiverMethod(receiver: unknown, method: string, args: unknown[]): unknown {
    this.assertMember(method);
    if (receiver === null || receiver === undefined) throw new Error("cannot call methods on null");
    if (["map", "filter", "find", "some", "every", "reduce"].includes(method)) {
      throw new Error(`${method} needs a function argument; use a while loop over indexes instead`);
    }
    if (!METHOD_ALLOWLIST.has(method)) {
      throw new Error(`method ${method} is not allowed`);
    }
    if (receiver === null || receiver === undefined) throw new Error("cannot call methods on null");
    const callOn = (host: object): unknown => {
      const result = (host as unknown as Record<string, (...parameters: unknown[]) => unknown>)[method](
        ...args.map((parameter) => (typeof parameter === "function" ? undefined
          : typeof parameter === "object" && parameter !== null && !Array.isArray(parameter)
            ? JSON.stringify(parameter) : parameter)),
      );
      if (typeof result === "function" || (typeof result === "object" && result !== null && !Array.isArray(result))) {
        throw new Error(`${method} returned a non-primitive value`);
      }
      return result;
    };
    if (typeof receiver === "string") return callOn(receiver as unknown as object);
    if (Array.isArray(receiver)) return callOn(receiver as unknown as object);
    if (typeof receiver === "object") {
      if (method === "hasOwnProperty") {
        return Object.prototype.hasOwnProperty.call(receiver, String(args[0] ?? ""));
      }
      throw new Error(`methods beyond data helpers are not allowed on plain objects`);
    }
    throw new Error("methods are allowed on strings, arrays and plain objects only");
  }

  private binary(op: string, left: unknown, right: unknown): unknown {
    switch (op) {
      case "+":
        if (typeof left === "string" || typeof right === "string") return `${String(left === null ? "" : left)}${String(right === null ? "" : right)}`;
        return this.asNumber(left) + this.asNumber(right);
      case "-": return this.asNumber(left) - this.asNumber(right);
      case "*": return this.asNumber(left) * this.asNumber(right);
      case "/": return this.asNumber(left) / this.asNumber(right);
      case "%": return this.asNumber(left) % this.asNumber(right);
      case "==": return left == right; // eslint-disable-line eqeqeq
      case "!=": return left != right; // eslint-disable-line eqeqeq
      case "===": return left === right;
      case "!==": return left !== right;
      case "<":
      case "<=":
      case ">":
      case ">=":
        if (typeof left === "string" && typeof right === "string") {
          return op === "<" ? left < right : op === "<=" ? left <= right : op === ">" ? left > right : left >= right;
        }
        return op === "<" ? this.asNumber(left) < this.asNumber(right)
          : op === "<=" ? this.asNumber(left) <= this.asNumber(right)
          : op === ">" ? this.asNumber(left) > this.asNumber(right)
          : this.asNumber(left) >= this.asNumber(right);
      default: throw new Error(`unsupported operator ${op}`);
    }
  }

  private asNumber(value: unknown): number {
    if (typeof value === "number") return value;
    if (value === null || value === undefined) return 0;
    if (typeof value === "boolean") return value ? 1 : 0;
    if (typeof value === "string") {
      const parsed = Number(value);
      if (Number.isNaN(parsed)) throw new Error(`cannot use ${JSON.stringify(value)} as a number`);
      return parsed;
    }
    throw new Error("cannot use a complex value as a number");
  }

  private async evaluateRead(target: Node, scope: Scope): Promise<unknown> {
    if (target.kind === "ident") {
      const found = scope.lookup(target.name);
      if (found.found) return found.value;
      if (Object.prototype.hasOwnProperty.call(this.scope.globals, target.name)) {
        const global = this.scope.globals[target.name];
        if (typeof global === "function") throw new Error(`${target.name} is not assignable`);
        return global;
      }
      throw new Error(`unknown identifier ${target.name}`);
    }
    if (target.kind === "member") {
      const object = await this.evaluate(target.object, scope);
      return this.readMember(object, target.property);
    }
    if (target.kind === "index") {
      const object = await this.evaluate(target.object, scope);
      const key = await this.evaluate(target.index, scope);
      return this.readMember(object, String(key));
    }
    throw new Error("invalid assignment target");
  }

  private async evaluateWrite(target: Node, value: unknown, scope: Scope): Promise<void> {
    if (target.kind === "ident") {
      if (!scope.assign(target.name, value)) {
        if (Object.prototype.hasOwnProperty.call(this.scope.globals, target.name)) {
          if (typeof this.scope.globals[target.name] === "function") throw new Error(`${target.name} is not assignable`);
          this.scope.globals[target.name] = value;
          return;
        }
        scope.declare(target.name, value);
      }
      return;
    }
    if (target.kind === "member") {
      const object = await this.evaluate(target.object, scope);
      if (!isPlainObject(object)) throw new Error("assignment is allowed on plain objects from the context only");
      this.assertMember(target.property);
      (object as Record<string, unknown>)[target.property] = value;
      return;
    }
    if (target.kind === "index") {
      const object = await this.evaluate(target.object, scope);
      const key = await this.evaluate(target.index, scope);
      if (Array.isArray(object)) {
        const index = Number(key);
        if (!Number.isInteger(index) || index < 0 || index > 100_000) throw new Error("invalid array index");
        object[index] = value;
        return;
      }
      if (!isPlainObject(object)) throw new Error("assignment is allowed on plain objects from the context only");
      this.assertMember(String(key));
      (object as Record<string, unknown>)[String(key)] = value;
      return;
    }
    throw new Error("invalid assignment target");
  }
}

function validateSource(source: string): void {
  if (typeof source !== "string" || source.trim().length === 0) throw new Error("expression body is required");
  if (source.length > MAX_SOURCE_LENGTH) throw new Error(`expression may not exceed ${MAX_SOURCE_LENGTH} characters`);
}

/** Parse and evaluate; returns { value, steps }. */
export async function evaluateExpression(
  source: string,
  buildGlobals: (state: HelperState) => Record<string, unknown>,
  stepBudget = DEFAULT_STEP_BUDGET,
): Promise<{ value: unknown; steps: number }> {
  validateSource(source);
  const counter = new StepCounter(stepBudget);
  const tokens = tokenize(source);
  const program = new Parser(tokens).parseProgram();
  const state: HelperState = { steps: 0 };
  const evaluator = new Evaluator({ globals: buildGlobals(state), stepBudget }, counter, state);
  const scope = new Scope(null);
  try {
    const value = await evaluator.evaluate(program, scope);
    return { value, steps: counter.used };
  } catch (error) {
    if (isReturnSignal(error)) return { value: error.value, steps: counter.used };
    throw error;
  }
}
