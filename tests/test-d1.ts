import { Database } from "bun:sqlite";

/**
 * An in-memory bun:sqlite instance dressed as the D1 API surface the platform
 * (better-auth's Kysely D1 dialect) actually calls: prepare/bind/all/run/
 * first/raw/batch/exec. Mutation statements report meta.changes so the
 * driver's numAffectedRows logic behaves like production D1. Detection on the
 * library side keys on the presence of prepare/batch/exec, exactly as D1 does.
 */
export interface TestD1 {
  db: D1Database;
  sqlite: Database;
}

export function createTestD1(): TestD1 {
  const sqlite = new Database(":memory:");
  sqlite.exec("PRAGMA foreign_keys = ON");
  const MUTATION = /^(INSERT|UPDATE|DELETE|REPLACE|CREATE|DROP|ALTER|VACUUM)\b/i;

  type Statement = {
    bind: (...args: unknown[]) => Promise<unknown>;
    all: (col?: string) => Promise<unknown>;
    run: () => Promise<unknown>;
    first: (col?: string) => Promise<unknown>;
    raw: () => Promise<unknown>;
    values: () => Promise<unknown>;
  };

  const execute = (sql: string, params: unknown[]) => {
    const statement = sqlite.prepare(sql);
    if (!MUTATION.test(sql) || /\bRETURNING\b/i.test(sql)) {
      const results = statement.all(...(params as never[])) as Record<string, unknown>[];
      return { success: true, results, meta: { changes: 0, last_row_id: 0 } };
    }
    const result = statement.run(...(params as never[]));
    return { success: true, results: [] as Record<string, unknown>[], meta: { changes: Number(result.changes), last_row_id: Number(result.lastInsertRowid) } };
  };

  const make = (sql: string, params: unknown[]): Statement => {
    const self = {} as Statement;
    self.bind = (...args: unknown[]) => statementFor(sql, args);
    self.all = async (col?: string) => {
      if (col === undefined) return execute(sql, params);
      const row = execute(sql, params).results[0] as Record<string, unknown> | undefined;
      const value = row?.[col];
      return { results: value === undefined ? [] : [value], meta: { changes: 0, last_row_id: 0 } };
    };
    self.run = async () => execute(sql, params);
    self.first = async (col?: string) => {
      const row = execute(sql, params).results[0] as Record<string, unknown> | undefined;
      if (!row) return null;
      return col === undefined ? row : (row[col] ?? null);
    };
    self.raw = async () => execute(sql, params).results.map((row) => Object.values(row));
    self.values = self.raw;
    return self;
  };

  const statementFor = (sql: string, params: unknown[]): Statement => make(sql, params);

  const db = {
    prepare: (sql: string): Statement => make(sql, []),
    async batch<Input>(statements: Promise<Input>[] | Input[]): Promise<unknown[]> {
      return Promise.all((statements as unknown as Statement[]).map((entry) => entry.run()));
    },
    async exec(sql: string): Promise<void> {
      sqlite.exec(sql);
    },
  };

  return { db: db as unknown as D1Database, sqlite };
}
