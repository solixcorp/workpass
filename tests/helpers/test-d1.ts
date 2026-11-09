import { Database } from "bun:sqlite";

/**
 * Minimal async D1-style adapter over bun:sqlite for tests: only the surface
 * this codebase uses (prepare().bind().run/first/all, batch, meta.changes).
 * Batch runs sequentially, not in a real transaction — statements under test
 * must rely on guarded SQL, not on adapter atomicity.
 */
export class TestD1 {
  readonly inner: Database;

  constructor(filename = ":memory:") {
    this.inner = new Database(filename);
  }

  prepare(sql: string) {
    const bindable = (params: unknown[]) => {
      const execute = () => {
        const statement = this.inner.prepare(sql);
        return statement;
      };
      return {
        run: async () => {
          const info = execute().run(...(params as never[]));
          return { meta: { changes: info.changes } };
        },
        first: async <T = Record<string, unknown>>() =>
          (execute().get(...(params as never[])) as T | undefined) ?? null,
        all: async <T = Record<string, unknown>>() =>
          ({ results: execute().all(...(params as never[])) as T[] }),
      };
    };
    return {
      ...bindable([]),
      bind: (...params: unknown[]) => bindable(params),
    };
  }

  async batch<T>(statements: Array<{ run: () => Promise<T> }>): Promise<T[]> {
    const results: T[] = [];
    for (const statement of statements) results.push(await statement.run());
    return results;
  }

  exec(sql: string): void {
    this.inner.exec(sql);
  }
}
