import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { migrate } from "./migrate.js";
import { createTestDatabase, type TestDatabase } from "./test-db.js";

let db: TestDatabase;
let dir: string;

beforeEach(async () => {
  db = await createTestDatabase();
  dir = await mkdtemp(join(tmpdir(), "messager-migrations-"));
});

afterEach(async () => {
  await db.drop();
  await rm(dir, { recursive: true, force: true });
});

async function tableExists(name: string): Promise<boolean> {
  const result = await db.pool.query("SELECT to_regclass($1) AS oid", [name]);
  return result.rows[0].oid !== null;
}

describe("migrate", () => {
  it("applies migration files in filename order", async () => {
    // 002 depends on 001, so wrong ordering would fail.
    await writeFile(join(dir, "002_b.sql"), "ALTER TABLE a ADD COLUMN extra text;");
    await writeFile(join(dir, "001_a.sql"), "CREATE TABLE a (id int);");

    const result = await migrate(db.pool, dir);

    expect(result.applied).toEqual(["001_a.sql", "002_b.sql"]);
    const columns = await db.pool.query(
      "SELECT column_name FROM information_schema.columns WHERE table_name = 'a' ORDER BY column_name",
    );
    expect(columns.rows.map((r) => r.column_name)).toEqual(["extra", "id"]);
  });

  it("does nothing on a second run", async () => {
    await writeFile(join(dir, "001_a.sql"), "CREATE TABLE a (id int);");
    await migrate(db.pool, dir);

    const second = await migrate(db.pool, dir);

    expect(second.applied).toEqual([]);
  });

  it("applies only new files on a later run", async () => {
    await writeFile(join(dir, "001_a.sql"), "CREATE TABLE a (id int);");
    await migrate(db.pool, dir);
    await writeFile(join(dir, "002_b.sql"), "CREATE TABLE b (id int);");

    const second = await migrate(db.pool, dir);

    expect(second.applied).toEqual(["002_b.sql"]);
    expect(await tableExists("b")).toBe(true);
  });

  it("rolls back a failing migration completely and keeps earlier ones", async () => {
    await writeFile(join(dir, "001_a.sql"), "CREATE TABLE a (id int);");
    await writeFile(join(dir, "002_bad.sql"), "CREATE TABLE b (id int); SELECT * FROM does_not_exist;");

    await expect(migrate(db.pool, dir)).rejects.toThrow(/002_bad\.sql/);

    expect(await tableExists("a")).toBe(true);
    expect(await tableExists("b")).toBe(false);
    const recorded = await db.pool.query("SELECT name FROM schema_migrations ORDER BY name");
    expect(recorded.rows.map((r) => r.name)).toEqual(["001_a.sql"]);
  });

  it("refuses to run if an already-applied migration file was edited", async () => {
    await writeFile(join(dir, "001_a.sql"), "CREATE TABLE a (id int);");
    await migrate(db.pool, dir);
    await writeFile(join(dir, "001_a.sql"), "CREATE TABLE a (id bigint);");

    await expect(migrate(db.pool, dir)).rejects.toThrow(/001_a\.sql.*changed/);
  });

  it("ignores files that are not numbered .sql migrations", async () => {
    await writeFile(join(dir, "001_a.sql"), "CREATE TABLE a (id int);");
    await writeFile(join(dir, "notes.txt"), "not sql");
    await writeFile(join(dir, "draft.sql"), "this is not valid sql");

    const result = await migrate(db.pool, dir);

    expect(result.applied).toEqual(["001_a.sql"]);
  });
});
