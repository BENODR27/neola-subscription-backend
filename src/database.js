const fs = require("node:fs/promises");
const path = require("node:path");
require("dotenv").config();
const { Pool, Client } = require("pg");
const database = process.env.CONTROL_DB_NAME || "neola_subscriptions";
const connection = {
  host: process.env.DB_HOST || "127.0.0.1",
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl:
    process.env.DB_SSL === "true"
      ? {
          rejectUnauthorized:
            process.env.DB_SSL_REJECT_UNAUTHORIZED !== "false",
        }
      : false,
};
const pool = new Pool({ ...connection, database, max: 10 });
const query = (sql, values = [], client = pool) => client.query(sql, values);
async function transaction(work) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await work(client);
    await client.query("COMMIT");
    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}
async function migrate() {
  await transaction(async (client) => {
    await client.query("SELECT pg_advisory_xact_lock(70202026)");
    await client.query(
      "CREATE TABLE IF NOT EXISTS control_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())",
    );
    const directory = path.join(__dirname, "../migrations");
    for (const name of (await fs.readdir(directory))
      .filter((name) => name.endsWith(".sql"))
      .sort()) {
      if (
        (
          await client.query("SELECT 1 FROM control_migrations WHERE name=$1", [
            name,
          ])
        ).rowCount
      )
        continue;
      await client.query(await fs.readFile(path.join(directory, name), "utf8"));
      await client.query("INSERT INTO control_migrations(name) VALUES($1)", [
        name,
      ]);
      console.log("Applied control migration", name);
    }
  });
}
async function create() {
  if (!/^[a-z][a-z0-9_]{2,62}$/.test(database))
    throw new Error("Invalid CONTROL_DB_NAME");
  const client = new Client({ ...connection, database: "postgres" });
  try {
    await client.connect();
    if (
      !(
        await client.query("SELECT 1 FROM pg_database WHERE datname=$1", [
          database,
        ])
      ).rowCount
    )
      await client.query(`CREATE DATABASE "${database}"`);
  } finally {
    await client.end();
  }
}
if (require.main === module)
  (process.argv[2] === "create" ? create() : migrate())
    .catch((error) => {
      console.error(error.message);
      process.exitCode = 1;
    })
    .finally(() => pool.end());
module.exports = { pool, query, transaction, migrate };
