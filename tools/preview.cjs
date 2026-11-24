// Isolated browser-test preview, never a deployment or normal development database.
Object.assign(process.env, {
  NODE_ENV: "test",
  DB_HOST: "127.0.0.1",
  DB_PORT: "55432",
  DB_USER: "mmms_test",
  DB_PASSWORD: "mmms_test_local",
  CONTROL_DB_NAME: "neola_subscriptions_test",
  DB_SSL: "false",
  CONTROL_ENCRYPTION_KEY: "a".repeat(64),
});
const express = require("express");
const path = require("node:path");
const { randomUUID, randomBytes } = require("node:crypto");
const { query, pool } = require("../src/database");
const { password } = require("../src/security");
const { createApp } = require("../src/server");
async function main() {
  const username = "preview-" + randomUUID().slice(0, 8),
    secret = randomBytes(18).toString("base64url");
  await query(
    "INSERT INTO control_users(id,username,display_name,password_hash,role) VALUES($1,$2,'Browser audit owner',$3,'platform_owner')",
    [randomUUID(), username, await password(secret)],
  );
  const app = express(),
    api = createApp(),
    directory = path.resolve(
      __dirname,
      "../../subscription-frontend/dist/subscriptions/browser",
    );
  app.use((req, res, next) =>
    req.path.startsWith("/api/control") ? api(req, res, next) : next(),
  );
  app.use(express.static(directory));
  app.get("*", (req, res) => res.sendFile(path.join(directory, "index.html")));
  const server = app.listen(17430, "127.0.0.1", () =>
    console.log(
      JSON.stringify({
        url: "http://127.0.0.1:17430",
        username,
        password: secret,
        pid: process.pid,
        database: process.env.CONTROL_DB_NAME,
      }),
    ),
  );
  for (const signal of ["SIGINT", "SIGTERM"])
    process.on(signal, () =>
      server.close(() => pool.end().then(() => process.exit(0))),
    );
}
main().catch((e) => {
  console.error(e.message);
  process.exitCode = 1;
});
