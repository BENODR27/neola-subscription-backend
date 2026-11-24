const { spawnSync } = require("node:child_process");
const path = require("node:path");
const { Client } = require("pg");
const env = {
  ...process.env,
  NODE_ENV: "test",
  DB_HOST: "127.0.0.1",
  DB_PORT: "55432",
  DB_USER: process.env.CONTROL_TEST_DB_USER || "mmms_test",
  DB_PASSWORD: process.env.CONTROL_TEST_DB_PASSWORD || "mmms_test_local",
  DB_SSL: "false",
  CONTROL_DB_NAME: "neola_subscriptions_test",
  DB_NAME: "neola_control_iam_test",
  CONTROL_INTEGRATION_TEST: "true",
  CONTROL_ENCRYPTION_KEY: "a".repeat(64),
  JWT_SECRET: "isolated-control-integration-test-secret-only",
  CONTROL_PLANE_MODE: "subscription",
  CONTROL_ENFORCED_APPLICATIONS: "MMMS,MASTERS",
  MMMS_DB_NAME: "neola_control_mmms_test",
};
async function main() {
  const client = new Client({
    host: env.DB_HOST,
    port: Number(env.DB_PORT),
    user: env.DB_USER,
    password: env.DB_PASSWORD,
    database: "postgres",
  });
  try {
    await client.connect();
    for (const name of [env.CONTROL_DB_NAME, env.DB_NAME, env.MMMS_DB_NAME])
      if (
        !(
          await client.query("SELECT 1 FROM pg_database WHERE datname=$1", [
            name,
          ])
        ).rowCount
      )
        await client.query(`CREATE DATABASE "${name}"`);
  } finally {
    await client.end();
  }
  const cwd = path.resolve(__dirname, ".."),
    iam = path.resolve(cwd, "../authguardv2-node");
  for (const [args, directory] of [
    [["src/database.js", "migrate"], cwd],
    [
      [
        path.join(iam, "node_modules/sequelize-cli/lib/sequelize"),
        "db:migrate",
      ],
      iam,
    ],
    [["--test", "test/workflows.integration.test.js"], cwd],
    [
      [
        path.resolve(
          cwd,
          "../mmms-backend/node_modules/sequelize-cli/lib/sequelize",
        ),
        "db:migrate",
      ],
      path.resolve(cwd, "../mmms-backend"),
    ],
    [["--test", "test/completion.integration.test.js"], cwd],
    [["--test", "test/iam-commercial-workflow.integration.test.js"], cwd],
  ]) {
    if (
      process.argv.includes("--workflow") &&
      args.includes("--test") &&
      !args.includes("test/iam-commercial-workflow.integration.test.js")
    )
      continue;
    const result = spawnSync(process.execPath, args, {
      cwd: directory,
      env,
      stdio: "inherit",
    });
    if (result.status !== 0) throw new Error("Integration check failed");
  }
}
main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
