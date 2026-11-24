"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { randomUUID } = require("node:crypto");
const bcrypt = require("bcryptjs");

function seedEnvironment(env = process.env) {
  const values = { ...env };
  const file = path.resolve(".env.seed");
  if (fs.existsSync(file))
    for (const line of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
      const match =
        /^(CONTROL_OWNER_USERNAME|CONTROL_OWNER_PASSWORD|CONTROL_OWNER_NAME|CONTROL_SEED_TEST_USERS|CONTROL_APPROVER_USERNAME|CONTROL_APPROVER_PASSWORD|CONTROL_CUSTOMER_USERNAME|CONTROL_CUSTOMER_PASSWORD|CONTROL_CUSTOMER_NAME|CONTROL_CUSTOMER_EMAIL)=(.*)$/.exec(
          line,
        );
      if (match && values[match[1]] === undefined) values[match[1]] = match[2];
    }
  return values;
}

async function seedBase(database, env = process.env) {
  return database.transaction(async (db) => {
    await db.query("SELECT pg_advisory_xact_lock(70202026)");
    const testUsers = env.CONTROL_SEED_TEST_USERS === "true";
    if (testUsers && env.NODE_ENV !== "development" && env.NODE_ENV !== "test")
      throw Error(
        "Optional approver/customer test users require NODE_ENV=development or test",
      );
    const accounts = [
      {
        role: "platform_owner",
        username: env.CONTROL_OWNER_USERNAME,
        password: env.CONTROL_OWNER_PASSWORD,
        name: env.CONTROL_OWNER_NAME || "NeoLA Platform Owner",
      },
    ];
    if (testUsers)
      accounts.push(
        {
          role: "approver",
          username: env.CONTROL_APPROVER_USERNAME,
          password: env.CONTROL_APPROVER_PASSWORD,
          name: "Test Approver",
        },
        {
          role: "customer_owner",
          username: env.CONTROL_CUSTOMER_USERNAME,
          password: env.CONTROL_CUSTOMER_PASSWORD,
          name: env.CONTROL_CUSTOMER_NAME || "Test Customer",
        },
      );
    const names = new Set();
    for (const account of accounts) {
      account.username = String(account.username || "")
        .trim()
        .toLowerCase();
      if (!account.username || account.username.length > 180)
        throw Error(
          "Configure a valid username for each requested base account in .env.seed",
        );
      if (names.has(account.username))
        throw Error("Owner, approver and customer usernames must be different");
      names.add(account.username);
      account.existing = (
        await db.query(
          "SELECT id,role,customer_id FROM control_users WHERE username=$1",
          [account.username],
        )
      ).rows[0];
      if (account.existing && account.existing.role !== account.role)
        throw Error(
          "A configured seed username already has another role; refusing to change access",
        );
      if (
        !account.existing &&
        (typeof account.password !== "string" ||
          account.password.length < 12 ||
          Buffer.byteLength(account.password) > 72)
      )
        throw Error(
          "Every new base account requires its configured password with 12–72 bytes",
        );
    }
    if (
      !accounts[0].existing &&
      (await db.query("SELECT 1 FROM control_users LIMIT 1")).rowCount
    )
      throw Error(
        "Console already has users; use the existing owner instead of creating another bootstrap owner",
      );
    const result = { created: 0, preserved: 0 };
    for (const account of accounts) {
      if (account.existing) {
        result.preserved++;
        continue;
      }
      let customerId = null;
      if (account.role === "customer_owner") {
        customerId = randomUUID();
        await db.query(
          "INSERT INTO control_customers(id,name,contact_email,status) VALUES($1,$2,$3,'pending')",
          [
            customerId,
            account.name,
            env.CONTROL_CUSTOMER_EMAIL || "customer@example.invalid",
          ],
        );
      }
      await db.query(
        "INSERT INTO control_users(id,username,display_name,password_hash,role,customer_id) VALUES($1,$2,$3,$4,$5,$6)",
        [
          randomUUID(),
          account.username,
          account.name,
          await bcrypt.hash(account.password, 12),
          account.role,
          customerId,
        ],
      );
      result.created++;
    }
    return result;
  });
}

if (require.main === module) {
  const seedValues = seedEnvironment();
  const database = require("./database");
  seedBase(database, { ...process.env, ...seedValues })
    .then((result) => console.log("Base Console seed:", JSON.stringify(result)))
    .catch((error) => {
      console.error(error.message);
      process.exitCode = 1;
    })
    .finally(() => database.pool.end());
}

module.exports = { seedBase, seedEnvironment };
