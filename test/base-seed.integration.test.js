const { test } = require("node:test");
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const { seedBase } = require("../src/seed-base");

test(
  "base Console seed separates roles, rolls back invalid input and never resets users",
  {
    skip: process.env.BASE_SEED_INTEGRATION_TEST !== "true",
  },
  async () => {
    assert.equal(process.env.DB_HOST, "127.0.0.1");
    assert.match(process.env.CONTROL_DB_NAME, /^neola_seed_control_\d+_test$/);
    const db = require("../src/database");
    const env = {
      NODE_ENV: "development",
      CONTROL_OWNER_USERNAME: "seed.owner",
      CONTROL_OWNER_PASSWORD: "Seed-owner-password-2026!",
      CONTROL_SEED_TEST_USERS: "true",
      CONTROL_APPROVER_USERNAME: "seed.approver",
      CONTROL_APPROVER_PASSWORD: "Seed-approver-password-2026!",
      CONTROL_CUSTOMER_USERNAME: "seed.customer",
      CONTROL_CUSTOMER_PASSWORD: "Seed-customer-password-2026!",
    };
    const count = async (table) =>
      Number((await db.query(`SELECT count(*) AS n FROM ${table}`)).rows[0].n);
    try {
      assert.equal(await count("control_users"), 0);
      await assert.rejects(
        seedBase(db, { ...env, CONTROL_CUSTOMER_PASSWORD: "short" }),
        /12–72/,
      );
      assert.equal(await count("control_users"), 0);
      assert.equal(await count("control_customers"), 0);
      await assert.rejects(
        seedBase(db, { ...env, NODE_ENV: "production" }),
        /require NODE_ENV/,
      );
      await assert.rejects(
        seedBase(db, {
          ...env,
          CONTROL_APPROVER_USERNAME: env.CONTROL_OWNER_USERNAME.toUpperCase(),
        }),
        /must be different/,
      );
      const parallel = await Promise.all([
        seedBase(db, env),
        seedBase(db, env),
      ]);
      assert.equal(
        parallel.reduce((sum, result) => sum + result.created, 0),
        3,
      );
      assert.equal(
        parallel.reduce((sum, result) => sum + result.preserved, 0),
        3,
      );
      const original = (
        await db.query("SELECT * FROM control_users ORDER BY username")
      ).rows;
      assert.deepEqual(
        new Set(original.map((user) => user.role)),
        new Set(["platform_owner", "approver", "customer_owner"]),
      );
      const customer = original.find((user) => user.role === "customer_owner");
      assert(customer.customer_id);
      assert.equal(
        (
          await db.query("SELECT status FROM control_customers WHERE id=$1", [
            customer.customer_id,
          ])
        ).rows[0].status,
        "pending",
      );
      const owner = original.find((user) => user.role === "platform_owner");
      assert(
        await bcrypt.compare(env.CONTROL_OWNER_PASSWORD, owner.password_hash),
      );
      await db.query("UPDATE control_users SET enabled=false WHERE id=$1", [
        owner.id,
      ]);
      assert.deepEqual(
        await seedBase(db, {
          ...env,
          CONTROL_OWNER_PASSWORD: "Different-owner-password-2026!",
        }),
        { created: 0, preserved: 3 },
      );
      const repeated = (
        await db.query("SELECT * FROM control_users ORDER BY username")
      ).rows;
      for (const user of repeated) {
        const previous = original.find((row) => row.id === user.id);
        assert.equal(user.password_hash, previous.password_hash);
        assert.equal(user.role, previous.role);
        assert.equal(user.customer_id, previous.customer_id);
      }
      assert.equal(
        repeated.find((user) => user.id === owner.id).enabled,
        false,
      );
      assert.equal(await count("control_customers"), 1);
      assert.equal(await count("control_plans"), 0);
      assert.equal(await count("control_subscriptions"), 0);
      assert.equal(await count("control_instances"), 0);
      await assert.rejects(
        seedBase(db, {
          ...env,
          CONTROL_OWNER_USERNAME: "another.owner",
          CONTROL_SEED_TEST_USERS: "false",
        }),
        /already has users/,
      );
      await assert.rejects(
        seedBase(db, {
          ...env,
          CONTROL_OWNER_USERNAME: "seed.approver",
          CONTROL_SEED_TEST_USERS: "false",
        }),
        /another role/,
      );
      await db.query(
        "UPDATE control_users SET role='platform_staff' WHERE id=$1",
        [owner.id],
      );
      await assert.rejects(
        seedBase(db, {
          ...env,
          CONTROL_OWNER_USERNAME: "missing.owner",
          CONTROL_SEED_TEST_USERS: "false",
        }),
        /already has users/,
      );
      assert.equal(await count("control_users"), 3);
    } finally {
      await db.pool.end();
    }
  },
);
