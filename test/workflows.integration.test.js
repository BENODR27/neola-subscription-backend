const { test } = require("node:test");
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
test(
  "subscription purchase, trial, customer isolation and ERP enforcement",
  { skip: process.env.CONTROL_INTEGRATION_TEST !== "true" },
  async (t) => {
    const { createApp } = require("../src/server");
    const { query, pool } = require("../src/database");
    const bcrypt = require("bcryptjs");
    const suffix = randomUUID().slice(0, 8),
      password = "Isolated-test-password-2026!";
    const ownerId = randomUUID();
    await query(
      "INSERT INTO control_users(id,username,display_name,password_hash,role) VALUES($1,$2,'Test owner',$3,'platform_owner')",
      [ownerId, `owner-${suffix}`, await bcrypt.hash(password, 12)],
    );
    const server = createApp().listen(0, "127.0.0.1");
    await new Promise((r) => server.once("listening", r));
    const origin = `http://127.0.0.1:${server.address().port}`;
    process.env.CONTROL_API_URL = origin;
    const iamApp = require("../../authguardv2-node/src/app");
    const iam = iamApp.listen(0, "127.0.0.1");
    await new Promise((r) => iam.once("listening", r));
    const iamOrigin = `http://127.0.0.1:${iam.address().port}`;
    process.env.CONTROL_ERP_ALLOWED_ORIGINS = iamOrigin;
    process.env.IAM_API_URL = iamOrigin;
    const resetCache =
      require("../../authguardv2-node/src/services/subscription-access").resetCache;
    const clients = {};
    async function request(
      path,
      method = "GET",
      body,
      account,
      expected = 200,
      raw = false,
    ) {
      const session = clients[account] || {};
      const response = await fetch(origin + "/api/control" + path, {
        method,
        headers: {
          "Content-Type": "application/json",
          ...(session.cookie
            ? { Cookie: session.cookie, "X-CSRF-Token": session.csrfToken }
            : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      const result = response.status === 204 ? {} : await response.json();
      assert.equal(
        response.status,
        expected,
        `${method} ${path}: ${JSON.stringify(result)}`,
      );
      if (path === "/auth/login" && expected === 200)
        clients[account] = {
          ...result,
          cookie: response.headers.get("set-cookie").split(";")[0],
        };
      return raw ? response : result;
    }
    try {
      await request(
        "/auth/login",
        "POST",
        { username: `owner-${suffix}`, password },
        "owner",
      );
      await request(
        "/operators",
        "POST",
        {
          username: `approver-${suffix}`,
          display_name: "Independent approver",
          password,
          role: "approver",
        },
        "owner",
        201,
      );
      await request(
        "/auth/login",
        "POST",
        { username: `approver-${suffix}`, password },
        "approver",
      );
      for (const name of ["a", "b"]) {
        await request(
          "/auth/register",
          "POST",
          {
            username: `${name}-${suffix}`,
            password,
            display_name: `Customer ${name}`,
            name: `Customer ${name}-${suffix}`,
            email: `${name}@example.com`,
          },
          null,
          201,
        );
        await request(
          "/auth/login",
          "POST",
          { username: `${name}-${suffix}`, password },
          name,
        );
      }
      const customerId = clients.a.user.customer_id,
        otherId = clients.b.user.customer_id;
      let instance, otherInstance, plan;
      await t.test(
        "customer records are isolated and CSRF is required",
        async () => {
          const rejectedOrigin = await fetch(
            origin + "/api/control/auth/login",
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
                Origin: "https://untrusted.example",
              },
              body: JSON.stringify({ username: `owner-${suffix}`, password }),
            },
          );
          assert.equal(rejectedOrigin.status, 403);
          await request(
            "/auth/login",
            "POST",
            { username: `missing-${suffix}`, password },
            "bad",
            401,
          );
          const own = await request("/customers", "GET", null, "a");
          assert.equal(own.total, 1);
          assert.equal(own.items[0].id, customerId);
          await request(
            `/instances?customer_id=${otherId}`,
            "GET",
            null,
            "a",
            403,
          );
          await request("/operators", "GET", null, "a", 403);
          const response = await fetch(origin + "/api/control/requests", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Cookie: clients.a.cookie,
            },
            body: "{}",
          });
          assert.equal(response.status, 403);
        },
      );
      await t.test(
        "catalog, instance keys and permission ceilings",
        async () => {
          await request(
            "/applications/MMMS",
            "PUT",
            {
              name: "MMMS",
              landing_route: "/mmms",
              required_permission: "MMMS-APP",
              navigation: [
                {
                  label: "Machines",
                  link: "/mmms/machines",
                  icon: "bi-tools",
                  permission: "MMMS-MACHINES-VIEW",
                },
              ],
            },
            "owner",
          );
          for (const code of ["MMMS-APP", "MMMS-MACHINES-VIEW"])
            await request(
              `/permissions/${code}`,
              "PUT",
              { application_code: "MMMS" },
              "owner",
            );
          await request(
            "/permissions/superadmin",
            "PUT",
            { application_code: "MMMS" },
            "owner",
            400,
          );
          plan = await request(
            "/plans",
            "POST",
            {
              name: `Plan-${suffix}`,
              price_minor: 10000,
              currency: "USD",
              duration_months: 1,
              trial_days: 7,
              max_users: 10000,
              published: true,
              entitlements: {
                applications: ["MMMS"],
                permissions: ["MMMS-APP", "MMMS-MACHINES-VIEW"],
              },
            },
            "owner",
            201,
          );
          instance = await request(
            "/instances",
            "POST",
            {
              customer_id: customerId,
              name: `ERP-${suffix}`,
              api_origin: iamOrigin,
            },
            "owner",
            201,
          );
          otherInstance = await request(
            "/instances",
            "POST",
            { customer_id: otherId, name: "Other ERP" },
            "owner",
            201,
          );
          await request(
            "/instances",
            "POST",
            {
              customer_id: customerId,
              name: "Unsafe",
              api_origin: "http://169.254.169.254",
            },
            "owner",
            400,
          );
          const listed = await request("/instances", "GET", null, "a");
          assert.equal(listed.items[0].encrypted_key, undefined);
          assert.equal(listed.items[0].key_hash, undefined);
          const wrongKey = await fetch(
            `${origin}/api/control/internal/instances/${otherInstance.id}/entitlements`,
            { headers: { Authorization: `Bearer ${instance.activation_key}` } },
          );
          assert.equal(wrongKey.status, 401);
          process.env.CONTROL_INSTANCE_ID = instance.id;
          process.env.CONTROL_INSTANCE_KEY = instance.activation_key;
        },
      );
      let trialRequest, purchaseRequest;
      await t.test(
        "manual trial approval, duplicate prevention and customer roles",
        async () => {
          trialRequest = await request(
            "/requests",
            "POST",
            { instance_id: instance.id, plan_id: plan.id, kind: "trial" },
            "a",
            201,
          );
          await request(
            "/requests",
            "POST",
            { instance_id: instance.id, plan_id: plan.id, kind: "trial" },
            "a",
            409,
          );
          await request(
            `/requests/${trialRequest.id}/review`,
            "POST",
            { decision: "approved", note: "Not an approver" },
            "a",
            403,
          );
          await request(
            `/requests/${trialRequest.id}/review`,
            "POST",
            { decision: "approved", note: "Approved trial" },
            "approver",
          );
          await request(
            `/requests/${trialRequest.id}/review`,
            "POST",
            { decision: "approved", note: "Duplicate" },
            "owner",
            409,
          );
          await request(
            "/requests",
            "POST",
            { instance_id: instance.id, plan_id: plan.id, kind: "trial" },
            "a",
            409,
          );
          await request(
            "/customer-roles",
            "POST",
            { name: `Unsafe-${suffix}`, permission_codes: ["*"] },
            "a",
            403,
          );
          await request(
            "/customer-roles",
            "POST",
            {
              name: `Mechanic-${suffix}`,
              permission_codes: ["MMMS-APP", "MMMS-MACHINES-VIEW"],
            },
            "a",
            201,
          );
        },
      );
      let token;
      await t.test(
        "real IAM role sync, employee creation, login and menu permissions",
        async () => {
          await request(
            `/instances/${instance.id}/sync-roles`,
            "POST",
            {},
            "a",
          );
          await request(
            `/instances/${instance.id}/users`,
            "POST",
            {
              username: `erp-${suffix}`,
              display_name: `ERP Employee ${suffix}`,
              password,
              roles: [`Mechanic-${suffix}`],
              scopes: [
                {
                  applicationName: "MMMS",
                  organizationId: "test-org",
                  factoryId: "test-factory",
                },
              ],
            },
            "a",
            201,
          );
          const response = await fetch(`${iamOrigin}/v3/api/auth/users/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              employeeCode: `erp-${suffix}`,
              authCode: password,
            }),
          });
          const result = await response.json();
          assert.equal(response.status, 200, JSON.stringify(result));
          token = result.token || result.result?.token;
          assert.ok(token, JSON.stringify(result));
          const workspace = await fetch(
            `${iamOrigin}/v3/api/auth/applications/workspace`,
            { headers: { Authorization: `Bearer ${token}` } },
          );
          const menus = await workspace.json();
          assert.equal(menus.result[0].applicationName, "MMMS");
          assert.equal(
            menus.navigation[0].navbarItems[0].permission,
            "MMMS-MACHINES-VIEW",
          );
          const blocked = await fetch(`${iamOrigin}/v3/api/auth/applications`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${token}`,
            },
            body: "{}",
          });
          assert.equal(blocked.status, 409);
          const ownUsers = await request(
            `/instances/${instance.id}/users?search=erp-${suffix}`,
            "GET",
            null,
            "a",
          );
          assert.ok(
            ownUsers.items.some((u) => u.employeeCode === `erp-${suffix}`),
          );
          assert.equal(ownUsers.items[0].authCode, undefined);
          await request(
            `/instances/${instance.id}/users`,
            "GET",
            null,
            "b",
            403,
          );
        },
      );
      await t.test(
        "paid approval uses the requested snapshot and records manual payment",
        async () => {
          purchaseRequest = await request(
            "/requests",
            "POST",
            { instance_id: instance.id, plan_id: plan.id, kind: "purchase" },
            "a",
            201,
          );
          await request(
            `/plans/${plan.id}`,
            "PUT",
            {
              name: "Edited plan",
              price_minor: 99900,
              currency: "USD",
              duration_months: 1,
              trial_days: 7,
              max_users: 10000,
              published: true,
              entitlements: {
                applications: ["MMMS"],
                permissions: ["MMMS-APP", "MMMS-MACHINES-VIEW"],
              },
            },
            "owner",
          );
          await request(
            `/requests/${purchaseRequest.id}/review`,
            "POST",
            { decision: "approved", note: "Missing payment" },
            "approver",
            400,
          );
          await request(
            `/requests/${purchaseRequest.id}/review`,
            "POST",
            {
              decision: "approved",
              note: "Bank transfer verified",
              payment_reference: `BANK-${suffix}`,
            },
            "approver",
          );
          const subs = await request("/subscriptions", "GET", null, "a");
          const active = subs.items.find((s) => s.status === "active");
          assert.equal(Number(active.plan_snapshot.price_minor), 10000);
          assert.equal(active.plan_snapshot.version, 1);
          assert.equal(
            subs.items.find((s) => s.kind === "trial").status,
            "superseded",
          );
        },
      );
      await t.test(
        "employee edits, role changes, seat limits and provider outages fail safely",
        async () => {
          const listing = await request(
            `/instances/${instance.id}/users?pageSize=100&search=erp-${suffix}`,
            "GET",
            null,
            "a",
          );
          const employee = listing.items.find(
            (u) => u.employeeCode === `erp-${suffix}`,
          );
          const values = {
            display_name: `Edited employee ${suffix}`,
            password: password + "v2",
            roles: [`Mechanic-${suffix}`],
            scopes: [
              {
                applicationName: "MMMS",
                organizationId: "test-org",
                factoryId: "test-factory",
              },
            ],
          };
          await request(
            `/instances/${instance.id}/users/${employee.id}`,
            "PUT",
            { ...values, roles: ["superadmin"] },
            "a",
            403,
          );
          await request(
            `/instances/${instance.id}/users/${employee.id}`,
            "PUT",
            values,
            "b",
            403,
          );
          await request(
            `/instances/${instance.id}/users/${employee.id}`,
            "PUT",
            values,
            "a",
          );
          const ended = await fetch(`${iamOrigin}/v3/api/auth/runtime/access`, {
            headers: { Authorization: `Bearer ${token}` },
          });
          assert.equal(ended.status, 401);
          async function login() {
            const response = await fetch(
              `${iamOrigin}/v3/api/auth/users/login`,
              {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  "x-application-name": "MMMS",
                },
                body: JSON.stringify({
                  employeeCode: `erp-${suffix}`,
                  authCode: password + "v2",
                }),
              },
            );
            const result = await response.json();
            assert.equal(response.status, 200, JSON.stringify(result));
            token = result.token;
          }
          await login();
          const roles = await request("/customer-roles", "GET", null, "a");
          const role = roles.items.find((r) => r.name === `Mechanic-${suffix}`);
          await request(
            `/customer-roles/${role.id}`,
            "PATCH",
            { enabled: true, permission_codes: ["*"] },
            "a",
            403,
          );
          await request(
            `/customer-roles/${role.id}`,
            "PATCH",
            { enabled: true, permission_codes: ["MMMS-APP"] },
            "a",
          );
          await request(
            `/instances/${instance.id}/sync-roles`,
            "POST",
            {},
            "a",
          );
          await login();
          const checked = { get: () => `Bearer ${token}`, auth: {} };
          await require("../../mmms-backend/src/middleware/subscription-access")(
            checked,
          );
          assert.deepEqual(checked.auth.permissions, ["MMMS-APP"]);
          await request(
            `/customer-roles/${role.id}`,
            "PATCH",
            {
              enabled: true,
              permission_codes: ["MMMS-APP", "MMMS-MACHINES-VIEW"],
            },
            "a",
          );
          await request(
            `/instances/${instance.id}/sync-roles`,
            "POST",
            {},
            "a",
          );
          await login();
          const active = (
            await request("/subscriptions", "GET", null, "a")
          ).items.find((r) => r.status === "active");
          const count =
            await require("../../authguardv2-node/src/models").User.count({
              where: { isActive: true },
            });
          await query(
            "UPDATE control_subscriptions SET plan_snapshot=jsonb_set(plan_snapshot,'{max_users}',$2::jsonb) WHERE id=$1",
            [active.id, JSON.stringify(count)],
          );
          resetCache();
          await request(
            `/instances/${instance.id}/users`,
            "POST",
            { ...values, username: `excess-${suffix}` },
            "a",
            409,
          );
          await query(
            "UPDATE control_subscriptions SET plan_snapshot=jsonb_set(plan_snapshot,'{max_users}',$2::jsonb) WHERE id=$1",
            [active.id, JSON.stringify(count - 1)],
          );
          resetCache();
          const overLimit = await fetch(
            `${iamOrigin}/v3/api/auth/runtime/access`,
            { headers: { Authorization: `Bearer ${token}` } },
          );
          assert.equal(overLimit.status, 403);
          await query(
            "UPDATE control_subscriptions SET plan_snapshot=jsonb_set(plan_snapshot,'{max_users}','10000'::jsonb) WHERE id=$1",
            [active.id],
          );
          resetCache();
          process.env.CONTROL_API_URL = "http://127.0.0.1:1";
          const unavailable = await fetch(
            `${iamOrigin}/v3/api/auth/runtime/access`,
            { headers: { Authorization: `Bearer ${token}` } },
          );
          assert.equal(unavailable.status, 503);
          process.env.CONTROL_API_URL = origin;
          resetCache();
        },
      );
      await t.test(
        "revocation and expiry block existing ERP tokens, MMMS and private files",
        async () => {
          const subs = await request("/subscriptions", "GET", null, "a"),
            active = subs.items.find((s) => s.status === "active");
          const req = {
            get: () => `Bearer ${token}`,
            auth: { permissions: ["*"] },
          };
          resetCache();
          await require("../../mmms-backend/src/middleware/subscription-access")(
            req,
          );
          assert.deepEqual(req.auth.permissions.sort(), [
            "MMMS-APP",
            "MMMS-MACHINES-VIEW",
          ]);
          await request(
            `/subscriptions/${active.id}/status`,
            "POST",
            { status: "suspended", note: "Payment dispute" },
            "approver",
          );
          resetCache();
          await assert.rejects(
            require("../../mmms-backend/src/middleware/subscription-access")({
              get: () => `Bearer ${token}`,
              auth: {},
            }),
            (e) => e.status === 403,
          );
          await assert.rejects(
            require("../../storage-service/routes/subscription-access")({
              get: () => `Bearer ${token}`,
              auth: {},
            }),
            (e) => e.status === 403,
          );
          await request(
            `/subscriptions/${active.id}/status`,
            "POST",
            { status: "active", note: "Dispute resolved" },
            "approver",
          );
          resetCache();
          await query(
            "UPDATE control_subscriptions SET starts_at=now()-interval '2 days', ends_at=now()-interval '1 day' WHERE id=$1",
            [active.id],
          );
          resetCache();
          const expired = await fetch(
            `${iamOrigin}/v3/api/auth/runtime/access`,
            { headers: { Authorization: `Bearer ${token}` } },
          );
          assert.equal(expired.status, 403);
          assert.equal(
            await require("../../mmms-backend/src/middleware/subscription-access").serviceAccess(),
            false,
          );
        },
      );
      await t.test("maker-checker, pagination and logout", async () => {
        const own = await request(
          "/requests",
          "POST",
          { instance_id: otherInstance.id, plan_id: plan.id, kind: "purchase" },
          "owner",
          201,
        );
        await request(
          `/requests/${own.id}/review`,
          "POST",
          { decision: "approved", note: "Self review", payment_reference: "x" },
          "owner",
          403,
        );
        await request(
          `/requests/${own.id}/review`,
          "POST",
          { decision: "rejected", note: "Independent rejection" },
          "approver",
        );
        const audit = await request(
          "/audit?page=1&pageSize=1",
          "GET",
          null,
          "a",
        );
        assert.equal(audit.items.length, 1);
        assert.ok(audit.total > 1);
        assert.equal(audit.items[0].customer_id, customerId);
        await request("/audit?pageSize=1000", "GET", null, "a", 400);
        await request("/auth/logout", "POST", {}, "a", 204);
        await request("/auth/session", "GET", null, "a", 401);
      });
    } finally {
      await Promise.all([
        new Promise((r) => server.close(r)),
        new Promise((r) => iam.close(r)),
      ]);
      await pool.end();
      await require("../../authguardv2-node/src/services/telemetry.service").drainTelemetry();
      await require("../../authguardv2-node/src/models").sequelize.close();
    }
  },
);
