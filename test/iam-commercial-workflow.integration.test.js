const { test } = require("node:test");
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

test(
  "one customer: purchase approval → IAM provisioning → licensing lifecycle",
  {
    skip: process.env.CONTROL_INTEGRATION_TEST !== "true",
    timeout: 120000,
  },
  async (t) => {
    // MMMS initializes its own DB_NAME; capture each service's intended database first.
    const databases = [
      process.env.CONTROL_DB_NAME,
      process.env.DB_NAME,
      process.env.MMMS_DB_NAME,
    ];
    const signingDirectory = fs.mkdtempSync(
      path.join(require("node:os").tmpdir(), "neola-license-test-"),
    );
    const keys = require("node:crypto").generateKeyPairSync("ed25519");
    const privateFile = path.join(signingDirectory, "private.pem"),
      publicFile = path.join(signingDirectory, "public.pem");
    fs.writeFileSync(
      privateFile,
      keys.privateKey.export({ type: "pkcs8", format: "pem" }),
      { mode: 0o600 },
    );
    fs.writeFileSync(
      publicFile,
      keys.publicKey.export({ type: "spki", format: "pem" }),
    );
    process.env.CONTROL_LICENSE_PRIVATE_KEY_FILE = privateFile;
    process.env.CONTROL_LICENSE_PUBLIC_KEY_FILE = publicFile;
    process.env.CONTROL_REQUIRE_SIGNED_LICENSE = "true";
    const { query, pool } = require("../src/database");
    const iamModels = require("../../authguardv2-node/src/models");
    const mmmsModels = require("../../mmms-backend/src/models");
    const licensing = require("../../authguardv2-node/src/services/subscription-access");
    const bcrypt = require("bcryptjs");
    const suffix = randomUUID().slice(0, 8),
      password = "Isolated-journey-2026!-" + suffix;
    const servers = [],
      sessions = {};
    const report = {
      startedAt: new Date().toISOString(),
      scenario: suffix,
      checks: [],
      signedLicenses: true,
    };
    const reportFile = path.resolve(
      __dirname,
      "../../.local/subscription-iam-workflow-report.json",
    );
    const record = () => {
      fs.mkdirSync(path.dirname(reportFile), { recursive: true });
      fs.writeFileSync(reportFile, JSON.stringify(report, null, 2));
    };
    const step = (name, work) =>
      t.test(name, async () => {
        const start = performance.now();
        await work();
        report.checks.push({
          name,
          passed: true,
          durationMs: Math.round(performance.now() - start),
        });
        record();
      });
    async function serve(app) {
      const server = app.listen(0, "127.0.0.1");
      servers.push(server);
      await new Promise((r) => server.once("listening", r));
      return "http://127.0.0.1:" + server.address().port;
    }
    async function http(
      origin,
      route,
      {
        body,
        method = body ? "POST" : "GET",
        headers = {},
        expected = 200,
      } = {},
    ) {
      const response = await fetch(origin + route, {
        method,
        headers: { "Content-Type": "application/json", ...headers },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      const value = await response.json();
      assert.equal(
        response.status,
        expected,
        `${method} ${route}: ${value.message || value.error?.message || response.status}`,
      );
      return { response, value };
    }
    let controlOrigin,
      iamOrigin,
      mmmsOrigin,
      customerId,
      instance,
      plan,
      subscriptionId,
      administrator,
      adminToken,
      employee,
      employeeToken,
      employeeRole,
      factory,
      company,
      machine;
    const control = async (who, route, options = {}) =>
      (
        await http(controlOrigin, "/api/control" + route, {
          ...options,
          headers: sessions[who] || {},
        })
      ).value;
    const iam = async (token, route, options = {}) =>
      (
        await http(iamOrigin, "/v3/api/auth" + route, {
          ...options,
          headers: {
            Authorization: "Bearer " + token,
            "x-application-name": "IAM",
          },
        })
      ).value;
    const mmms = async (token, route, expected = 200) =>
      (
        await http(mmmsOrigin, "/v1" + route, {
          expected,
          headers: { Authorization: "Bearer " + token },
        })
      ).value;
    async function consoleLogin(who, username) {
      const result = await http(controlOrigin, "/api/control/auth/login", {
        body: { username, password },
      });
      sessions[who] = {
        Cookie: result.response.headers.get("set-cookie").split(";")[0],
        "X-CSRF-Token": result.value.csrfToken,
      };
      return result.value.user;
    }
    async function employeeLogin() {
      employeeToken = (
        await iam("", "/users/login", {
          body: { employeeCode: employee.employeeCode, authCode: password },
        })
      ).token;
    }
    async function waitForAccess(expected) {
      const start = performance.now();
      while (performance.now() - start < 17000) {
        const response = await fetch(
          iamOrigin + "/v3/api/auth/runtime/access",
          { headers: { Authorization: "Bearer " + employeeToken } },
        );
        if (response.status === expected)
          return Math.round(performance.now() - start);
        assert.ok(
          [200, 403].includes(response.status),
          "Unexpected runtime access status " + response.status,
        );
        await new Promise((r) => setTimeout(r, 150));
      }
      assert.fail(
        "Access did not become " +
          expected +
          " within the 15-second cache window plus polling allowance",
      );
    }
    try {
      // Refuse to run lifecycle mutations against ordinary local/customer databases.
      assert.ok(databases.every((name) => name?.endsWith("_test")));
      assert.equal(
        (await query("SELECT current_database() AS name")).rows[0].name,
        databases[0],
      );
      for (const [sequelize, expected] of [
        [iamModels.sequelize, databases[1]],
        [mmmsModels.sequelize, databases[2]],
      ]) {
        const [rows] = await sequelize.query(
          "SELECT current_database() AS name",
        );
        assert.equal(rows[0].name, expected);
      }
      report.databases = databases;
      process.env.PLATFORM_MASTERS_MODE = "shared";
      controlOrigin = await serve(require("../src/server").createApp());
      iamOrigin = await serve(require("../../authguardv2-node/src/app"));
      process.env.CONTROL_API_URL = controlOrigin;
      process.env.CONTROL_ERP_ALLOWED_ORIGINS = iamOrigin;
      process.env.IAM_API_URL = iamOrigin;
      mmmsOrigin = await serve(require("../../mmms-backend/src/app"));

      // Installation/bootstrap fixtures only. Every business transition below uses real HTTP APIs.
      await query(
        "INSERT INTO control_users(id,username,display_name,password_hash,role) VALUES($1,$2,'Journey platform owner',$3,'platform_owner')",
        [
          randomUUID(),
          "journey-owner-" + suffix,
          await bcrypt.hash(password, 12),
        ],
      );
      await consoleLogin("owner", "journey-owner-" + suffix);
      await control("owner", "/operators", {
        body: {
          username: "journey-approver-" + suffix,
          display_name: "Journey approver",
          password,
          role: "approver",
        },
        expected: 201,
      });
      await consoleLogin("approver", "journey-approver-" + suffix);
      await control("", "/auth/register", {
        body: {
          username: "journey-customer-" + suffix,
          display_name: "Journey customer owner",
          name: "Journey customer " + suffix,
          email: "journey-" + suffix + "@example.invalid",
          password,
        },
        expected: 201,
      });
      customerId = (
        await consoleLogin("customer", "journey-customer-" + suffix)
      ).customer_id;
      const [wildcard] = await iamModels.Permission.findOrCreate({
        where: { name: "*" },
        defaults: { enabled: true },
      });
      const bootstrapRole = await iamModels.Role.create({
        name: "Journey installation bootstrap " + suffix,
        enabled: true,
      });
      await bootstrapRole.setPermissions([wildcard]);
      administrator = await iamModels.User.create({
        employeeCode: "journey-admin-" + suffix,
        employeeName: "Journey IAM administrator " + suffix,
        authCode: await bcrypt.hash(password, 12),
        isActive: true,
      });
      await administrator.setRoles([bootstrapRole]);
      const grants = [
        "MMMS-APP",
        "MMMS-MACHINES",
        "MMMS-MACHINES-VIEW",
        "MASTERS-APP",
        "MASTERS-READ",
        "MASTERS-MANAGE",
        "MASTERS-ADMIN",
      ];
      for (const [code, route] of [
        ["MMMS", "/mmms/machines"],
        ["MASTERS", "/masters"],
      ]) {
        await control("owner", "/applications/" + code, {
          method: "PUT",
          body: {
            name: code,
            icon: "bi-grid",
            landing_route: route,
            required_permission: code + "-APP",
            navigation:
              code === "MMMS"
                ? [
                    {
                      label: "Machines",
                      link: route,
                      permission: "MMMS-MACHINES",
                      icon: "bi-gear",
                    },
                    {
                      label: "Work orders",
                      link: "/mmms/work-orders",
                      permission: "MMMS-WORK-ORDERS",
                      icon: "bi-tools",
                    },
                  ]
                : [
                    {
                      label: "Masters",
                      link: route,
                      permission: "MASTERS-READ",
                      icon: "bi-diagram-3",
                    },
                  ],
          },
        });
      }
      for (const code of [...grants, "MMMS-WORK-ORDERS"]) {
        await control("owner", "/permissions/" + code, {
          method: "PUT",
          body: {
            application_code: code.startsWith("MMMS") ? "MMMS" : "MASTERS",
          },
        });
        await iamModels.Permission.findOrCreate({
          where: { name: code },
          defaults: {
            enabled: true,
            appname: code.startsWith("MMMS") ? "MMMS" : "MASTERS",
          },
        });
      }
      const seatLimit =
        (await iamModels.User.count({ where: { isActive: true } })) + 1;
      report.seatLimit = seatLimit;
      plan = await control("owner", "/plans", {
        body: {
          name: "Journey paid plan " + suffix,
          price_minor: 2500,
          currency: "USD",
          duration_months: 1,
          trial_days: 0,
          max_users: seatLimit,
          published: true,
          entitlements: {
            applications: ["MMMS", "MASTERS"],
            permissions: grants,
          },
        },
        expected: 201,
      });
      instance = await control("owner", "/instances", {
        body: {
          customer_id: customerId,
          name: "Journey ERP " + suffix,
          api_origin: iamOrigin,
        },
        expected: 201,
      });
      process.env.CONTROL_INSTANCE_ID = instance.id;
      process.env.CONTROL_INSTANCE_KEY = instance.activation_key;
      licensing.resetCache();

      await step(
        "customer requests a plan; a different approver activates it",
        async () => {
          await iam("", "/users/login", {
            body: {
              employeeCode: administrator.employeeCode,
              authCode: password,
            },
            expected: 403,
          });
          const request = await control("customer", "/requests", {
            body: {
              instance_id: instance.id,
              plan_id: plan.id,
              kind: "purchase",
            },
            expected: 201,
          });
          await control("customer", "/requests/" + request.id + "/review", {
            body: {
              decision: "approved",
              note: "Cannot approve own purchase",
              payment_reference: "TEST-ONLY",
            },
            expected: 403,
          });
          await control("approver", "/requests/" + request.id + "/review", {
            body: {
              decision: "approved",
              note: "Isolated manual payment verified; no real charge",
              payment_reference: "JOURNEY-TEST-" + suffix,
            },
          });
          await control("approver", "/requests/" + request.id + "/review", {
            body: {
              decision: "approved",
              note: "Duplicate review",
              payment_reference: "TEST-ONLY",
            },
            expected: 409,
          });
          const invoice = (await control("customer", "/invoices")).items.find(
            (i) => i.request_id === request.id,
          );
          assert.equal(Number(invoice.amount_minor), 2500);
          subscriptionId = (
            await control("customer", "/subscriptions")
          ).items.find((s) => s.instance_id === instance.id).id;
          licensing.resetCache(); // Start the activated installation; revocation checks below never reset caches.
          adminToken = (
            await iam("", "/users/login", {
              body: {
                employeeCode: administrator.employeeCode,
                authCode: password,
              },
            })
          ).token;
        },
      );
      await step(
        "IAM creates a role and employee inside purchased permissions",
        async () => {
          const permissions = (await iam(adminToken, "/permissions")).result;
          const selected = permissions.filter((p) =>
            ["MMMS-APP", "MMMS-MACHINES", "MMMS-MACHINES-VIEW"].includes(
              p.name,
            ),
          );
          assert.equal(selected.length, 3);
          const forbidden = await iamModels.Permission.findOne({
            where: { name: "MMMS-WORK-ORDERS" },
          });
          await iam(adminToken, "/roles", {
            body: {
              name: "Unpurchased journey role " + suffix,
              permissionIds: [forbidden.id],
            },
            expected: 403,
          });
          employeeRole = (
            await iam(adminToken, "/roles", {
              body: {
                name: "Journey machine reader " + suffix,
                permissionIds: selected.map((p) => p.id),
              },
            })
          ).result;
          employee = (
            await iam(adminToken, "/users", {
              body: {
                employeeCode: "journey-employee-" + suffix,
                employeeName: "Journey employee " + suffix,
                authCode: password,
                roleIds: [employeeRole.id],
              },
            })
          ).result;
          await employeeLogin();
          assert.deepEqual((await mmms(employeeToken, "/machines")).result, []);
        },
      );
      await step(
        "IAM assigns canonical company/factory scope and MMMS enforces it",
        async () => {
          company = (
            await iam(adminToken, "/shared-masters", {
              body: {
                name: "Journey company " + suffix,
                code: "JC-" + suffix,
                unitType: "Company",
              },
              expected: 201,
            })
          ).id;
          factory = (
            await iam(adminToken, "/shared-masters", {
              body: {
                name: "Journey factory " + suffix,
                code: "JF-" + suffix,
                unitType: "Factory",
                parentId: company,
              },
              expected: 201,
            })
          ).id;
          const otherFactory = (
            await iam(adminToken, "/shared-masters", {
              body: {
                name: "Other factory " + suffix,
                code: "JFO-" + suffix,
                unitType: "Factory",
                parentId: company,
              },
              expected: 201,
            })
          ).id;
          const createMachine = (tag, factoryId) =>
            mmmsModels.Machine.create({
              id: "J-" + tag + "-" + suffix,
              assetNumber: "JA-" + tag + "-" + suffix,
              machineCode: "JC-" + tag + "-" + suffix,
              qrReference: "JQR-" + tag + "-" + suffix,
              name: "Journey machine " + tag,
              category: "Sewing",
              organizationId: company,
              factoryId,
            });
          machine = await createMachine("owned", factory);
          const otherMachine = await createMachine("other", otherFactory);
          await iam(adminToken, "/users/" + employee.id + "/scopes", {
            method: "PUT",
            body: {
              scopes: [
                {
                  applicationName: "MMMS",
                  organizationId: company,
                  factoryId: randomUUID(),
                },
              ],
            },
            expected: 422,
          });
          await iam(adminToken, "/users/" + employee.id + "/scopes", {
            method: "PUT",
            body: {
              scopes: [
                {
                  applicationName: "MMMS",
                  organizationId: company,
                  factoryId: factory,
                },
              ],
            },
          });
          await iam(employeeToken, "/runtime/access", { expected: 401 });
          await employeeLogin();
          assert.deepEqual(
            (await mmms(employeeToken, "/machines")).result.map((m) => m.id),
            [machine.id],
          );
          await mmms(employeeToken, "/machines/" + machine.id);
          await mmms(employeeToken, "/machines/" + otherMachine.id, 403);
        },
      );
      await step(
        "navigation exposes only purchased and assigned applications/actions",
        async () => {
          const workspace = await iam(employeeToken, "/applications/workspace");
          assert.deepEqual(
            workspace.result.map((a) => a.applicationName),
            ["MMMS"],
          );
          assert.deepEqual(
            workspace.navigation[0].navbarItems.map((n) => n.link),
            ["/mmms/machines"],
          );
          await iam(employeeToken, "/users", { expected: 403 });
          await mmms(employeeToken, "/work-orders", 403);
          report.navigation = ["MMMS → Machines"];
        },
      );
      await step(
        "seat limits reject additional creation and reactivation, then recover when a seat is freed",
        async () => {
          const newUser = (tag) => ({
            employeeCode: "journey-" + tag + "-" + suffix,
            employeeName: "Journey " + tag + " " + suffix,
            authCode: password,
            roleIds: [employeeRole.id],
          });
          const count = await iamModels.User.count();
          await iam(adminToken, "/users", {
            body: newUser("excess"),
            expected: 409,
          });
          assert.equal(await iamModels.User.count(), count);
          await iam(
            adminToken,
            "/users/" + employee.id + "/status?enable=false",
            { method: "PATCH", body: {} },
          );
          const replacement = (
            await iam(adminToken, "/users", { body: newUser("replacement") })
          ).result;
          await iam(
            adminToken,
            "/users/" + employee.id + "/status?enable=true",
            { method: "PATCH", body: {}, expected: 409 },
          );
          await iam(
            adminToken,
            "/users/" + replacement.id + "/status?enable=false",
            { method: "PATCH", body: {} },
          );
          await iam(
            adminToken,
            "/users/" + employee.id + "/status?enable=true",
            { method: "PATCH", body: {} },
          );
          await employeeLogin();
          await mmms(employeeToken, "/machines/" + machine.id);
        },
      );
      await step(
        "suspension blocks an already-issued JWT within the real cache lifetime",
        async () => {
          await iam(employeeToken, "/runtime/access");
          await control(
            "approver",
            "/subscriptions/" + subscriptionId + "/status",
            { body: { status: "suspended", note: "Isolated suspension test" } },
          );
          report.suspensionDeniedAfterMs = await waitForAccess(403);
          await iam(employeeToken, "/applications/workspace", {
            expected: 403,
          });
          await iam("", "/users/login", {
            body: { employeeCode: employee.employeeCode, authCode: password },
            expected: 403,
          });
          await mmms(employeeToken, "/machines/" + machine.id, 403);
          assert.equal(
            await require("../../mmms-backend/src/middleware/subscription-access").serviceAccess(),
            false,
          );
          await assert.rejects(
            require("../../storage-service/routes/subscription-access")({
              get: () => "Bearer " + employeeToken,
              auth: {},
            }),
            (e) => e.status === 403,
          );
        },
      );
      await step(
        "resuming restores access for the same valid employee JWT",
        async () => {
          await control(
            "approver",
            "/subscriptions/" + subscriptionId + "/status",
            {
              body: { status: "active", note: "Isolated suspension resolved" },
            },
          );
          report.resumedAfterMs = await waitForAccess(200);
          await mmms(employeeToken, "/machines/" + machine.id);
        },
      );
      await step(
        "natural subscription expiry denies navigation, login and MMMS without waiting for JWT expiry",
        async () => {
          // Shorten only this isolated fixture's term, then warm its actual expiry-bound cache.
          await query(
            "UPDATE control_subscriptions SET ends_at=now()+interval '2 seconds' WHERE id=$1",
            [subscriptionId],
          );
          licensing.resetCache();
          await iam(employeeToken, "/runtime/access");
          await mmms(employeeToken, "/machines/" + machine.id);
          report.expiredAfterMs = await waitForAccess(403);
          const claims =
            require("../../authguardv2-node/node_modules/jsonwebtoken").decode(
              employeeToken,
            );
          assert.ok(
            claims.exp * 1000 > Date.now() + 60000,
            "JWT itself must still be valid",
          );
          await iam(employeeToken, "/applications/workspace", {
            expected: 403,
          });
          await iam("", "/users/login", {
            body: { employeeCode: employee.employeeCode, authCode: password },
            expected: 403,
          });
          await mmms(employeeToken, "/machines/" + machine.id, 403);
          await control(
            "approver",
            "/subscriptions/" + subscriptionId + "/status",
            {
              body: { status: "active", note: "Expired term cannot resume" },
              expected: 409,
            },
          );
        },
      );
      await step(
        "a newly requested and approved purchase restores the same IAM user, role and scope",
        async () => {
          const renewal = await control("customer", "/requests", {
            body: {
              instance_id: instance.id,
              plan_id: plan.id,
              kind: "purchase",
            },
            expected: 201,
          });
          await control("approver", "/requests/" + renewal.id + "/review", {
            body: {
              decision: "approved",
              note: "Isolated renewal approved; no real charge",
              payment_reference: "JOURNEY-RENEWAL-" + suffix,
            },
          });
          report.renewedAfterMs = await waitForAccess(200);
          await mmms(employeeToken, "/machines/" + machine.id);
          assert.equal(
            (await iam(employeeToken, "/users/me")).result.id,
            employee.id,
          );
          assert.equal(
            (await iam(adminToken, "/users/" + employee.id + "/scopes"))
              .result[0].factoryId,
            factory,
          );
        },
      );
      report.passed = report.checks.length === 9;
    } finally {
      report.finishedAt = new Date().toISOString();
      report.passed ??= false;
      record();
      for (const server of servers.reverse())
        await new Promise((r) => server.close(r));
      await require("../../authguardv2-node/src/services/telemetry.service").drainTelemetry();
      await Promise.all([
        pool.end(),
        iamModels.sequelize.close(),
        mmmsModels.sequelize.close(),
      ]);
      fs.unlinkSync(privateFile);
      fs.unlinkSync(publicFile);
      fs.rmdirSync(signingDirectory);
    }
  },
);
