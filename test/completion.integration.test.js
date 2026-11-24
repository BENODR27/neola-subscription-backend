const { test } = require("node:test");
const assert = require("node:assert/strict");
const { randomUUID } = require("node:crypto");
test(
  "account security, billing, rotation, legacy adoption and common masters",
  { skip: process.env.CONTROL_INTEGRATION_TEST !== "true" },
  async (t) => {
    const { query, pool } = require("../src/database"),
      s = require("../src/security"),
      bcrypt = require("bcryptjs");
    const suffix = randomUUID().slice(0, 8),
      password = "Completion-test-password-2026!",
      ownerId = randomUUID();
    await query(
      "INSERT INTO control_users(id,username,display_name,password_hash,role,email) VALUES($1,$2,'Completion owner',$3,'platform_owner',$4)",
      [
        ownerId,
        "completion-" + suffix,
        await bcrypt.hash(password, 12),
        "owner-" + suffix + "@example.invalid",
      ],
    );
    const server = require("../src/server").createApp().listen(0, "127.0.0.1");
    await new Promise((r) => server.once("listening", r));
    const base = `http://127.0.0.1:${server.address().port}/api/control`;
    const models = require("../../authguardv2-node/src/models");
    const iam = require("../../authguardv2-node/src/app").listen(
      0,
      "127.0.0.1",
    );
    await new Promise((r) => iam.once("listening", r));
    const iamOrigin = `http://127.0.0.1:${iam.address().port}`;
    process.env.CONTROL_API_URL = base.replace("/api/control", "");
    process.env.CONTROL_ERP_ALLOWED_ORIGINS = iamOrigin;
    process.env.IAM_API_URL = iamOrigin;
    let cookie = "",
      csrf = "",
      erpToken,
      instance,
      plan,
      customer,
      requestId,
      recoveryCode;
    async function api(
      path,
      body,
      expected = 200,
      method = body ? "POST" : "GET",
      headers = { Cookie: cookie, "X-CSRF-Token": csrf },
    ) {
      const r = await fetch(base + path, {
        method,
        headers: { "Content-Type": "application/json", ...headers },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      const v = r.status === 204 ? {} : await r.json();
      assert.equal(r.status, expected, path + ": " + JSON.stringify(v));
      return { body: v, response: r };
    }
    async function login(code = "") {
      const r = await api(
        "/auth/login",
        { username: "completion-" + suffix, password, mfa_code: code },
        200,
        "POST",
        {},
      );
      cookie = r.response.headers.get("set-cookie").split(";")[0];
      csrf = r.body.csrfToken;
    }
    async function iamApi(
      path,
      body,
      expected = path === "/shared-masters" && body ? 201 : 200,
      method = body ? "POST" : "GET",
    ) {
      const r = await fetch(iamOrigin + "/v3/api/auth" + path, {
        method,
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer " + erpToken,
          "x-application-name": "MMMS",
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
      const v = await r.json();
      assert.equal(r.status, expected, path + ": " + JSON.stringify(v));
      return v;
    }
    let legacyUser, company, factory, sourcePasswordHash;
    try {
      await login();
      await t.test(
        "email verification and single-use recovery links",
        async () => {
          await api("/account/resend-verification", {});
          let mail = (
            await query(
              "SELECT * FROM control_mail_outbox WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1",
              [ownerId],
            )
          ).rows[0];
          let token = new URL(
            JSON.parse(s.decrypt(mail.encrypted_payload)).url,
          ).searchParams.get("token");
          await api("/account/verify-email", { token });
          await api("/account/verify-email", { token }, 400);
          assert.equal(
            (await api("/account/security")).body.email_verified,
            true,
          );
          await api("/account/forgot-password", {
            username: "completion-" + suffix,
          });
          mail = (
            await query(
              "SELECT * FROM control_mail_outbox WHERE user_id=$1 AND kind='reset_password' ORDER BY created_at DESC LIMIT 1",
              [ownerId],
            )
          ).rows[0];
          token = new URL(
            JSON.parse(s.decrypt(mail.encrypted_payload)).url,
          ).searchParams.get("token");
          await api("/account/reset-password", { token, password });
          await api("/account/reset-password", { token, password }, 400);
          await api("/auth/session", undefined, 401);
          await login();
        },
      );
      await t.test(
        "authenticator enrollment, replay rejection and recovery codes",
        async () => {
          const setup = (await api("/account/mfa/setup", { password })).body;
          const { totp } = require("../src/account-security");
          const enrolledCode = totp(setup.secret);
          const confirmed = (
            await api("/account/mfa/confirm", { code: enrolledCode })
          ).body;
          recoveryCode = confirmed.recovery_codes[0];
          assert.equal(confirmed.recovery_codes.length, 8);
          await api(
            "/auth/login",
            { username: "completion-" + suffix, password },
            401,
            "POST",
            {},
          );
          await api(
            "/auth/login",
            {
              username: "completion-" + suffix,
              password,
              mfa_code: enrolledCode,
            },
            401,
            "POST",
            {},
          );
          await login(recoveryCode);
          await api(
            "/auth/login",
            {
              username: "completion-" + suffix,
              password,
              mfa_code: recoveryCode,
            },
            401,
            "POST",
            {},
          );
          await api("/account/mfa/disable", {
            password,
            code: confirmed.recovery_codes[1],
          });
          await login();
        },
      );
      await api(
        "/auth/register",
        {
          username: "customer-" + suffix,
          password,
          name: "Completion customer " + suffix,
          display_name: "Owner",
          email: "customer-" + suffix + "@example.invalid",
        },
        201,
      );
      customer = (
        await query("SELECT customer_id FROM control_users WHERE username=$1", [
          "customer-" + suffix,
        ])
      ).rows[0].customer_id;
      for (const app of ["MMMS", "MASTERS"]) {
        await api(
          "/applications/" + app,
          {
            name: app,
            required_permission: app + "-APP",
            landing_route: app === "MMMS" ? "/mmms" : "/masters",
            navigation: [],
          },
          200,
          "PUT",
        );
      }
      const permissions = [
        "MMMS-APP",
        "MMMS-MACHINES-VIEW",
        "MMMS-TECHNICIANS",
        "MMMS-TECHNICIANS-CREATE",
        "MMMS-TECHNICIANS-EDIT",
        "MMMS-SPARE-PARTS",
        "MMMS-SPARE-PARTS-CREATE",
        "MASTERS-APP",
        "MASTERS-READ",
        "MASTERS-MANAGE",
        "MASTERS-ADMIN",
      ];
      for (const code of permissions)
        await api(
          "/permissions/" + code,
          { application_code: code.startsWith("MMMS") ? "MMMS" : "MASTERS" },
          200,
          "PUT",
        );
      plan = (
        await api(
          "/plans",
          {
            name: "Completion " + suffix,
            price_minor: 1200,
            currency: "USD",
            duration_months: 1,
            trial_days: 0,
            max_users: 100000,
            published: true,
            entitlements: { applications: ["MMMS", "MASTERS"], permissions },
          },
          201,
        )
      ).body;
      instance = (
        await api(
          "/instances",
          {
            customer_id: customer,
            name: "Completion ERP",
            api_origin: iamOrigin,
          },
          201,
        )
      ).body;
      process.env.CONTROL_INSTANCE_ID = instance.id;
      process.env.CONTROL_INSTANCE_KEY = instance.activation_key;
      const customerLogin = await api(
        "/auth/login",
        { username: "customer-" + suffix, password },
        200,
        "POST",
        {},
      );
      const customerHeaders = {
        Cookie: customerLogin.response.headers.get("set-cookie").split(";")[0],
        "X-CSRF-Token": customerLogin.body.csrfToken,
      };
      requestId = (
        await api(
          "/requests",
          { instance_id: instance.id, plan_id: plan.id, kind: "purchase" },
          201,
          "POST",
          customerHeaders,
        )
      ).body.id;
      await api(`/requests/${requestId}/review`, {
        decision: "approved",
        note: "Manual payment checked",
        payment_reference: "BANK-" + suffix,
      });
      await t.test(
        "manual invoice snapshots and scheduled renewal activation",
        async () => {
          const invoices = (await api("/invoices?customer_id=" + customer)).body
            .items;
          const invoice = invoices.find((i) => i.request_id === requestId);
          assert.equal(Number(invoice.amount_minor), 1200);
          assert.equal(
            invoice.customer_snapshot.name,
            "Completion customer " + suffix,
          );
          const renewal = (
            await api(
              "/requests",
              {
                instance_id: instance.id,
                plan_id: plan.id,
                kind: "purchase",
                renewal_mode: "after_current_term",
              },
              201,
              "POST",
              customerHeaders,
            )
          ).body;
          await api(`/requests/${renewal.id}/review`, {
            decision: "approved",
            note: "Renew after paid term",
            payment_reference: "RENEW-" + suffix,
          });
          const subs = (await api("/subscriptions?customer_id=" + customer))
            .body.items;
          const active = subs.find((s) => s.status === "active"),
            scheduled = subs.find((s) => s.status === "scheduled");
          assert.equal(
            new Date(active.ends_at).getTime(),
            new Date(scheduled.starts_at).getTime(),
          );
          assert.equal(
            (await require("../src/subscriptions").entitlements(instance.id))
              .subscription_id,
            active.id,
          );
          await query(
            "UPDATE control_subscriptions SET starts_at=now()-interval '2 days',ends_at=now()-interval '1 day' WHERE id=$1",
            [active.id],
          );
          await query(
            "UPDATE control_subscriptions SET starts_at=now()-interval '1 hour' WHERE id=$1",
            [scheduled.id],
          );
          assert.equal(
            (await require("../src/subscriptions").entitlements(instance.id))
              .subscription_id,
            scheduled.id,
          );
        },
      );
      sourcePasswordHash = await bcrypt.hash(password, 12);
      legacyUser = await models.User.create({
        employeeCode: "legacy-" + suffix,
        employeeName: "Legacy " + suffix,
        authCode: sourcePasswordHash,
        isActive: true,
      });
      const [wildcard] = await models.Permission.findOrCreate({
        where: { name: "*" },
        defaults: { enabled: true },
      });
      const legacyRole = await models.Role.create({
        name: "Legacy source " + suffix,
        enabled: true,
      });
      await legacyRole.setPermissions([wildcard]);
      await legacyUser.setRoles([legacyRole]);
      let logged = await iamApi("/users/login", {
        employeeCode: legacyUser.employeeCode,
        authCode: password,
      });
      erpToken = logged.token;
      await t.test(
        "shared hierarchy, catalogs, scope filtering and revision conflicts",
        async () => {
          company = await iamApi("/shared-masters", {
            name: "Shared company " + suffix,
            code: "C-" + suffix,
            unitType: "Company",
          });
          factory = await iamApi("/shared-masters", {
            name: "Shared factory " + suffix,
            code: "F-" + suffix,
            unitType: "Factory",
            parentId: company.id,
          });
          await iamApi(
            "/shared-masters",
            {
              name: "Invalid company employee",
              code: "BAD-" + suffix,
              module: "employees",
              organizationId: randomUUID(),
            },
            422,
          );
          await iamApi(
            "/shared-masters",
            {
              name: "Invalid factory contact",
              code: "BADF-" + suffix,
              module: "contacts",
              organizationId: company.id,
              factoryId: randomUUID(),
            },
            422,
          );
          await iamApi(
            "/shared-masters",
            {
              name: "Bypass hierarchy",
              code: "BADH-" + suffix,
              module: "factories",
              organizationId: company.id,
            },
            422,
          );
          const unit = await iamApi("/shared-masters", {
            name: "Shared unit " + suffix,
            code: "U-" + suffix,
            module: "units",
            organizationId: company.id,
          });
          await iamApi("/shared-masters", {
            name: "Shared person " + suffix,
            code: "EMP-" + suffix,
            module: "employees",
            organizationId: company.id,
            email: "employee@example.invalid",
            phone: "000",
          });
          const vendor = await iamApi("/shared-masters", {
            name: "Shared supplier " + suffix,
            code: "V-" + suffix,
            module: "vendors",
            organizationId: company.id,
          });
          const archived = await iamApi(
            "/shared-masters/" + vendor.id,
            { ...vendor, status: "Inactive" },
            200,
            "PUT",
          );
          assert.equal(archived.status, "Inactive");
          const changed = await iamApi(
            "/shared-masters/" + unit.id,
            { ...unit, name: "Updated unit " + suffix },
            200,
            "PUT",
          );
          assert.equal(changed.revision, 2);
          await iamApi(
            "/shared-masters/" + unit.id,
            { ...unit, name: "Stale" },
            409,
            "PUT",
          );
          await iamApi(
            "/shared-masters/" + company.id,
            { ...company, status: "Inactive" },
            409,
            "PUT",
          );
          const read = await iamApi(
            "/shared-masters?module=hierarchy&page=1&pageSize=1",
          );
          assert.equal(read.items.length, 1);
          assert.ok(read.total >= 2);
          const limited = await models.User.create({
            employeeCode: "limited-" + suffix,
            employeeName: "Limited " + suffix,
            authCode: sourcePasswordHash,
            isActive: true,
          });
          const role = await models.Role.create({
            name: "Read only " + suffix,
            enabled: true,
          });
          const grants = [];
          for (const name of ["MMMS-APP", "MASTERS-READ"]) {
            const [p] = await models.Permission.findOrCreate({
              where: { name },
              defaults: { enabled: true },
            });
            grants.push(p);
          }
          await role.setPermissions(grants);
          await limited.setRoles([role]);
          await models.UserAccessScope.create({
            userId: limited.id,
            applicationName: "MMMS",
            organizationId: company.id,
            factoryId: factory.id,
            enabled: true,
          });
          logged = await iamApi("/users/login", {
            employeeCode: limited.employeeCode,
            authCode: password,
          });
          const ownerToken = erpToken;
          erpToken = logged.token;
          const own = await iamApi("/shared-masters?pageSize=100");
          assert.ok(
            own.items.every(
              (r) => r.organizationId === company.id || r.id === company.id,
            ),
          );
          await iamApi(
            "/shared-masters",
            { name: "Forbidden", code: "X-" + suffix, unitType: "Company" },
            403,
          );
          erpToken = ownerToken;
        },
      );
      await t.test(
        "nine hierarchy catalogs enforce per-page reads, writes, parent lookups and licensed navigation",
        async () => {
          const entries = [
            ["companies", "Company", null],
            ["business-units", "Business Unit", "Company"],
            ["factories", "Factory", "Business Unit"],
            ["buildings", "Building", "Factory"],
            ["floors", "Floor", "Building"],
            ["departments", "Department", "Floor"],
            ["sections", "Production Section", "Department"],
            ["lines", "Production Line", "Production Section"],
            ["locations", "Machine Location", "Production Line"],
          ];
          const tree = {};
          for (const [page, type, parent] of entries) {
            tree[type] = await iamApi("/shared-masters", {
              name: "Hierarchy " + page + " " + suffix,
              code: page + "-" + suffix,
              unitType: type,
              parentId: parent ? tree[parent].id : null,
            });
            const result = await iamApi(
              "/shared-masters?module=hierarchy&unitType=" +
                encodeURIComponent(type) +
                "&pageSize=1",
            );
            assert.equal(result.items.length, 1);
            assert.ok(result.items.every((row) => row.unitType === type));
            assert.ok(result.total >= 1);
          }
          await api(
            "/applications/MASTERS",
            {
              name: "MASTERS",
              required_permission: "MASTERS-APP",
              landing_route: "/masters",
              navigation: entries.map(([page]) => ({
                label: page,
                link: "/masters/" + page,
                icon: "bi-building",
                permission: "MASTERS-" + page.toUpperCase() + "-READ",
              })),
            },
            200,
            "PUT",
          );
          require("../../authguardv2-node/src/services/subscription-access").resetCache();
          const limited = await models.User.create({
            employeeCode: "hierarchy-" + suffix,
            employeeName: "Hierarchy editor " + suffix,
            authCode: sourcePasswordHash,
            isActive: true,
          });
          const role = await models.Role.create({
            name: "Department editor " + suffix,
            enabled: true,
          });
          const grants = [];
          for (const name of [
            "MASTERS-APP",
            "MASTERS-DEPARTMENTS-READ",
            "MASTERS-DEPARTMENTS-MANAGE",
          ]) {
            const [permission] = await models.Permission.findOrCreate({
              where: { name },
              defaults: { appname: "MASTERS", enabled: true },
            });
            grants.push(permission);
          }
          await role.setPermissions(grants);
          await limited.setRoles([role]);
          await models.UserAccessScope.create({
            userId: limited.id,
            applicationName: "MASTERS",
            organizationId: tree.Company.id,
            factoryId: tree.Factory.id,
            enabled: true,
          });
          const ownerToken = erpToken;
          try {
            const login = await iamApi("/users/login", {
              employeeCode: limited.employeeCode,
              authCode: password,
            });
            erpToken = login.token;
            const workspace = await iamApi("/applications/workspace");
            const menu = workspace.navigation.find(
              (app) => app.applicationName === "MASTERS",
            );
            assert.deepEqual(
              menu.navbarItems.map((item) => item.link),
              ["/masters/departments"],
            );
            const rows = await iamApi(
              "/shared-masters?module=hierarchy&pageSize=100",
            );
            assert.ok(rows.items.length > 0);
            assert.ok(
              rows.items.every(
                (row) =>
                  row.unitType === "Department" &&
                  row.organizationId === tree.Company.id,
              ),
            );
            await iamApi(
              "/shared-masters?module=hierarchy&unitType=Factory",
              undefined,
              403,
            );
            assert.equal(
              (await iamApi("/shared-masters?module=organization")).items
                .length,
              0,
            );
            await iamApi(
              "/shared-masters?module=hierarchy&lookupFor=Factory",
              undefined,
              403,
            );
            const options = await iamApi(
              "/shared-masters?module=hierarchy&lookupFor=Department",
            );
            assert.ok(options.items.some((row) => row.id === tree.Floor.id));
            assert.ok(
              options.items.every((row) =>
                ["Company", "Factory", "Floor"].includes(row.unitType),
              ),
            );
            assert.ok(
              options.items.every(
                (row) => row.email === undefined && row.phone === undefined,
              ),
            );
            const department = await iamApi("/shared-masters", {
              name: "Permitted department " + suffix,
              code: "PERM-" + suffix,
              unitType: "Department",
              parentId: tree.Floor.id,
            });
            const updated = await iamApi(
              "/shared-masters/" + department.id,
              { ...department, name: "Edited department " + suffix },
              200,
              "PUT",
            );
            assert.equal(updated.revision, 2);
            await iamApi(
              "/shared-masters",
              {
                name: "Forbidden building",
                code: "DENY-" + suffix,
                unitType: "Building",
                parentId: tree.Factory.id,
              },
              403,
            );
            await iamApi(
              "/shared-masters/" + tree.Factory.id,
              { ...tree.Factory, name: "Forbidden factory" },
              403,
              "PUT",
            );
            await iamApi(
              "/shared-masters",
              {
                name: "Foreign scope",
                code: "FOREIGN-" + suffix,
                unitType: "Department",
                parentId: factory.id,
              },
              403,
            );
          } finally {
            erpToken = ownerToken;
          }
        },
      );
      await t.test(
        "legacy adoption preserves identities/passwords and supports reviewed rollback",
        async () => {
          let preview = (await api(`/instances/${instance.id}/legacy-preview`))
            .body;
          await api(
            `/instances/${instance.id}/legacy-adopt`,
            { source_hash: "outdated", user_ids: [String(legacyUser.id)] },
            409,
          );
          await api(`/instances/${instance.id}/legacy-adopt`, {
            source_hash: preview.source_hash,
            user_ids: [String(legacyUser.id)],
          });
          const user = await models.User.unscoped().findByPk(legacyUser.id);
          assert.equal(user.authCode, sourcePasswordHash);
          assert.equal(user.employeeCode, legacyUser.employeeCode);
          assert.ok(await models.Role.findByPk(legacyRole.id));
          await iamApi("/runtime/access", undefined, 401);
          logged = await iamApi("/users/login", {
            employeeCode: legacyUser.employeeCode,
            authCode: password,
          });
          erpToken = logged.token;
          assert.ok(
            logged.result.accessScopes.some((s) => s.factoryId === factory.id),
          );
          assert.ok(
            !logged.result.roles.some((r) =>
              r.permissions.some((p) => p.name === "*"),
            ),
          );
          await api(`/instances/${instance.id}/legacy-rollback`, {
            user_ids: [String(legacyUser.id)],
          });
          assert.equal(
            (
              await models.User.findByPk(legacyUser.id, {
                include: [{ model: models.Role, as: "roles" }],
              })
            ).roles[0].id,
            legacyRole.id,
          );
        },
      );
      await t.test(
        "two-phase activation-key rotation keeps access until IAM confirms the new key",
        async () => {
          const rotation = (
            await api(`/instances/${instance.id}/key-rotation`, {})
          ).body;
          await api(`/instances/${instance.id}/key-rotation/commit`, {}, 409);
          const licenseUrl = `${base}/internal/instances/${instance.id}/entitlements`;
          for (const key of [
            instance.activation_key,
            rotation.activation_key,
          ]) {
            const response = await fetch(licenseUrl, {
              headers: { Authorization: "Bearer " + key },
            });
            assert.equal(response.status, 200);
          }
          process.env.CONTROL_INSTANCE_KEY = rotation.activation_key;
          await api(`/instances/${instance.id}/key-rotation/commit`, {});
          const old = await fetch(licenseUrl, {
            headers: { Authorization: "Bearer " + instance.activation_key },
          });
          assert.equal(old.status, 401);
        },
      );
      await t.test(
        "MMMS consumes common IDs as a read-only projection and fails closed when unavailable",
        async () => {
          process.env.PLATFORM_MASTERS_MODE = "shared";
          const fresh = (
            await api("/instances/" + instance.id + "/legacy-preview")
          ).body;
          await api("/instances/" + instance.id + "/legacy-adopt", {
            source_hash: fresh.source_hash,
            user_ids: [String(legacyUser.id)],
          });
          logged = await iamApi("/users/login", {
            employeeCode: legacyUser.employeeCode,
            authCode: password,
          });
          erpToken = logged.token;
          const projection = require("../../mmms-backend/src/services/shared-master-projection");
          await projection.sync(true);
          const { MasterRecord } = require("../../mmms-backend/src/models");
          const projected = await MasterRecord.findByPk(factory.id);
          assert.equal(projected.organizationId, company.id);
          assert.equal(projected.data.sharedMaster, true);
          const options = (
            await api(`/instances/${instance.id}/master-options`)
          ).body;
          assert.ok(
            options.factories.some(
              (f) => f.id === factory.id && f.organization_id === company.id,
            ),
          );
          await api(
            "/customer-roles",
            {
              customer_id: customer,
              name: "Scoped operator " + suffix,
              permission_codes: ["MMMS-APP", "MASTERS-READ"],
            },
            201,
          );
          await api(`/instances/${instance.id}/sync-roles`, {});
          const employeeBody = {
            username: "scoped-" + suffix,
            display_name: "Scoped console employee " + suffix,
            password,
            roles: ["Scoped operator " + suffix],
            scopes: [
              {
                applicationName: "MMMS",
                organizationId: company.id,
                factoryId: "invalid-factory",
              },
            ],
          };
          await api(`/instances/${instance.id}/users`, employeeBody, 422);
          employeeBody.scopes[0].factoryId = factory.id;
          await api(`/instances/${instance.id}/users`, employeeBody, 201);
          // Provisioning may synchronize licensed roles and deliberately invalidate old sessions.
          logged = await iamApi("/users/login", {
            employeeCode: legacyUser.employeeCode,
            authCode: password,
          });
          erpToken = logged.token;
          const mmmsServer = require("../../mmms-backend/src/app").listen(
            0,
            "127.0.0.1",
          );
          await new Promise((r) => mmmsServer.once("listening", r));
          try {
            const url = "http://127.0.0.1:" + mmmsServer.address().port + "/v1";
            const headers = {
              Authorization: "Bearer " + erpToken,
              "Content-Type": "application/json",
            };
            const body = {
              employeeNumber: "EMP-" + suffix,
              name: "Client name cannot override master",
              organizationId: company.id,
              factoryId: factory.id,
              skillCategories: ["Sewing"],
              details: {},
            };
            let r = await fetch(url + "/technicians", {
              method: "POST",
              headers,
              body: JSON.stringify(body),
            });
            const technician = await r.json();
            assert.equal(r.status, 201, JSON.stringify(technician));
            assert.equal(technician.result.name, "Shared person " + suffix);
            assert.ok(technician.result.details.employeeId);
            r = await fetch(url + "/spare-parts", {
              method: "POST",
              headers,
              body: JSON.stringify({
                name: "Common unit part " + suffix,
                category: "General",
                reorderLevel: 0,
                unitCost: 1,
                organizationId: company.id,
                factoryId: factory.id,
                details: { unit: "Each" },
              }),
            });
            const part = await r.json();
            assert.equal(r.status, 201, JSON.stringify(part));
            assert.ok(part.result.details.unitId);
            r = await fetch(url + "/master-data/units", {
              method: "POST",
              headers,
              body: JSON.stringify({ name: "Forbidden" }),
            });
            assert.equal(r.status, 409);
          } finally {
            await new Promise((r) => mmmsServer.close(r));
          }

          const rejected = await new Promise((resolve) =>
            projection.middleware(
              { path: "/hierarchy", method: "POST", body: {} },
              {},
              resolve,
            ),
          );
          assert.equal(rejected.status, 409);
          await models.sequelize.query(
            "INSERT INTO app_shared_master_references(consumer,record_id,reference_count) VALUES(:consumer,:id,1) ON CONFLICT(consumer,record_id) DO UPDATE SET reference_count=1",
            { replacements: { consumer: "MMMS", id: factory.id } },
          );
          await iamApi(
            "/shared-masters/" + factory.id,
            { ...factory, status: "Inactive" },
            409,
            "PUT",
          );
          process.env.IAM_API_URL = "http://127.0.0.1:1";
          await assert.rejects(projection.sync(true), (e) => e.status === 503);
          process.env.IAM_API_URL = iamOrigin;
        },
      );
      await t.test(
        "ERP IAM administration stays local and inside commercial limits",
        async () => {
          const workspace = await iamApi("/applications/workspace");
          assert.ok(workspace.result.some((a) => a.applicationName === "IAM"));
          const nav = workspace.navigation.find(
            (a) => a.applicationName === "IAM",
          );
          assert.ok(nav.navbarItems.some((n) => n.link === "/adminv2/user"));
          assert.ok(
            nav.navbarItems.every((n) => !n.link.includes("subscription")),
          );
          const directory = (await iamApi("/users")).result;
          assert.ok(
            directory.some((u) => String(u.id) === String(legacyUser.id)),
          );
          assert.ok(directory.every((u) => !Object.hasOwn(u, "authCode")));
          const options = (await iamApi("/users/access-options")).result;
          assert.ok(options.factories.some((f) => f.id === factory.id));
          const permissionCatalog = (await iamApi("/permissions")).result;
          assert.ok(permissionCatalog.some((p) => p.name === "IAM-APP"));
          assert.ok(!permissionCatalog.some((p) => p.name === "*"));
          const appPermission = permissionCatalog.find(
            (p) => p.name === "MMMS-APP",
          );
          const delegateRole = (
            await iamApi("/roles", {
              name: "Delegated roles " + suffix,
              permissionIds: permissionCatalog
                .filter((p) => ["IAM-APP", "roles:manage"].includes(p.name))
                .map((p) => p.id),
            })
          ).result;
          const delegate = (
            await iamApi("/users", {
              employeeCode: "iam-delegate-" + suffix,
              employeeName: "IAM delegate " + suffix,
              authCode: password,
              roleIds: [delegateRole.id],
            })
          ).result;
          const administratorToken = erpToken;
          const delegateLogin = await iamApi("/users/login", {
            employeeCode: delegate.employeeCode,
            authCode: password,
          });
          const protectedRole = await models.Role.findOne({
            where: { name: "IAM Identity Administrator" },
          });
          try {
            erpToken = delegateLogin.token;
            await iamApi(
              "/roles/" + protectedRole.id,
              {
                name: protectedRole.name,
                permissionIds: delegateRole.permissions.map((p) => p.id),
              },
              403,
              "PUT",
            );
          } finally {
            erpToken = administratorToken;
          }
          await iamApi(
            "/users/" + delegate.id + "/status?enable=false",
            {},
            200,
            "PATCH",
          );
          const denied = await models.Permission.create({
            name: "UNPURCHASED-" + suffix,
            enabled: true,
          });
          await iamApi(
            "/roles",
            { name: "Invalid IAM " + suffix, permissionIds: [denied.id] },
            403,
          );
          const role = (
            await iamApi("/roles", {
              name: "Local operator " + suffix,
              permissionIds: [appPermission.id],
            })
          ).result;
          const created = (
            await iamApi("/users", {
              employeeCode: "iam-" + suffix,
              employeeName: "IAM operator " + suffix,
              authCode: password,
              roleIds: [role.id],
            })
          ).result;
          await iamApi(
            "/users/" + created.id + "/scopes",
            {
              scopes: [
                {
                  applicationName: "MMMS",
                  organizationId: company.id,
                  factoryId: randomUUID(),
                },
              ],
            },
            422,
            "PUT",
          );
          await iamApi(
            "/users/" + created.id + "/scopes",
            {
              scopes: [
                {
                  applicationName: "MMMS",
                  organizationId: company.id,
                  factoryId: factory.id,
                },
              ],
            },
            200,
            "PUT",
          );
          let employeeLogin = await iamApi("/users/login", {
            employeeCode: created.employeeCode,
            authCode: password,
          });
          const adminToken = erpToken;
          erpToken = employeeLogin.token;
          const employeeWorkspace = await iamApi("/applications/workspace");
          assert.ok(
            !employeeWorkspace.result.some((a) => a.applicationName === "IAM"),
          );
          await iamApi("/users", undefined, 403);
          erpToken = adminToken;
          await iamApi(
            "/users/" + created.id,
            {
              employeeCode: created.employeeCode,
              employeeName: "Updated IAM " + suffix,
              roleIds: [role.id],
            },
            200,
            "PUT",
          );
          erpToken = employeeLogin.token;
          await iamApi("/runtime/access", undefined, 401);
          erpToken = adminToken;
          await iamApi(
            "/roles/" + role.id,
            { name: role.name, permissionIds: [appPermission.id] },
            200,
            "PUT",
          );
          await iamApi(
            "/users/" + created.id + "/status?enable=false",
            {},
            200,
            "PATCH",
          );
          await iamApi(
            "/users/login",
            { employeeCode: created.employeeCode, authCode: password },
            403,
          );
          const licensing = require("../../authguardv2-node/src/services/subscription-access");
          const originalEntitlements =
            require("../src/subscriptions").entitlements;
          // A real provider plan snapshot change must also constrain direct IAM creation/reactivation.
          const subId = (await originalEntitlements(instance.id))
            .subscription_id;
          const original = (
            await query(
              "SELECT plan_snapshot FROM control_subscriptions WHERE id=$1",
              [subId],
            )
          ).rows[0].plan_snapshot;
          const activeCount = await models.User.count({
            where: { isActive: true },
          });
          try {
            await query(
              "UPDATE control_subscriptions SET plan_snapshot=jsonb_set(plan_snapshot,'{max_users}',$2::jsonb) WHERE id=$1",
              [subId, JSON.stringify(activeCount)],
            );
            licensing.resetCache();
            await iamApi(
              "/users/" + created.id + "/status?enable=true",
              {},
              409,
              "PATCH",
            );
            await iamApi(
              "/users",
              {
                employeeCode: "full-" + suffix,
                employeeName: "Full " + suffix,
                authCode: password,
                roleIds: [role.id],
              },
              409,
            );
          } finally {
            await query(
              "UPDATE control_subscriptions SET plan_snapshot=$2 WHERE id=$1",
              [subId, original],
            );
            licensing.resetCache();
          }
          await iamApi(
            "/users/" + created.id + "/status?enable=true",
            {},
            200,
            "PATCH",
          );
          const oldLogin = await iamApi("/users/login", {
            employeeCode: created.employeeCode,
            authCode: password,
          });
          await iamApi(
            "/roles/" + role.id + "/status?enable=false",
            {},
            200,
            "PATCH",
          );
          erpToken = oldLogin.token;
          await iamApi("/runtime/access", undefined, 401);
          erpToken = adminToken;
          await iamApi(
            "/roles/" + role.id + "/status?enable=true",
            {},
            200,
            "PATCH",
          );
          await iamApi("/applications", { applicationName: "BYPASS" }, 409);
          await iamApi("/permissions", { name: "BYPASS" }, 409);
          const all = await models.User.findAll({
            where: { isActive: true },
            include: [
              {
                model: models.Role,
                as: "roles",
                include: [{ model: models.Permission, as: "permissions" }],
              },
            ],
          });
          const local =
            require("../../authguardv2-node/src/services/iam-access.service").localPermissions;
          const otherAdmins = all
            .filter((u) => String(u.id) !== String(legacyUser.id))
            .filter((u) => {
              const grants = u.roles
                .filter((r) => r.enabled)
                .flatMap((r) =>
                  r.permissions.filter((p) => p.enabled).map((p) => p.name),
                );
              return (
                grants.includes("*") || local.every((p) => grants.includes(p))
              );
            })
            .map((u) => u.id);
          try {
            if (otherAdmins.length)
              await models.User.update(
                { isActive: false },
                { where: { id: otherAdmins } },
              );
            await iamApi(
              "/users/" + legacyUser.id + "/status?enable=false",
              {},
              409,
              "PATCH",
            );
            const adminRole = await models.Role.findOne({
              where: { name: "IAM Identity Administrator" },
            });
            await iamApi(
              "/roles/" + adminRole.id + "/status?enable=false",
              {},
              409,
              "PATCH",
            );
          } finally {
            if (otherAdmins.length)
              await models.User.update(
                { isActive: true },
                { where: { id: otherAdmins } },
              );
          }
          await iamApi("/users/" + created.id, {}, 200, "DELETE");
          assert.ok(await models.User.findByPk(created.id));
        },
      );
      await t.test(
        "operator editing, disabling and reactivation invalidate stale sessions",
        async () => {
          const operator = (
            await api(
              "/operators",
              {
                username: "operator-" + suffix,
                display_name: "Staff " + suffix,
                password,
                role: "platform_staff",
              },
              201,
            )
          ).body;
          const old = await api(
            "/auth/login",
            { username: "operator-" + suffix, password },
            200,
            "POST",
            {},
          );
          const oldHeaders = {
            Cookie: old.response.headers.get("set-cookie").split(";")[0],
            "X-CSRF-Token": old.body.csrfToken,
          };
          await api(
            "/operators/" + operator.id,
            {
              display_name: "Approver " + suffix,
              password: "",
              role: "approver",
            },
            200,
            "PUT",
          );
          await api("/auth/session", undefined, 401, "GET", oldHeaders);
          await api("/operators/" + operator.id + "/disable", {});
          await api(
            "/auth/login",
            { username: "operator-" + suffix, password },
            401,
            "POST",
            {},
          );
          await api("/operators/" + operator.id + "/enable", {});
          await api(
            "/auth/login",
            { username: "operator-" + suffix, password },
            200,
            "POST",
            {},
          );
        },
      );
    } finally {
      await Promise.all([
        new Promise((r) => server.close(r)),
        new Promise((r) => iam.close(r)),
      ]);
      await pool.end();
      await require("../../authguardv2-node/src/services/telemetry.service").drainTelemetry();
      await models.sequelize.close();
      if (require.cache[require.resolve("../../mmms-backend/src/models")])
        await require("../../mmms-backend/src/models").sequelize.close();
    }
  },
);
