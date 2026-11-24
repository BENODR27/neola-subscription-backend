const { Router } = require("express");
const { query, transaction } = require("./database");
const { action } = require("./auth");
const s = require("./security");
const { scopedRecord, audit, id } = require("./common");
const { allowedOrigin, entitlements } = require("./subscriptions");
const router = Router();
async function call(instance, path, body, method = "GET") {
  s.requireValue(
    instance.enabled && instance.api_origin,
    "ERP instance is disabled or has no API origin",
    409,
  );
  const origin = allowedOrigin(instance.api_origin);
  let response;
  const send = (key) =>
    fetch(`${origin}/v3/api/auth/internal/control${path}`, {
      method,
      signal: AbortSignal.timeout(10000),
      redirect: "error",
      headers: {
        Authorization: `Bearer ${s.decrypt(key)}`,
        "Content-Type": "application/json",
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
  try {
    response = await send(instance.encrypted_key);
    if (response.status === 401 && instance.encrypted_pending_key)
      response = await send(instance.encrypted_pending_key);
  } catch {
    throw new s.Problem(
      502,
      "ERP instance is unavailable. Verify its origin and integration settings.",
    );
  }
  const result = await response.json();
  s.requireValue(
    response.ok,
    result.message || result.error?.message || "ERP request was rejected",
    response.status >= 500 ? 502 : response.status,
  );
  return result;
}
const owners = s.allow("platform_owner", "platform_staff", "customer_owner");
router.get('/instances/:id/master-options',owners,action(async(req,res)=>{const instance=await scopedRecord({query},'control_instances',req.params.id,req.user);res.json(await call(instance,'/master-options'));}));
router.post(
  "/instances/:id/import-catalog",
  s.allow("platform_owner", "platform_staff"),
  action(async (req, res) => {
    const instance = await scopedRecord(
      { query },
      "control_instances",
      req.params.id,
      req.user,
    );
    const source = await call(instance, "/catalog");
    await transaction(async (db) => {
      for (const app of source.applications) {
        if (
          !app.requiredPermission ||
          ["superadmin", "*"].includes(app.requiredPermission) ||
          !/^[a-zA-Z0-9][a-zA-Z0-9:_-]{1,79}$/.test(app.applicationName)
        )
          continue;
        const navigation = source.navigation.find(
          (n) => n.applicationName === app.applicationName,
        );
        if (!navigation) continue;
        await db.query(
          `INSERT INTO control_applications(code,name,icon,landing_route,navigation,required_permission) VALUES($1,$1,$2,$3,$4,$5) ON CONFLICT(code) DO NOTHING`,
          [
            app.applicationName,
            app.applicationIcon || "bi-grid",
            navigation.landingRoute,
            JSON.stringify(navigation.navbarItems),
            app.requiredPermission,
          ],
        );
        for (const permission of source.permissions) {
          if (
            !permission.enabled ||
            ["*", "superadmin"].includes(permission.name)
          )
            continue;
          if (
            permission.name !== app.requiredPermission &&
            permission.appname?.toUpperCase() !==
              app.applicationName.toUpperCase()
          )
            continue;
          await db.query(
            "INSERT INTO control_permissions(code,application_code,enabled) VALUES($1,$2,true) ON CONFLICT(code) DO NOTHING",
            [permission.name, app.applicationName],
          );
        }
      }
      await db.query(
        "UPDATE control_instances SET connected_at=now() WHERE id=$1",
        [instance.id],
      );
      await audit(
        db,
        req.user,
        "instance.catalog-imported",
        instance.id,
        instance.customer_id,
      );
    });
    res.json({
      message:
        "Imported missing applications and permissions. Existing console definitions were preserved.",
    });
  }),
);
router.post(
  "/instances/:id/sync-roles",
  owners,
  action(async (req, res) => {
    const instance = await scopedRecord(
      { query },
      "control_instances",
      req.params.id,
      req.user,
    );
    const license = await entitlements(instance.id);
    s.requireValue(license.active, "Active subscription required", 403);
    const roles = (
      await query("SELECT * FROM control_customer_roles WHERE customer_id=$1", [
        instance.customer_id,
      ])
    ).rows;
    for (const role of roles) {
      // A downgrade removes old grants instead of reintroducing permissions no longer purchased.
      await call(
        instance,
        `/roles/${encodeURIComponent(role.name)}`,
        {
          permissions: role.permission_codes.filter((p) =>
            license.permissions.includes(p),
          ),
          enabled: role.enabled,
        },
        "PUT",
      );
    }
    await transaction(async (db) => {
      await db.query(
        "UPDATE control_instances SET last_synced_at=now() WHERE id=$1",
        [instance.id],
      );
      await audit(
        db,
        req.user,
        "instance.roles-synced",
        instance.id,
        instance.customer_id,
        { count: roles.length },
      );
    });
    res.json({ message: `${roles.length} customer roles synchronized` });
  }),
);
router.get(
  "/instances/:id/users",
  owners,
  action(async (req, res) => {
    const instance = await scopedRecord(
      { query },
      "control_instances",
      req.params.id,
      req.user,
    );
    const page = Number(req.query.page || 1),
      pageSize = Number(req.query.pageSize || 12);
    s.requireValue(
      Number.isInteger(page) &&
        page > 0 &&
        Number.isInteger(pageSize) &&
        pageSize > 0 &&
        pageSize <= 100,
      "Invalid pagination",
    );
    res.json(
      await call(
        instance,
        `/users?page=${page}&pageSize=${pageSize}&search=${encodeURIComponent(String(req.query.search || ""))}`,
      ),
    );
  }),
);
router.post(
  "/instances/:id/users",
  owners,
  action(async (req, res) => {
    const instance = await scopedRecord(
      { query },
      "control_instances",
      req.params.id,
      req.user,
    );
    const { username, display_name, password, roles, scopes } = req.body;
    const result = await call(
      instance,
      "/users",
      { username, display_name, password, roles, scopes },
      "POST",
    );
    await audit(
      { query },
      req.user,
      "instance.user-created",
      instance.id,
      instance.customer_id,
      { username },
    );
    res.status(201).json(result);
  }),
);
router.patch(
  "/instances/:id/users/:userId",
  owners,
  action(async (req, res) => {
    const instance = await scopedRecord(
      { query },
      "control_instances",
      req.params.id,
      req.user,
    );
    s.requireValue(/^\d+$/.test(req.params.userId), "Invalid ERP user ID");
    const result = await call(
      instance,
      `/users/${req.params.userId}`,
      { enabled: req.body.enabled },
      "PATCH",
    );
    await audit(
      { query },
      req.user,
      "instance.user-status",
      instance.id,
      instance.customer_id,
      { user_id: req.params.userId, enabled: req.body.enabled },
    );
    res.json(result);
  }),
);
router.patch(
  "/customer-roles/:id",
  owners,
  action(async (req, res) => {
    await transaction(async (db) => {
      const role = await scopedRecord(
        db,
        "control_customer_roles",
        req.params.id,
        req.user,
        true,
      );
      s.requireValue(
        typeof req.body.enabled === "boolean",
        "Enabled status required",
      );
      let permissions = role.permission_codes;
      if (req.body.permission_codes !== undefined) {
        s.requireValue(
          Array.isArray(req.body.permission_codes) &&
            req.body.permission_codes.every((p) => typeof p === "string"),
          "Select permission codes",
        );
        await scopedRecord(
          db,
          "control_customers",
          role.customer_id,
          req.user,
          true,
        );
        const instances = (
          await db.query(
            "SELECT id FROM control_instances WHERE customer_id=$1 AND enabled",
            [role.customer_id],
          )
        ).rows;
        const allowed = new Set();
        for (const instance of instances)
          for (const code of (await entitlements(instance.id, db)).permissions)
            allowed.add(code);
        s.requireValue(
          req.body.permission_codes.every((p) => allowed.has(p)),
          "Role exceeds the active subscription permission ceiling",
          403,
        );
        permissions = [...new Set(req.body.permission_codes)];
      }
      await db.query(
        "UPDATE control_customer_roles SET enabled=$2,permission_codes=$3 WHERE id=$1",
        [role.id, req.body.enabled, JSON.stringify(permissions)],
      );
      await audit(
        db,
        req.user,
        "customer-role.updated",
        role.id,
        role.customer_id,
        { enabled: req.body.enabled },
      );
    });
    res.json({
      message:
        "Role status saved. Synchronize instance roles to apply the change to ERP users.",
    });
  }),
);
router.put(
  "/instances/:id/users/:userId",
  owners,
  action(async (req, res) => {
    const instance = await scopedRecord(
      { query },
      "control_instances",
      req.params.id,
      req.user,
    );
    s.requireValue(/^\d+$/.test(req.params.userId), "Invalid ERP user ID");
    const { display_name, password, roles, scopes } = req.body;
    const result = await call(
      instance,
      `/users/${req.params.userId}`,
      { display_name, password, roles, scopes },
      "PUT",
    );
    await audit(
      { query },
      req.user,
      "instance.user-updated",
      instance.id,
      instance.customer_id,
      { user_id: req.params.userId },
    );
    res.json(result);
  }),
);
router.get(
  "/instances/:id/legacy-preview",
  s.allow("platform_owner", "platform_staff"),
  action(async (req, res) => {
    const instance = await scopedRecord(
      { query },
      "control_instances",
      req.params.id,
      req.user,
    );
    const license = await entitlements(instance.id);
    const result = await call(instance, "/legacy-preview");
    result.items = result.items.map((u) => {
      const original = new Set(
        u.roles.filter((r) => r.enabled).flatMap((r) => r.permissions),
      );
      return {
        ...u,
        effective_permissions: license.permissions.filter(
          (p) => original.has("*") || original.has(p),
        ),
        excluded_permissions: [...original].filter(
          (p) => p !== "*" && !license.permissions.includes(p),
        ),
      };
    });
    res.json(result);
  }),
);
router.post(
  "/instances/:id/legacy-adopt",
  s.allow("platform_owner"),
  action(async (req, res) => {
    const instance = await scopedRecord(
      { query },
      "control_instances",
      req.params.id,
      req.user,
    );
    const license = await entitlements(instance.id);
    s.requireValue(license.active, "Active subscription required", 403);
    const preview = await call(instance, "/legacy-preview");
    s.requireValue(
      preview.source_hash === req.body.source_hash,
      "Preview changed. Reload before migration",
      409,
    );
    const result = await call(
      instance,
      "/legacy-adopt",
      { source_hash: req.body.source_hash, user_ids: req.body.user_ids },
      "POST",
    );
    await transaction(async (db) => {
      for (const user of preview.items.filter((u) =>
        req.body.user_ids.map(String).includes(u.id),
      )) {
        const original = new Set(
          user.roles.filter((r) => r.enabled).flatMap((r) => r.permissions),
        );
        const permissions = license.permissions.filter(
          (p) => original.has("*") || original.has(p),
        );
        await db.query(
          "INSERT INTO control_customer_roles(id,customer_id,name,permission_codes,enabled) VALUES($1,$2,$3,$4,true) ON CONFLICT(customer_id,name) DO NOTHING",
          [
            require("node:crypto").randomUUID(),
            instance.customer_id,
            `Legacy user ${user.id}`,
            JSON.stringify(permissions),
          ],
        );
      }
      await audit(
        db,
        req.user,
        "instance.legacy-adopted",
        instance.id,
        instance.customer_id,
        { user_ids: req.body.user_ids },
      );
    });
    res.json(result);
  }),
);
router.post(
  "/instances/:id/legacy-rollback",
  s.allow("platform_owner"),
  action(async (req, res) => {
    const instance = await scopedRecord(
      { query },
      "control_instances",
      req.params.id,
      req.user,
    );
    const result = await call(
      instance,
      "/legacy-rollback",
      { user_ids: req.body.user_ids },
      "POST",
    );
    await audit(
      { query },
      req.user,
      "instance.legacy-rollback",
      instance.id,
      instance.customer_id,
      { user_ids: req.body.user_ids },
    );
    res.json(result);
  }),
);
module.exports = router;
