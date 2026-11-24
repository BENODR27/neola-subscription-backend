const { Router } = require("express");
const { query, transaction } = require("./database");
const { action } = require("./auth");
const s = require("./security");
const { audit, list, id, integer, randomUUID } = require("./common");
const router = Router();
const staff = s.allow("platform_owner", "platform_staff");
function code(value) {
  const result = s.text(value, "Code");
  s.requireValue(
    /^[a-zA-Z0-9][a-zA-Z0-9:_-]{1,179}$/.test(result) &&
      !["superadmin", "*"].includes(result.toLowerCase()),
    "Use a stable application/permission code; wildcard and superadmin grants cannot be sold",
  );
  return result;
}
function internalRoute(value) {
  s.requireValue(
    typeof value === "string" && /^\/(?!\/)[a-zA-Z0-9/_-]*$/.test(value),
    "Use an internal ERP route, for example /mmms",
  );
  return value;
}
async function validateEntitlements(input, db = { query }) {
  s.requireValue(
    input &&
      Array.isArray(input.applications) &&
      Array.isArray(input.permissions),
    "Choose applications and permissions",
  );
  const applications = [...new Set(input.applications.map(code))];
  const enforced = (process.env.CONTROL_ENFORCED_APPLICATIONS || "MMMS")
    .split(",")
    .map((v) => v.trim());
  s.requireValue(
    applications.every((app) => enforced.includes(app)),
    "An application has not been enabled for verified subscription enforcement",
  );
  const permissions = [...new Set(input.permissions.map(code))];
  s.requireValue(
    applications.length > 0 &&
      applications.length <= 100 &&
      permissions.length <= 10000,
    "Choose 1–100 applications and at most 10000 permissions",
  );
  const apps = await db.query(
    "SELECT code,required_permission FROM control_applications WHERE code=ANY($1) AND enabled",
    [applications],
  );
  s.requireValue(
    apps.rowCount === applications.length,
    "An application is unavailable",
  );
  s.requireValue(
    apps.rows.every(
      (app) =>
        app.required_permission &&
        permissions.includes(app.required_permission),
    ),
    "Include each application’s entry permission in the plan",
  );
  const grants = await db.query(
    "SELECT code,application_code FROM control_permissions WHERE code=ANY($1) AND enabled",
    [permissions],
  );
  s.requireValue(
    grants.rowCount === permissions.length &&
      grants.rows.every((p) => applications.includes(p.application_code)),
    "Every permission must belong to a selected, enabled application",
  );
  return { applications, permissions };
}
router.get(
  "/applications",
  action(async (req, res) =>
    res.json(
      await list(req, "control_applications", "*", {
        order: "name,code",
        where: req.user.role === "customer_owner" ? ["enabled"] : [],
      }),
    ),
  ),
);
router.put(
  "/applications/:code",
  staff,
  action(async (req, res) => {
    const appCode = code(req.params.code);
    s.requireValue(appCode.length <= 80, "Application code is too long");
    const navigation = req.body.navigation || [];
    s.requireValue(
      Array.isArray(navigation) && navigation.length <= 100,
      "Navigation must be a list of at most 100 items",
    );
    const normalized = navigation.map((n) => ({
      label: s.text(n.label, "Navigation label"),
      link: internalRoute(n.link),
      icon: s.text(n.icon || "bi-grid", "Icon", 80),
      permission: code(n.permission),
    }));
    await transaction(async (db) => {
      await db.query(
        `INSERT INTO control_applications(code,name,description,icon,landing_route,navigation,enabled) VALUES($1,$2,$3,$4,$5,$6,$7)
      ON CONFLICT(code) DO UPDATE SET name=excluded.name,description=excluded.description,icon=excluded.icon,landing_route=excluded.landing_route,navigation=excluded.navigation,enabled=excluded.enabled`,
        [
          appCode,
          s.text(req.body.name, "Application name"),
          String(req.body.description || "").slice(0, 4000),
          s.text(req.body.icon || "bi-grid", "Icon", 80),
          internalRoute(req.body.landing_route),
          JSON.stringify(normalized),
          req.body.enabled !== false,
        ],
      );
      await db.query(
        "UPDATE control_applications SET required_permission=$2 WHERE code=$1",
        [appCode, code(req.body.required_permission)],
      );
      await audit(db, req.user, "application.saved", appCode, null);
    });
    res.json({ message: "Application saved" });
  }),
);
router.get(
  "/permissions",
  action(async (req, res) =>
    res.json(
      await list(req, "control_permissions", "*", {
        order: "application_code,code",
        where: req.user.role === "customer_owner" ? ["enabled"] : [],
      }),
    ),
  ),
);
router.put(
  "/permissions/:code",
  staff,
  action(async (req, res) => {
    const permission = code(req.params.code),
      app = code(req.body.application_code);
    await transaction(async (db) => {
      await db.query(
        `INSERT INTO control_permissions(code,application_code,description,enabled) VALUES($1,$2,$3,$4)
      ON CONFLICT(code) DO UPDATE SET application_code=excluded.application_code,description=excluded.description,enabled=excluded.enabled`,
        [
          permission,
          app,
          String(req.body.description || "").slice(0, 4000),
          req.body.enabled !== false,
        ],
      );
      await audit(db, req.user, "permission.saved", permission, null);
    });
    res.json({ message: "Permission saved" });
  }),
);
router.get(
  "/plans",
  action(async (req, res) =>
    res.json(
      await list(req, "control_plans", "*", {
        where: req.user.role === "customer_owner" ? ["published"] : [],
      }),
    ),
  ),
);
router.post(
  "/plans",
  staff,
  action(async (req, res) => savePlan(req, res)),
);
router.put(
  "/plans/:id",
  staff,
  action(async (req, res) => savePlan(req, res)),
);
async function savePlan(req, res) {
  const recordId = req.params.id ? id(req.params.id) : randomUUID(),
    b = req.body;
  s.requireValue(
    Intl.supportedValuesOf("currency").includes(b.currency),
    "Choose a supported ISO currency code",
  );
  s.requireValue(
    typeof b.currency === "string" && /^[A-Z]{3}$/.test(b.currency),
    "Use a three-letter currency such as USD",
  );
  await transaction(async (db) => {
    const entitlements = await validateEntitlements(b.entitlements, db);
    const values = [
      recordId,
      s.text(b.name, "Plan name"),
      String(b.description || "").slice(0, 4000),
      integer(b.price_minor, 0, 100000000000, "Price in minor units"),
      b.currency,
      integer(b.duration_months, 1, 36, "Duration in months"),
      integer(b.trial_days, 0, 90, "Trial days"),
      integer(b.max_users, 1, 100000, "User limit"),
      JSON.stringify(entitlements),
      b.published === true,
    ];
    if (req.params.id) {
      const result = await db.query(
        `UPDATE control_plans SET name=$2,description=$3,price_minor=$4,currency=$5,duration_months=$6,trial_days=$7,max_users=$8,entitlements=$9,published=$10,version=version+1,updated_at=now() WHERE id=$1`,
        values,
      );
      s.requireValue(result.rowCount, "Plan not found", 404);
    } else
      await db.query(
        "INSERT INTO control_plans(id,name,description,price_minor,currency,duration_months,trial_days,max_users,entitlements,published) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        values,
      );
    await audit(db, req.user, "plan.saved", recordId, null);
  });
  res.status(req.params.id ? 200 : 201).json({ id: recordId });
}
module.exports = { router, validateEntitlements };
