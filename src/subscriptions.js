const { Router } = require("express");
const { randomBytes } = require("node:crypto");
const { query, transaction } = require("./database");
const { action } = require("./auth");
const s = require("./security");
const { id, audit, list, scopedRecord, randomUUID } = require("./common");
const { validateEntitlements } = require("./catalog");
const router = Router();
const staff = s.allow("platform_owner", "platform_staff");
const review = s.allow("platform_owner", "approver");
const owners = s.allow("platform_owner", "platform_staff", "customer_owner");
function allowedOrigin(value) {
  if (!value) return null;
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new s.Problem(400, "Invalid ERP API origin");
  }
  const origins = (process.env.CONTROL_ERP_ALLOWED_ORIGINS || "")
    .split(",")
    .map((x) => x.trim());
  s.requireValue(
    url.origin === value &&
      !url.username &&
      !url.password &&
      origins.includes(value) &&
      (url.protocol === "https:" ||
        (process.env.NODE_ENV !== "production" &&
          (["localhost", "127.0.0.1"].includes(url.hostname) ||
            process.env.CONTROL_ALLOW_HTTP_ERP === "true"))),
    "ERP origin must be explicitly allowed by the operator",
  );
  return value;
}
router.get(
  "/customers",
  action(async (req, res) =>
    res.json(
      await list(req, "control_customers", "*", {
        where: req.user.role === "customer_owner" ? ["id=$1"] : [],
        values:
          req.user.role === "customer_owner" ? [req.user.customer_id] : [],
      }),
    ),
  ),
);
router.patch(
  "/customers/:id",
  staff,
  action(async (req, res) => {
    s.requireValue(
      ["pending", "active", "suspended"].includes(req.body.status),
      "Choose pending, active or suspended",
    );
    await transaction(async (db) => {
      await scopedRecord(
        db,
        "control_customers",
        req.params.id,
        req.user,
        true,
      );
      await db.query("UPDATE control_customers SET status=$2 WHERE id=$1", [
        req.params.id,
        req.body.status,
      ]);
      await audit(
        db,
        req.user,
        "customer.status",
        req.params.id,
        req.params.id,
        { status: req.body.status },
      );
    });
    res.json({ message: "Customer status updated" });
  }),
);
const instanceFields =
  "id,customer_id,name,api_origin,enabled,connected_at,last_synced_at,created_at";
router.get(
  "/instances",
  action(async (req, res) =>
    res.json(
      await list(req, "control_instances", instanceFields, { customer: true }),
    ),
  ),
);
router.post(
  "/instances",
  staff,
  action(async (req, res) => {
    const instanceId = randomUUID(),
      key = randomBytes(32).toString("hex"),
      customerId = id(req.body.customer_id);
    await transaction(async (db) => {
      await scopedRecord(db, "control_customers", customerId, req.user, true);
      await db.query(
        "INSERT INTO control_instances(id,customer_id,name,api_origin,key_hash,encrypted_key) VALUES($1,$2,$3,$4,$5,$6)",
        [
          instanceId,
          customerId,
          s.text(req.body.name, "Instance name"),
          allowedOrigin(req.body.api_origin),
          s.hash(key),
          s.encrypt(key),
        ],
      );
      await audit(db, req.user, "instance.created", instanceId, customerId);
    });
    res.status(201).json({
      id: instanceId,
      activation_key: key,
      message:
        "Save this activation key securely. It will not be displayed again.",
    });
  }),
);
router.patch(
  "/instances/:id",
  staff,
  action(async (req, res) => {
    await transaction(async (db) => {
      const instance = await scopedRecord(
        db,
        "control_instances",
        req.params.id,
        req.user,
        true,
      );
      await db.query(
        "UPDATE control_instances SET name=$2,api_origin=$3,enabled=$4 WHERE id=$1",
        [
          instance.id,
          s.text(req.body.name, "Instance name"),
          allowedOrigin(req.body.api_origin),
          req.body.enabled !== false,
        ],
      );
      await audit(
        db,
        req.user,
        "instance.updated",
        instance.id,
        instance.customer_id,
      );
    });
    res.json({ message: "Instance updated" });
  }),
);
router.get(
  "/requests",
  action(async (req, res) =>
    res.json(await list(req, "control_requests", "*", { customer: true })),
  ),
);
router.post(
  "/requests",
  owners,
  action(async (req, res) => {
    if (
      req.user.role === "customer_owner" &&
      (process.env.CONTROL_REQUIRE_VERIFIED_EMAIL === "true" ||
        process.env.NODE_ENV === "production")
    )
      s.requireValue(
        req.user.email_verified,
        "Verify your email in Account & security before requesting a plan",
        403,
      );
    const requestId = randomUUID();
    s.requireValue(
      ["purchase", "trial"].includes(req.body.kind),
      "Choose purchase or trial",
    );
    await transaction(async (db) => {
      const instance = await scopedRecord(
        db,
        "control_instances",
        req.body.instance_id,
        req.user,
        true,
      );
      s.requireValue(instance.enabled, "Instance is disabled");
      const customer = await scopedRecord(
        db,
        "control_customers",
        instance.customer_id,
        req.user,
        true,
      );
      s.requireValue(
        customer.status !== "suspended",
        "Customer account is suspended",
        403,
      );
      const {
        rows: [plan],
      } = await db.query(
        "SELECT * FROM control_plans WHERE id=$1 AND published FOR SHARE",
        [id(req.body.plan_id)],
      );
      s.requireValue(plan, "Plan is not available");
      await validateEntitlements(plan.entitlements, db);
      if (req.body.kind === "trial") {
        s.requireValue(plan.trial_days > 0, "This plan does not offer a trial");
        const previous = await db.query(
          "SELECT 1 FROM control_subscriptions WHERE customer_id=$1 AND kind='trial'",
          [instance.customer_id],
        );
        s.requireValue(
          !previous.rowCount,
          "A customer can receive only one approved trial",
          409,
        );
      }
      await db.query(
        "INSERT INTO control_requests(id,customer_id,instance_id,plan_id,kind,plan_snapshot,requested_by,renewal_mode) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",
        [
          requestId,
          instance.customer_id,
          instance.id,
          plan.id,
          req.body.kind,
          JSON.stringify(plan),
          req.user.id,
          req.body.renewal_mode || "immediate",
        ],
      );
      await audit(
        db,
        req.user,
        "request.created",
        requestId,
        instance.customer_id,
        { kind: req.body.kind, plan_version: plan.version },
      );
    });
    res.status(201).json({ id: requestId });
  }),
);
router.post(
  "/requests/:id/cancel",
  owners,
  action(async (req, res) => {
    await transaction(async (db) => {
      const request = await scopedRecord(
        db,
        "control_requests",
        req.params.id,
        req.user,
        true,
      );
      s.requireValue(
        request.status === "pending",
        "Only pending requests can be cancelled",
        409,
      );
      await db.query(
        "UPDATE control_requests SET status='cancelled' WHERE id=$1",
        [request.id],
      );
      await audit(
        db,
        req.user,
        "request.cancelled",
        request.id,
        request.customer_id,
      );
    });
    res.json({ message: "Request cancelled" });
  }),
);
router.post(
  "/requests/:id/review",
  review,
  action(async (req, res) => {
    s.requireValue(
      ["approved", "rejected"].includes(req.body.decision),
      "Choose approved or rejected",
    );
    const note = s.text(req.body.note, "Review note", 4000);
    await transaction(async (db) => {
      const request = await scopedRecord(
        db,
        "control_requests",
        req.params.id,
        req.user,
        true,
      );
      s.requireValue(
        request.status === "pending",
        "This request has already been reviewed",
        409,
      );
      s.requireValue(
        request.requested_by !== req.user.id,
        "The requester cannot approve or reject their own request",
        403,
      );
      const customer = await scopedRecord(
        db,
        "control_customers",
        request.customer_id,
        req.user,
        true,
      );
      const instance = await scopedRecord(
        db,
        "control_instances",
        request.instance_id,
        req.user,
        true,
      );
      if (req.body.decision === "approved") {
        s.requireValue(
          customer.status !== "suspended" && instance.enabled,
          "Customer or instance is suspended",
        );
        await validateEntitlements(request.plan_snapshot.entitlements, db);
        if (request.kind === "trial") {
          const trial = await db.query(
            "SELECT 1 FROM control_subscriptions WHERE customer_id=$1 AND kind='trial'",
            [request.customer_id],
          );
          s.requireValue(
            !trial.rowCount,
            "This customer already received a trial",
            409,
          );
          const paid = await db.query(
            "SELECT 1 FROM control_subscriptions WHERE instance_id=$1 AND kind='purchase' AND status='active' AND ends_at>now()",
            [instance.id],
          );
          s.requireValue(
            !paid.rowCount,
            "An active purchase cannot be replaced with a trial",
            409,
          );
        }
        if (
          request.kind === "purchase" &&
          Number(request.plan_snapshot.price_minor) > 0
        )
          s.text(req.body.payment_reference, "Manual payment reference", 255);
        const scheduled = request.renewal_mode === "after_current_term";
        s.requireValue(
          !scheduled || request.kind === "purchase",
          "Only paid terms can be scheduled",
        );
        const {
          rows: [current],
        } = await db.query(
          "SELECT ends_at FROM control_subscriptions WHERE instance_id=$1 AND status IN ('active','scheduled') AND starts_at<=now() AND ends_at>now() ORDER BY starts_at DESC LIMIT 1",
          [instance.id],
        );
        const start = scheduled && current ? current.ends_at : new Date();
        if (!scheduled)
          await db.query(
            "UPDATE control_subscriptions SET status='superseded' WHERE instance_id=$1 AND status IN ('active','suspended','scheduled')",
            [instance.id],
          );
        await db.query(
          "INSERT INTO control_subscriptions(id,customer_id,instance_id,request_id,kind,plan_snapshot,starts_at,ends_at,status) VALUES($1,$2,$3,$4,$5,$6,$7::timestamptz,$7::timestamptz+CASE WHEN $5::varchar='trial' THEN ($8::int*interval '1 day') ELSE ($9::int*interval '1 month') END,$10)",
          [
            randomUUID(),
            request.customer_id,
            instance.id,
            request.id,
            request.kind,
            JSON.stringify(request.plan_snapshot),
            start,
            request.plan_snapshot.trial_days,
            request.plan_snapshot.duration_months,
            scheduled && current ? "scheduled" : "active",
          ],
        );
        if (request.kind === "purchase")
          await db.query(
            "INSERT INTO control_invoices(id,invoice_number,customer_id,request_id,currency,amount_minor,payment_reference,customer_snapshot,plan_snapshot) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            [
              randomUUID(),
              "NL-" + request.id.toUpperCase(),
              request.customer_id,
              request.id,
              request.plan_snapshot.currency,
              request.plan_snapshot.price_minor,
              req.body.payment_reference || null,
              JSON.stringify({
                name: customer.name,
                email: customer.contact_email,
              }),
              JSON.stringify(request.plan_snapshot),
            ],
          );
        await db.query(
          "UPDATE control_customers SET status='active' WHERE id=$1",
          [customer.id],
        );
      }
      await db.query(
        "UPDATE control_requests SET status=$2,reviewed_by=$3,review_note=$4,payment_reference=$5,reviewed_at=now() WHERE id=$1",
        [
          request.id,
          req.body.decision,
          req.user.id,
          note,
          req.body.decision === "approved" && request.kind === "purchase"
            ? req.body.payment_reference || null
            : null,
        ],
      );
      await audit(
        db,
        req.user,
        `request.${req.body.decision}`,
        request.id,
        request.customer_id,
        { note },
      );
    });
    res.json({ message: "Review recorded" });
  }),
);
router.get(
  "/subscriptions",
  action(async (req, res) =>
    res.json(
      await list(
        req,
        "control_subscriptions",
        "*,CASE WHEN status IN ('active','scheduled') AND ends_at<=now() THEN 'expired' WHEN status='scheduled' AND starts_at<=now() THEN 'active' ELSE status END AS effective_status",
        { customer: true },
      ),
    ),
  ),
);
router.post(
  "/subscriptions/:id/status",
  review,
  action(async (req, res) => {
    s.requireValue(
      ["active", "suspended", "cancelled"].includes(req.body.status),
      "Choose active, suspended or cancelled",
    );
    const note = s.text(req.body.note, "Status change reason", 4000);
    await transaction(async (db) => {
      const sub = await scopedRecord(
        db,
        "control_subscriptions",
        req.params.id,
        req.user,
        true,
      );
      await scopedRecord(
        db,
        "control_instances",
        sub.instance_id,
        req.user,
        true,
      );
      s.requireValue(
        ["active", "suspended", "scheduled"].includes(sub.status),
        "Cancelled and superseded subscriptions are historical records",
        409,
      );
      s.requireValue(
        req.body.status !== "active" || new Date(sub.ends_at) > new Date(),
        "An expired subscription cannot be resumed",
        409,
      );
      const nextStatus =
        req.body.status === "active" && new Date(sub.starts_at) > new Date()
          ? "scheduled"
          : req.body.status;
      if (nextStatus === "active")
        await db.query(
          "UPDATE control_subscriptions SET status='superseded' WHERE instance_id=$1 AND id<>$2 AND status='active' AND ends_at<=now()",
          [sub.instance_id, sub.id],
        );
      await db.query("UPDATE control_subscriptions SET status=$2 WHERE id=$1", [
        sub.id,
        nextStatus,
      ]);
      await audit(
        db,
        req.user,
        "subscription.status",
        sub.id,
        sub.customer_id,
        { status: req.body.status, note },
      );
    });
    res.json({ message: "Subscription updated" });
  }),
);
async function entitlements(instanceId, db = { query }) {
  const {
    rows: [record],
  } = await db.query(
    `SELECT s.*,i.enabled AS instance_enabled,c.status AS customer_status FROM control_subscriptions s
    JOIN control_instances i ON i.id=s.instance_id JOIN control_customers c ON c.id=i.customer_id
    WHERE s.instance_id=$1 AND s.status IN ('active','scheduled') AND s.starts_at<=now() AND s.ends_at>now() ORDER BY s.starts_at DESC LIMIT 1`,
    [instanceId],
  );
  if (
    !record ||
    !record.instance_enabled ||
    record.customer_status !== "active"
  )
    return { active: false, applications: [], permissions: [], max_users: 0 };
  const apps = (
    await db.query(
      "SELECT * FROM control_applications WHERE code=ANY($1) AND enabled",
      [record.plan_snapshot.entitlements.applications],
    )
  ).rows;
  const permissions = (
    await db.query(
      "SELECT code FROM control_permissions WHERE code=ANY($1) AND application_code=ANY($2) AND enabled",
      [record.plan_snapshot.entitlements.permissions, apps.map((a) => a.code)],
    )
  ).rows.map((p) => p.code);
  const navigationPermissions = require("./master-permissions").hierarchyNavigationPermissions(permissions);
  return {
    active: true,
    instance_id: instanceId,
    customer_id: record.customer_id,
    subscription_id: record.id,
    kind: record.kind,
    expires_at: record.ends_at,
    applications: apps.map((a) => ({
      ...a,
      navigation: a.navigation.filter((n) =>
        navigationPermissions.has(n.permission),
      ),
    })),
    permissions,
    max_users: record.plan_snapshot.max_users,
  };
}
router.get(
  "/customer-roles",
  action(async (req, res) =>
    res.json(
      await list(req, "control_customer_roles", "*", { customer: true }),
    ),
  ),
);
router.post(
  "/customer-roles",
  owners,
  action(async (req, res) => {
    s.requireValue(
      typeof req.body.name === "string" &&
        !["superadmin", "admin", "*"].includes(
          req.body.name.trim().toLowerCase(),
        ),
      "Choose a customer role name, not an installation administrator role",
    );
    const customerId = id(s.customerScope(req.user, req.body.customer_id));
    s.requireValue(
      Array.isArray(req.body.permission_codes) &&
        req.body.permission_codes.every((p) => typeof p === "string"),
      "Select permission codes",
    );
    const roleId = randomUUID();
    await transaction(async (db) => {
      await scopedRecord(db, "control_customers", customerId, req.user, true);
      const instances = (
        await db.query(
          "SELECT id FROM control_instances WHERE customer_id=$1 AND enabled",
          [customerId],
        )
      ).rows;
      const allowed = new Set();
      for (const instance of instances)
        for (const p of (await entitlements(instance.id, db)).permissions)
          allowed.add(p);
      s.requireValue(
        req.body.permission_codes.every((p) => allowed.has(p)),
        "Role exceeds the active subscription permission ceiling",
        403,
      );
      await db.query(
        "INSERT INTO control_customer_roles(id,customer_id,name,permission_codes) VALUES($1,$2,$3,$4)",
        [
          roleId,
          customerId,
          s.text(req.body.name, "Role name", 100),
          JSON.stringify([...new Set(req.body.permission_codes)]),
        ],
      );
      await audit(db, req.user, "customer-role.created", roleId, customerId);
    });
    res.status(201).json({ id: roleId });
  }),
);
router.get(
  "/audit",
  action(async (req, res) =>
    res.json(await list(req, "control_audit", "*", { customer: true })),
  ),
);
module.exports = { router, entitlements, allowedOrigin };
