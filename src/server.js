const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const { rateLimit } = require("express-rate-limit");
const { randomUUID } = require("node:crypto");
const { query, transaction, pool } = require("./database");
const { router: auth, action } = require("./auth");
const { router: catalog } = require("./catalog");
const { router: subscriptions, entitlements } = require("./subscriptions");
const s = require("./security");
const { id, list, audit } = require("./common");
function createApp() {
  require("./license-signing").privateKey();
  const app = express();
  const hops = Number(process.env.CONTROL_TRUST_PROXY_HOPS || 0);
  if (Number.isInteger(hops) && hops > 0 && hops <= 3)
    app.set("trust proxy", hops);
  app.disable("x-powered-by");
  app.use(helmet());
  const origins = (process.env.CONTROL_ALLOWED_ORIGINS || "")
    .split(",")
    .map((v) => v.trim());
  app.use(
    cors({
      credentials: true,
      origin(origin, cb) {
        cb(null, !origin || origins.includes(origin));
      },
    }),
  );
  app.use(express.json({ limit: "128kb" }), cookieParser());
  app.use("/api/control", (req, res, next) => {
    const origin = req.get("Origin");
    if (
      !["GET", "HEAD", "OPTIONS"].includes(req.method) &&
      origin &&
      !origins.includes(origin) &&
      origin !== `${req.protocol}://${req.get("host")}`
    )
      return next(new s.Problem(403, "Request origin is not allowed"));
    next();
  });
  app.get(
    "/health",
    action(async (req, res) => {
      await query("SELECT 1");
      res.json({ status: "ok", service: "neola-subscriptions" });
    }),
  );
  app.use("/api/control", (req, res, next) => {
    res.set("Cache-Control", "no-store");
    next();
  });
  app.get(
    "/api/control/internal/instances/:id/entitlements",
    rateLimit({
      windowMs: 60000,
      limit: 600,
      standardHeaders: "draft-7",
      legacyHeaders: false,
    }),
    action(async (req, res) => {
      const {
        rows: [instance],
      } = await query(
        "SELECT key_hash,pending_key_hash FROM control_instances WHERE id=$1",
        [id(req.params.id)],
      );
      const key = req.get("Authorization")?.replace(/^Bearer /, "") || "";
      s.requireValue(
        instance &&
          (s.safeEqual(instance.key_hash, s.hash(key)) ||
            s.safeEqual(instance.pending_key_hash, s.hash(key))),
        "Invalid activation key",
        401,
      );
      res.json(
        require("./license-signing").signLicense(
          await entitlements(req.params.id),
          req.params.id,
        ),
      );
    }),
  );
  app.use("/api/control/auth", auth);
  app.use("/api/control/account", require("./account-security").router);
  app.use("/api/control", s.session);
  app.use("/api/control", (req, res, next) => {
    const required =
      process.env.CONTROL_REQUIRE_OPERATOR_MFA === "true" ||
      (process.env.NODE_ENV === "production" &&
        process.env.CONTROL_REQUIRE_OPERATOR_MFA !== "false");
    if (
      required &&
      req.user.role !== "customer_owner" &&
      !req.user.mfa_enabled &&
      !["GET", "HEAD", "OPTIONS"].includes(req.method)
    )
      return next(
        new s.Problem(
          403,
          "Enable an authenticator in Account & security before managing subscriptions",
        ),
      );
    next();
  });
  app.get(
    "/api/control/operators",
    s.allow("platform_owner"),
    action(async (req, res) =>
      res.json(
        await list(
          req,
          "control_users",
          "id,username,display_name,role,enabled,created_at",
          { where: ["role<>'customer_owner'"] },
        ),
      ),
    ),
  );
  app.post(
    "/api/control/operators",
    s.allow("platform_owner"),
    action(async (req, res) => {
      s.requireValue(
        ["platform_owner", "platform_staff", "approver"].includes(
          req.body.role,
        ),
        "Choose a platform operator role",
      );
      const userId = randomUUID(),
        passwordHash = await s.password(req.body.password);
      await transaction(async (db) => {
        await db.query(
          "INSERT INTO control_users(id,username,display_name,password_hash,role) VALUES($1,$2,$3,$4,$5)",
          [
            userId,
            s.text(req.body.username, "Username").toLowerCase(),
            s.text(req.body.display_name, "Name"),
            passwordHash,
            req.body.role,
          ],
        );
        await audit(db, req.user, "operator.created", userId, null, {
          role: req.body.role,
        });
      });
      res.status(201).json({ id: userId });
    }),
  );
  app.post(
    "/api/control/operators/:id/disable",
    s.allow("platform_owner"),
    action(async (req, res) => {
      s.requireValue(
        req.user.id !== req.params.id,
        "You cannot disable your own account",
      );
      await transaction(async (db) => {
        // Serialize owner-account changes so two operators cannot remove every owner.
        await db.query("SELECT pg_advisory_xact_lock(70202027)");
        const {
          rows: [operator],
        } = await db.query(
          "SELECT * FROM control_users WHERE id=$1 FOR UPDATE",
          [id(req.params.id)],
        );
        s.requireValue(
          operator && operator.role !== "customer_owner",
          "Operator not found",
          404,
        );
        const owners = await db.query(
          "SELECT 1 FROM control_users WHERE role='platform_owner' AND enabled AND id<>$1",
          [operator.id],
        );
        s.requireValue(
          operator.role !== "platform_owner" || owners.rowCount,
          "At least one active platform owner is required",
          409,
        );
        await db.query("UPDATE control_users SET enabled=false WHERE id=$1", [
          operator.id,
        ]);
        await db.query("DELETE FROM control_sessions WHERE user_id=$1", [
          operator.id,
        ]);
        await audit(db, req.user, "operator.disabled", operator.id, null);
      });
      res.json({ message: "Operator disabled" });
    }),
  );
  app.use(
    "/api/control",
    catalog,
    subscriptions,
    require("./erp"),
    require("./billing"),
    require("./operators"),
  );
  app.use((req, res) =>
    res.status(404).json({ message: "Endpoint not found" }),
  );
  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    const status =
      error.status ||
      (error.code === "23505"
        ? 409
        : ["23503", "23514", "22P02"].includes(error.code)
          ? 400
          : 500);
    if (status >= 500)
      console.error("Subscription request failed:", error.message);
    res.status(status).json({
      message:
        status === 409 && !error.status
          ? "A record already exists or a request is already pending"
          : status === 500
            ? "The request could not be completed"
            : error.status
              ? error.message
              : "Invalid record or relationship",
    });
  });
  return app;
}
if (require.main === module) {
  const port = Number(process.env.PORT || 7020);
  const server = createApp().listen(port, process.env.HOST || "127.0.0.1", () =>
    console.log(`NeoLA subscription API listening on ${port}`),
  );
  for (const signal of ["SIGINT", "SIGTERM"])
    process.on(signal, () =>
      server.close(() => pool.end().then(() => process.exit(0))),
    );
}
module.exports = { createApp };
