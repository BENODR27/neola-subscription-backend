const { Router } = require("express");
const { transaction } = require("./database");
const s = require("./security");
const { action } = require("./auth");
const { id, audit } = require("./common");
const router = Router();
router.put(
  "/operators/:id",
  s.allow("platform_owner"),
  action(async (req, res) => {
    const userId = id(req.params.id);
    s.requireValue(
      ["platform_owner", "platform_staff", "approver"].includes(req.body.role),
      "Choose a console operator role",
    );
    const password = req.body.password
      ? await s.password(req.body.password)
      : null;
    await transaction(async (db) => {
      await db.query("SELECT pg_advisory_xact_lock(70202027)");
      const {
        rows: [u],
      } = await db.query(
        "SELECT * FROM control_users WHERE id=$1 AND role<>'customer_owner' FOR UPDATE",
        [userId],
      );
      s.requireValue(u, "Operator not found", 404);
      if (u.role === "platform_owner" && req.body.role !== "platform_owner") {
        const count = await db.query(
          "SELECT 1 FROM control_users WHERE role='platform_owner' AND enabled AND id<>$1",
          [userId],
        );
        s.requireValue(
          count.rowCount,
          "Keep at least one active platform owner",
          409,
        );
      }
      await db.query(
        "UPDATE control_users SET display_name=$2,role=$3,password_hash=COALESCE($4,password_hash) WHERE id=$1",
        [
          userId,
          s.text(req.body.display_name, "Display name"),
          req.body.role,
          password,
        ],
      );
      await db.query("DELETE FROM control_sessions WHERE user_id=$1", [userId]);
      await audit(db, req.user, "operator.updated", userId, null, {
        role: req.body.role,
      });
    });
    res.json({
      message: "Operator updated. Their existing sessions have ended.",
    });
  }),
);
router.post(
  "/operators/:id/enable",
  s.allow("platform_owner"),
  action(async (req, res) => {
    await transaction(async (db) => {
      const r = await db.query(
        "UPDATE control_users SET enabled=true WHERE id=$1 AND role<>'customer_owner' RETURNING id",
        [id(req.params.id)],
      );
      s.requireValue(r.rowCount, "Operator not found", 404);
      await audit(db, req.user, "operator.enabled", req.params.id, null);
    });
    res.json({ message: "Operator enabled" });
  }),
);
module.exports = router;
