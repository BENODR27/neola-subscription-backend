const { Router } = require("express");
const { randomUUID, randomBytes } = require("node:crypto");
const { query, transaction } = require("./database");
const { action } = require("./auth");
const s = require("./security");
const { list, scopedRecord, audit } = require("./common");
const router = Router();
router.get(
  "/invoices",
  action(async (req, res) =>
    res.json(
      await list(req, "control_invoices", "*", {
        customer: true,
        order: "issued_at DESC,id DESC",
      }),
    ),
  ),
);
router.post(
  "/instances/:id/key-rotation",
  s.allow("platform_owner"),
  action(async (req, res) => {
    const key = randomBytes(32).toString("hex");
    await transaction(async (db) => {
      const instance = await scopedRecord(
        db,
        "control_instances",
        req.params.id,
        req.user,
        true,
      );
      s.requireValue(
        !instance.pending_key_hash,
        "A rotation is already pending. Commit or cancel it first.",
        409,
      );
      await db.query(
        "UPDATE control_instances SET pending_key_hash=$2,encrypted_pending_key=$3 WHERE id=$1",
        [instance.id, s.hash(key), s.encrypt(key)],
      );
      await db.query(
        "INSERT INTO control_key_rotations(id,instance_id,previous_hash,new_hash) VALUES($1,$2,$3,$4)",
        [randomUUID(), instance.id, instance.key_hash, s.hash(key)],
      );
      await audit(
        db,
        req.user,
        "instance.key-rotation-staged",
        instance.id,
        instance.customer_id,
      );
    });
    res.json({
      activation_key: key,
      message:
        "Update this instance’s IAM key, then commit the rotation. Both keys verify licensing until commit.",
    });
  }),
);
router.post(
  "/instances/:id/key-rotation/commit",
  s.allow("platform_owner"),
  action(async (req, res) => {
    const instance = await scopedRecord(
      { query },
      "control_instances",
      req.params.id,
      req.user,
    );
    s.requireValue(instance.encrypted_pending_key, "No pending rotation", 409);
    const { allowedOrigin } = require("./subscriptions");
    const origin = allowedOrigin(instance.api_origin);
    s.requireValue(origin, "Configure the IAM origin first");
    let response;
    try {
      response = await fetch(`${origin}/v3/api/auth/internal/control/catalog`, {
        headers: {
          Authorization: `Bearer ${s.decrypt(instance.encrypted_pending_key)}`,
        },
        signal: AbortSignal.timeout(5000),
        redirect: "error",
      });
    } catch {
      throw new s.Problem(502, "IAM has not confirmed the pending key");
    }
    s.requireValue(
      response.ok,
      "Update IAM to the pending key before committing",
      409,
    );
    await transaction(async (db) => {
      const locked = await scopedRecord(
        db,
        "control_instances",
        instance.id,
        req.user,
        true,
      );
      s.requireValue(
        locked.pending_key_hash === instance.pending_key_hash,
        "Rotation changed. Reload.",
        409,
      );
      await db.query(
        "UPDATE control_instances SET key_hash=pending_key_hash,encrypted_key=encrypted_pending_key,pending_key_hash=null,encrypted_pending_key=null WHERE id=$1",
        [instance.id],
      );
      await audit(
        db,
        req.user,
        "instance.key-rotation-committed",
        instance.id,
        instance.customer_id,
      );
    });
    res.json({ message: "Rotation committed. The previous key is revoked." });
  }),
);
router.post(
  "/instances/:id/key-rotation/cancel",
  s.allow("platform_owner"),
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
        "UPDATE control_instances SET pending_key_hash=null,encrypted_pending_key=null WHERE id=$1",
        [instance.id],
      );
      await audit(
        db,
        req.user,
        "instance.key-rotation-cancelled",
        instance.id,
        instance.customer_id,
      );
    });
    res.json({
      message: "Pending key revoked. Keep IAM configured with the current key.",
    });
  }),
);
module.exports = router;
