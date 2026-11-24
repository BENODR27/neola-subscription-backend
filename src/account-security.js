const crypto = require("node:crypto");
const { Router } = require("express");
const { rateLimit } = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const { query, transaction } = require("./database");
const s = require("./security");
const router = Router(),
  action = (fn) => (req, res, next) =>
    Promise.resolve(fn(req, res)).catch(next);
const limit = rateLimit({
  windowMs: 15 * 60000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
});
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32(bytes) {
  let out = "",
    buffer = 0,
    bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits) out += alphabet[(buffer << (5 - bits)) & 31];
  return out;
}
function decode(value) {
  let buffer = 0,
    bits = 0,
    bytes = [];
  for (const c of value) {
    const n = alphabet.indexOf(c);
    s.requireValue(n >= 0, "Invalid authenticator secret");
    buffer = (buffer << 5) | n;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}
function totp(secret, counter = Math.floor(Date.now() / 30000)) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(counter));
  const hash = crypto.createHmac("sha1", decode(secret)).update(bytes).digest(),
    offset = hash[19] & 15;
  return String((hash.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(
    6,
    "0",
  );
}
function counterFor(secret, code, last = -1) {
  const now = Math.floor(Date.now() / 30000);
  for (const delta of [-1, 0, 1])
    if (
      now + delta > Number(last ?? -1) &&
      s.safeEqual(totp(secret, now + delta), String(code || ""))
    )
      return now + delta;
  return null;
}
async function verifyMfa(db, user, code) {
  if (!user.mfa_secret) return true;
  const counter = counterFor(
    s.decrypt(user.mfa_secret),
    code,
    user.mfa_last_counter,
  );
  if (counter !== null) {
    await db.query("UPDATE control_users SET mfa_last_counter=$2 WHERE id=$1", [
      user.id,
      counter,
    ]);
    return true;
  }
  const index = user.recovery_hashes.indexOf(s.hash(String(code || "")));
  if (index >= 0) {
    const hashes = user.recovery_hashes.filter((_, i) => i !== index);
    await db.query("UPDATE control_users SET recovery_hashes=$2 WHERE id=$1", [
      user.id,
      JSON.stringify(hashes),
    ]);
    return true;
  }
  return false;
}
async function sendToken(user, kind, db = { query }) {
  s.requireValue(user.email, "Set your email address first");
  const raw = crypto.randomBytes(32).toString("hex"),
    expires = kind === "reset_password" ? "30 minutes" : "24 hours";
  await db.query(
    "DELETE FROM control_action_tokens WHERE user_id=$1 AND kind=$2",
    [user.id, kind],
  );
  await db.query(
    `INSERT INTO control_action_tokens(token_hash,user_id,kind,expires_at) VALUES($1,$2,$3,now()+$4::interval)`,
    [s.hash(raw), user.id, kind, expires],
  );
  const path = kind === "reset_password" ? "reset" : "verify",
    url = new URL(process.env.CONTROL_PORTAL_URL || "http://127.0.0.1:4300");
  url.searchParams.set("action", path);
  url.searchParams.set("token", raw);
  await db.query(
    "INSERT INTO control_mail_outbox(id,user_id,recipient,kind,encrypted_payload) VALUES($1,$2,$3,$4,$5)",
    [
      crypto.randomUUID(),
      user.id,
      user.email,
      kind,
      s.encrypt(JSON.stringify({ url: url.href, kind })),
    ],
  );
}
router.post(
  "/forgot-password",
  limit,
  action(async (req, res) => {
    const username = String(req.body.username || "")
      .trim()
      .toLowerCase();
    const {
      rows: [user],
    } = await query(
      "SELECT * FROM control_users WHERE username=$1 AND enabled",
      [username],
    );
    if (user?.email)
      await transaction((db) => sendToken(user, "reset_password", db));
    res.json({
      message:
        "If the account has an email address, recovery instructions have been queued for delivery.",
    });
  }),
);
router.post(
  "/reset-password",
  limit,
  action(async (req, res) => {
    const hash = await s.password(req.body.password);
    await transaction(async (db) => {
      const {
        rows: [token],
      } = await db.query(
        "SELECT t.*,u.mfa_secret,u.mfa_last_counter,u.recovery_hashes FROM control_action_tokens t JOIN control_users u ON u.id=t.user_id WHERE token_hash=$1 AND kind='reset_password' AND expires_at>now() FOR UPDATE",
        [s.hash(String(req.body.token || ""))],
      );
      s.requireValue(token, "Recovery link is invalid or expired", 400);
      s.requireValue(
        await verifyMfa(db, { ...token, id: token.user_id }, req.body.mfa_code),
        "Authenticator or recovery code required",
        401,
      );
      await db.query("UPDATE control_users SET password_hash=$2 WHERE id=$1", [
        token.user_id,
        hash,
      ]);
      await db.query("DELETE FROM control_sessions WHERE user_id=$1", [
        token.user_id,
      ]);
      await db.query(
        "DELETE FROM control_action_tokens WHERE user_id=$1 AND kind='reset_password'",
        [token.user_id],
      );
    });
    res.json({ message: "Password changed. Sign in again." });
  }),
);
router.post(
  "/verify-email",
  limit,
  action(async (req, res) => {
    await transaction(async (db) => {
      const {
        rows: [token],
      } = await db.query(
        "SELECT * FROM control_action_tokens WHERE token_hash=$1 AND kind='verify_email' AND expires_at>now() FOR UPDATE",
        [s.hash(String(req.body.token || ""))],
      );
      s.requireValue(token, "Verification link is invalid or expired");
      await db.query(
        "UPDATE control_users SET email_verified=true WHERE id=$1",
        [token.user_id],
      );
      await db.query("DELETE FROM control_action_tokens WHERE token_hash=$1", [
        token.token_hash,
      ]);
    });
    res.json({ message: "Email verified" });
  }),
);
router.use(s.session);
router.get(
  "/security",
  action(async (req, res) => {
    const {
      rows: [u],
    } = await query(
      "SELECT email,email_verified,mfa_secret FROM control_users WHERE id=$1",
      [req.user.id],
    );
    res.json({
      email: u.email,
      email_verified: u.email_verified,
      mfa_enabled: !!u.mfa_secret,
      development_outbox: process.env.NODE_ENV !== "production",
    });
  }),
);
router.put(
  "/email",
  action(async (req, res) => {
    const email = s.text(req.body.email, "Email", 255).toLowerCase();
    s.requireValue(
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email),
      "Valid email required",
    );
    await transaction(async (db) => {
      const {
        rows: [u],
      } = await db.query("SELECT * FROM control_users WHERE id=$1 FOR UPDATE", [
        req.user.id,
      ]);
      s.requireValue(
        await bcrypt.compare(String(req.body.password || ""), u.password_hash),
        "Current password required",
        401,
      );
      s.requireValue(
        await verifyMfa(db, u, req.body.mfa_code),
        "Authenticator code required",
        401,
      );
      await db.query(
        "UPDATE control_users SET email=$2,email_verified=false WHERE id=$1",
        [u.id, email],
      );
      await sendToken({ ...u, email }, "verify_email", db);
    });
    res.json({
      message: "Verification queued. Open the link delivered to your email.",
    });
  }),
);
router.post(
  "/resend-verification",
  limit,
  action(async (req, res) => {
    await transaction(async (db) => {
      const {
        rows: [u],
      } = await db.query("SELECT * FROM control_users WHERE id=$1", [
        req.user.id,
      ]);
      await sendToken(u, "verify_email", db);
    });
    res.json({ message: "Verification queued" });
  }),
);
router.get(
  "/development-inbox",
  action(async (req, res) => {
    s.requireValue(
      process.env.NODE_ENV !== "production",
      "Local delivery inbox is unavailable",
      404,
    );
    await db.query("DELETE FROM control_action_tokens WHERE user_id=$1", [
      u.id,
    ]);
    await db.query(
      "UPDATE control_mail_outbox SET status='cancelled' WHERE user_id=$1 AND status='queued'",
      [u.id],
    );
    const { rows } = await query(
      "SELECT * FROM control_mail_outbox WHERE user_id=$1 ORDER BY created_at DESC LIMIT 10",
      [req.user.id],
    );
    res.json({
      items: rows.map((r) => ({
        id: r.id,
        kind: r.kind,
        created_at: r.created_at,
        ...JSON.parse(s.decrypt(r.encrypted_payload)),
      })),
    });
  }),
);
router.post(
  "/mfa/setup",
  action(async (req, res) => {
    const {
      rows: [u],
    } = await query("SELECT * FROM control_users WHERE id=$1", [req.user.id]);
    s.requireValue(!u.mfa_secret, "MFA is already enabled", 409);
    s.requireValue(
      await bcrypt.compare(String(req.body.password || ""), u.password_hash),
      "Current password required",
      401,
    );
    const secret = base32(crypto.randomBytes(20));
    await query("UPDATE control_users SET mfa_pending=$2 WHERE id=$1", [
      u.id,
      s.encrypt(secret),
    ]);
    res.json({
      secret,
      uri: `otpauth://totp/NeoLA:${encodeURIComponent(u.username)}?secret=${secret}&issuer=NeoLA&digits=6&period=30`,
    });
  }),
);
router.post(
  "/mfa/confirm",
  action(async (req, res) => {
    let recovery;
    await transaction(async (db) => {
      const {
        rows: [u],
      } = await db.query("SELECT * FROM control_users WHERE id=$1 FOR UPDATE", [
        req.user.id,
      ]);
      s.requireValue(
        u.mfa_pending && !u.mfa_secret,
        "Start authenticator setup first",
        409,
      );
      const counter = counterFor(s.decrypt(u.mfa_pending), req.body.code);
      s.requireValue(counter !== null, "Invalid authenticator code");
      recovery = Array.from({ length: 8 }, () =>
        crypto.randomBytes(8).toString("hex"),
      );
      await db.query(
        "UPDATE control_users SET mfa_secret=mfa_pending,mfa_pending=null,mfa_last_counter=$2,recovery_hashes=$3 WHERE id=$1",
        [u.id, counter, JSON.stringify(recovery.map(s.hash))],
      );
      await db.query(
        "DELETE FROM control_sessions WHERE user_id=$1 AND token_hash<>$2",
        [u.id, s.hash(req.cookies[s.cookie])],
      );
    });
    res.json({
      recovery_codes: recovery,
      message: "Save these recovery codes securely. They are displayed once.",
    });
  }),
);
router.post(
  "/mfa/disable",
  action(async (req, res) => {
    await transaction(async (db) => {
      const {
        rows: [u],
      } = await db.query("SELECT * FROM control_users WHERE id=$1 FOR UPDATE", [
        req.user.id,
      ]);
      s.requireValue(
        await bcrypt.compare(String(req.body.password || ""), u.password_hash),
        "Current password required",
        401,
      );
      s.requireValue(
        await verifyMfa(db, u, req.body.code),
        "Authenticator or recovery code required",
        401,
      );
      await db.query(
        "UPDATE control_users SET mfa_secret=null,mfa_pending=null,mfa_last_counter=null,recovery_hashes='[]' WHERE id=$1",
        [u.id],
      );
      await db.query(
        "DELETE FROM control_sessions WHERE user_id=$1 AND token_hash<>$2",
        [u.id, s.hash(req.cookies[s.cookie])],
      );
    });
    res.json({ message: "Authenticator disabled" });
  }),
);
module.exports = { router, verifyMfa, sendToken, totp, base32 };
