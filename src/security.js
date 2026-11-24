const crypto = require("node:crypto");
const bcrypt = require("bcryptjs");
const { query } = require("./database");
const cookie = "neola_control_session";
const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
const csrf = (token) => hash(`csrf:${token}`);
const safeEqual = (a, b) =>
  typeof a === "string" &&
  typeof b === "string" &&
  Buffer.byteLength(a) === Buffer.byteLength(b) &&
  crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
class Problem extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}
const requireValue = (condition, message, status = 400) => {
  if (!condition) throw new Problem(status, message);
};
function text(value, label, max = 180) {
  requireValue(
    typeof value === "string" &&
      value.trim().length > 0 &&
      value.trim().length <= max,
    `${label} is required (maximum ${max} characters)`,
  );
  return value.trim();
}
function password(value) {
  requireValue(
    typeof value === "string" &&
      value.length >= 12 &&
      Buffer.byteLength(value) <= 72,
    "Password must contain 12–72 bytes",
  );
  return bcrypt.hash(value, 12);
}
const publicUser = (u) => ({
  id: u.id,
  username: u.username,
  display_name: u.display_name,
  role: u.role,
  customer_id: u.customer_id,
  email_verified: !!u.email_verified,
  mfa_enabled: !!u.mfa_secret,
});
const cookieOptions = () => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
  path: "/api/control",
  maxAge: 8 * 60 * 60 * 1000,
});
async function session(req, res, next) {
  try {
    const token = req.cookies[cookie];
    requireValue(token && token.length === 64, "Please log in", 401);
    const {
      rows: [user],
    } = await query(
      `SELECT u.* FROM control_sessions s JOIN control_users u ON u.id=s.user_id
      WHERE s.token_hash=$1 AND s.expires_at>now() AND u.enabled`,
      [hash(token)],
    );
    requireValue(user, "Session expired. Please log in again", 401);
    if (!["GET", "HEAD", "OPTIONS"].includes(req.method))
      requireValue(
        safeEqual(req.get("X-CSRF-Token"), csrf(token)),
        "Invalid request token",
        403,
      );
    req.user = publicUser(user);
    next();
  } catch (error) {
    next(error);
  }
}
function allow(...roles) {
  return (req, res, next) =>
    roles.includes(req.user.role)
      ? next()
      : next(new Problem(403, "This action requires a different account role"));
}
function customerScope(user, requested) {
  if (user.role === "customer_owner") {
    requireValue(
      !requested || requested === user.customer_id,
      "Customer access denied",
      403,
    );
    return user.customer_id;
  }
  return requested || null;
}
function encrypt(value) {
  const key = Buffer.from(process.env.CONTROL_ENCRYPTION_KEY || "", "hex");
  requireValue(
    key.length === 32,
    "Configure CONTROL_ENCRYPTION_KEY with 64 hexadecimal characters",
    503,
  );
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  return [
    iv.toString("hex"),
    cipher.update(value, "utf8", "hex") + cipher.final("hex"),
    cipher.getAuthTag().toString("hex"),
  ].join(":");
}
function decrypt(value) {
  const [iv, encrypted, tag] = value.split(":");
  const cipher = crypto.createDecipheriv(
    "aes-256-gcm",
    Buffer.from(process.env.CONTROL_ENCRYPTION_KEY || "", "hex"),
    Buffer.from(iv, "hex"),
  );
  cipher.setAuthTag(Buffer.from(tag, "hex"));
  return cipher.update(encrypted, "hex", "utf8") + cipher.final("utf8");
}
module.exports = {
  Problem,
  requireValue,
  text,
  password,
  publicUser,
  session,
  allow,
  customerScope,
  hash,
  csrf,
  safeEqual,
  cookie,
  cookieOptions,
  encrypt,
  decrypt,
};
