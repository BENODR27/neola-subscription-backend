const { Router } = require("express");
const { randomBytes, randomUUID } = require("node:crypto");
const bcrypt = require("bcryptjs");
const { rateLimit } = require("express-rate-limit");
const { query, transaction } = require("./database");
const s = require("./security");
const router = Router();
const action = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res)).catch(next);
const limit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false,
});
router.post(
  "/login",
  limit,
  action(async (req, res) => {
    const username = s.text(req.body.username, "Username").toLowerCase();
    const {
      rows: [user],
    } = await query(
      "SELECT * FROM control_users WHERE username=$1 AND enabled",
      [username],
    );
    // Equal-cost comparison even when the username does not exist.
    const valid = await bcrypt.compare(
      typeof req.body.password === "string" ? req.body.password : "",
      user?.password_hash ||
        "$2a$12$kE5FU4vYx3IJVdvRUONxOu7xfu4JndVftMDT3GvXTSgBtmLEh5bH.",
    );
    s.requireValue(user && valid, "Incorrect username or password", 401);
    if (user.mfa_secret)
      await transaction(async (db) => {
        const {
          rows: [locked],
        } = await db.query(
          "SELECT * FROM control_users WHERE id=$1 FOR UPDATE",
          [user.id],
        );
        s.requireValue(
          await require("./account-security").verifyMfa(
            db,
            locked,
            req.body.mfa_code,
          ),
          "Authenticator or recovery code required",
          401,
        );
      });
    const token = randomBytes(32).toString("hex");
    await query("DELETE FROM control_sessions WHERE expires_at<=now()");
    await query(
      "INSERT INTO control_sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '8 hours')",
      [s.hash(token), user.id],
    );
    res
      .cookie(s.cookie, token, s.cookieOptions())
      .json({ user: s.publicUser(user), csrfToken: s.csrf(token) });
  }),
);
router.post(
  "/register",
  limit,
  action(async (req, res) => {
    const username = s.text(req.body.username, "Username").toLowerCase();
    const name = s.text(req.body.name, "Customer name");
    const displayName = s.text(req.body.display_name, "Your name");
    const email = s.text(req.body.email, "Email", 255);
    s.requireValue(
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email),
      "Enter a valid contact email",
    );
    const passwordHash = await s.password(req.body.password);
    await transaction(async (db) => {
      const customerId = randomUUID();
      await db.query(
        "INSERT INTO control_customers(id,name,contact_email) VALUES($1,$2,$3)",
        [customerId, name, email],
      );
      await db.query(
        "INSERT INTO control_users(id,username,display_name,password_hash,role,customer_id) VALUES($1,$2,$3,$4,'customer_owner',$5)",
        [randomUUID(), username, displayName, passwordHash, customerId],
      );
      await db.query("UPDATE control_users SET email=$2 WHERE username=$1", [
        username,
        email,
      ]);
    });
    res.status(201).json({
      message:
        "Account created. Log in to request a plan. A platform operator will provision your dedicated ERP instance.",
    });
  }),
);
router.get(
  "/session",
  s.session,
  action(async (req, res) =>
    res.json({ user: req.user, csrfToken: s.csrf(req.cookies[s.cookie]) }),
  ),
);
router.post(
  "/logout",
  s.session,
  action(async (req, res) => {
    await query("DELETE FROM control_sessions WHERE token_hash=$1", [
      s.hash(req.cookies[s.cookie]),
    ]);
    res
      .clearCookie(s.cookie, { ...s.cookieOptions(), maxAge: undefined })
      .sendStatus(204);
  }),
);
module.exports = { router, action };
