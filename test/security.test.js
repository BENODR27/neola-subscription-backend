const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
  customerScope,
  safeEqual,
  password,
  encrypt,
  decrypt,
} = require("../src/security");
const { allowedOrigin } = require("../src/subscriptions");
test("authenticator output matches RFC 6238 SHA-1 test vector", () => {
  const { base32, totp } = require("../src/account-security");
  const secret = base32(Buffer.from("12345678901234567890"));
  assert.equal(secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
  assert.equal(totp(secret, 1), "287082");
});
test("customer accounts cannot select another customer scope", () => {
  const user = { role: "customer_owner", customer_id: "own" };
  assert.equal(customerScope(user), "own");
  assert.throws(() => customerScope(user, "other"), /denied/);
});
test("activation keys are encrypted, authenticated and never plaintext", () => {
  const old = process.env.CONTROL_ENCRYPTION_KEY;
  process.env.CONTROL_ENCRYPTION_KEY = "b".repeat(64);
  try {
    const encrypted = encrypt("one-time-secret");
    assert.ok(!encrypted.includes("one-time-secret"));
    assert.equal(decrypt(encrypted), "one-time-secret");
    assert.throws(() =>
      decrypt(encrypted.slice(0, -1) + (encrypted.endsWith("0") ? "1" : "0")),
    );
  } finally {
    if (old === undefined) delete process.env.CONTROL_ENCRYPTION_KEY;
    else process.env.CONTROL_ENCRYPTION_KEY = old;
  }
});
test("password length cannot bypass bcrypt byte limits", async () => {
  assert.throws(() => password("short"), /12/);
  assert.throws(() => password("🙂".repeat(30)), /72/);
  assert.equal(safeEqual("abc", "abc"), true);
  assert.equal(safeEqual("abc", "abcd"), false);
});
test("ERP destinations require an exact operator allowlist", () => {
  const old = process.env.CONTROL_ERP_ALLOWED_ORIGINS;
  process.env.CONTROL_ERP_ALLOWED_ORIGINS = "https://erp.example.com";
  try {
    assert.equal(
      allowedOrigin("https://erp.example.com"),
      "https://erp.example.com",
    );
    for (const url of [
      "https://erp.example.com.evil.test",
      "https://erp.example.com/path",
      "http://169.254.169.254",
      "https://user:pass@erp.example.com",
    ])
      assert.throws(() => allowedOrigin(url));
  } finally {
    if (old === undefined) delete process.env.CONTROL_ERP_ALLOWED_ORIGINS;
    else process.env.CONTROL_ERP_ALLOWED_ORIGINS = old;
  }
});
