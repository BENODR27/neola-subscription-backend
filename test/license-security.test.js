const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs"),
  path = require("node:path"),
  os = require("node:os"),
  crypto = require("node:crypto");
const { signLicense } = require("../src/license-signing");
const {
  verifyLicense,
  assertCustomerConfiguration,
} = require("../../authguardv2-node/src/services/license-verification");
test("customer licenses reject forgery, substitution, expiry and unsafe deployment configuration", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "neola-license-unit-")),
    priv = path.join(dir, "private.pem"),
    pub = path.join(dir, "public.pem");
  t.after(() => {
    fs.unlinkSync(priv);
    fs.unlinkSync(pub);
    fs.rmdirSync(dir);
  });
  const keys = crypto.generateKeyPairSync("ed25519");
  fs.writeFileSync(
    priv,
    keys.privateKey.export({ type: "pkcs8", format: "pem" }),
    { mode: 0o600 },
  );
  fs.writeFileSync(pub, keys.publicKey.export({ type: "spki", format: "pem" }));
  const id = crypto.randomUUID(),
    now = Date.now(),
    env = {
      CONTROL_LICENSE_PRIVATE_KEY_FILE: priv,
      CONTROL_LICENSE_PUBLIC_KEY_FILE: pub,
      NEOLA_CUSTOMER_DEPLOYMENT: "true",
      CONTROL_PLANE_MODE: "subscription",
      CONTROL_API_URL: "https://licenses.example.com",
      CONTROL_INSTANCE_ID: id,
      CONTROL_INSTANCE_KEY: "a".repeat(64),
    };
  const value = {
    active: true,
    instance_id: id,
    permissions: ["MMMS-APP"],
    applications: [],
    max_users: 2,
  };
  const signed = signLicense(value, id, env, now);
  assert.equal(
    verifyLicense({ ...signed, max_users: 999 }, id, env, now).value.max_users,
    2,
  );
  assert.throws(
    () =>
      verifyLicense(
        {
          ...signed,
          lease: {
            ...signed.lease,
            payload: Buffer.from(JSON.stringify({ max_users: 999 })).toString(
              "base64url",
            ),
          },
        },
        id,
        env,
        now,
      ),
    /signature/,
  );
  assert.throws(
    () => verifyLicense(signed, crypto.randomUUID(), env, now),
    /bound/,
  );
  assert.throws(() => verifyLicense(signed, id, env, now + 15001), /Expired/);
  assert.throws(() => verifyLicense(value, id, env, now), /Signed/);
  assert.doesNotThrow(() => assertCustomerConfiguration(env));
  assert.throws(
    () => assertCustomerConfiguration({ ...env, CONTROL_PLANE_MODE: "legacy" }),
    /enforcement/,
  );
  assert.throws(
    () =>
      assertCustomerConfiguration({
        ...env,
        CONTROL_API_URL: "http://licenses.example.com",
      }),
    /HTTPS/,
  );
  assert.throws(
    () =>
      assertCustomerConfiguration({
        ...env,
        CONTROL_LICENSE_PUBLIC_KEY_FILE: "",
      }),
    /public key/,
  );
  const long = JSON.parse(Buffer.from(signed.lease.payload, "base64url"));
  long.exp = now + 3600000;
  const bytes = Buffer.from(JSON.stringify(long));
  assert.throws(
    () =>
      verifyLicense(
        {
          lease: {
            payload: bytes.toString("base64url"),
            signature: crypto
              .sign(null, bytes, keys.privateKey)
              .toString("base64url"),
          },
        },
        id,
        env,
        now,
      ),
    /bound/,
  );
});
test("customer MMMS and storage refuse legacy mode or missing IAM verification", (t) => {
  const saved = {
    NEOLA_CUSTOMER_DEPLOYMENT: process.env.NEOLA_CUSTOMER_DEPLOYMENT,
    CONTROL_PLANE_MODE: process.env.CONTROL_PLANE_MODE,
    IAM_API_URL: process.env.IAM_API_URL,
  };
  t.after(() => {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
  const guards = [
    require("../../mmms-backend/src/config/customer-deployment"),
    require("../../storage-service/config/customer-deployment"),
  ];
  process.env.NEOLA_CUSTOMER_DEPLOYMENT = "true";
  process.env.CONTROL_PLANE_MODE = "legacy";
  for (const guard of guards) assert.throws(guard, /require subscription/);
  process.env.CONTROL_PLANE_MODE = "subscription";
  delete process.env.IAM_API_URL;
  for (const guard of guards) assert.throws(guard, /require subscription/);
  process.env.IAM_API_URL = "http://iam:7001";
  for (const guard of guards) assert.doesNotThrow(guard);
});
