const fs = require("node:fs");
const crypto = require("node:crypto");
function privateKey(env = process.env) {
  const file = env.CONTROL_LICENSE_PRIVATE_KEY_FILE;
  if (!file) {
    if (env.CONTROL_REQUIRE_SIGNED_LICENSE === "true")
      throw Error("Configure the provider license signing key file");
    return null;
  }
  const key = crypto.createPrivateKey(fs.readFileSync(file));
  if (key.asymmetricKeyType !== "ed25519")
    throw Error("The provider license signing key must be Ed25519");
  return key;
}
function signLicense(
  entitlements,
  instanceId,
  env = process.env,
  now = Date.now(),
) {
  const key = privateKey(env);
  if (!key) return entitlements;
  const payload = Buffer.from(
    JSON.stringify({
      version: 1,
      iss: "neola-control",
      aud: "neola-erp-license",
      instance_id: instanceId,
      iat: now,
      exp: now + 15000,
      entitlements,
    }),
  );
  return {
    ...entitlements,
    lease: {
      payload: payload.toString("base64url"),
      signature: crypto.sign(null, payload, key).toString("base64url"),
    },
  };
}
module.exports = { privateKey, signLicense };
