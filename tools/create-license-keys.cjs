// Explicit key generation only. Existing signing keys are never overwritten.
const fs = require("node:fs"),
  path = require("node:path"),
  crypto = require("node:crypto");
const directory = process.argv[2];
if (!directory)
  throw Error(
    "Usage: node tools/create-license-keys.cjs /new/signing-key-directory",
  );
fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
const priv = path.resolve(directory, "provider-license-private.pem"),
  pub = path.resolve(directory, "provider-license-public.pem");
if (fs.existsSync(priv) || fs.existsSync(pub))
  throw Error(
    "Signing keys already exist; preserve them or use a new directory",
  );
const pair = crypto.generateKeyPairSync("ed25519");
fs.writeFileSync(
  priv,
  pair.privateKey.export({ format: "pem", type: "pkcs8" }),
  { flag: "wx", mode: 0o600 },
);
fs.writeFileSync(pub, pair.publicKey.export({ format: "pem", type: "spki" }), {
  flag: "wx",
  mode: 0o644,
});
console.log(
  "Created signing key files. Keep the private key only on the provider; distribute only the public key.",
);
