const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { seedEnvironment } = require("../src/seed-base");

test("Console seed file keeps literal passwords and cannot change its database target", () => {
  const previous = process.cwd();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "control-seed-env-"));
  try {
    process.chdir(directory);
    fs.writeFileSync(
      ".env.seed",
      "CONTROL_OWNER_USERNAME=seed.owner\nCONTROL_OWNER_PASSWORD=literal#password=$value\nDB_HOST=untrusted.invalid\n",
    );
    const result = seedEnvironment({});
    assert.equal(result.CONTROL_OWNER_PASSWORD, "literal#password=$value");
    assert.equal(result.DB_HOST, undefined);
    assert.equal(
      seedEnvironment({ CONTROL_OWNER_PASSWORD: "explicit-value" })
        .CONTROL_OWNER_PASSWORD,
      "explicit-value",
    );
  } finally {
    process.chdir(previous);
  }
});
