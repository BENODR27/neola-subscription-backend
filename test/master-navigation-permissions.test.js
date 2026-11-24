const { test } = require("node:test");
const assert = require("node:assert/strict");
const { hierarchyNavigationPermissions } = require("../src/master-permissions");
test("commercial navigation honors read bundles without turning one purchased page into all hierarchy access", () => {
  assert.ok(
    hierarchyNavigationPermissions(["MASTERS-READ"]).has(
      "MASTERS-FACTORIES-READ",
    ),
  );
  assert.ok(
    hierarchyNavigationPermissions(["MASTERS-ADMIN"]).has(
      "MASTERS-LOCATIONS-READ",
    ),
  );
  assert.ok(
    !hierarchyNavigationPermissions(["MASTERS-DEPARTMENTS-READ"]).has(
      "MASTERS-FACTORIES-READ",
    ),
  );
  assert.ok(
    !hierarchyNavigationPermissions(["MASTERS-MANAGE"]).has(
      "MASTERS-FACTORIES-READ",
    ),
  );
  assert.ok(!hierarchyNavigationPermissions([]).has("MASTERS-COMPANIES-READ"));
});
