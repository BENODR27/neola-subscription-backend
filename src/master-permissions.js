// Masters read/admin grants are legacy all-hierarchy bundles. Specific grants stay specific.
function hierarchyNavigationPermissions(permissions) {
  const expanded = new Set(permissions);
  if (expanded.has("MASTERS-READ") || expanded.has("MASTERS-ADMIN"))
    for (const code of [
      "MASTERS-COMPANIES-READ",
      "MASTERS-BUSINESS-UNITS-READ",
      "MASTERS-FACTORIES-READ",
      "MASTERS-BUILDINGS-READ",
      "MASTERS-FLOORS-READ",
      "MASTERS-DEPARTMENTS-READ",
      "MASTERS-SECTIONS-READ",
      "MASTERS-LINES-READ",
      "MASTERS-LOCATIONS-READ",
    ])
      expanded.add(code);
  return expanded;
}
module.exports = { hierarchyNavigationPermissions };
