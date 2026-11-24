-- Register page/action definitions without changing purchased plans, request snapshots or roles.
INSERT INTO control_permissions(code,application_code,description,enabled)
SELECT code,'MASTERS','Hierarchy page permission',true
FROM unnest(ARRAY['MASTERS-COMPANIES-READ','MASTERS-COMPANIES-MANAGE','MASTERS-BUSINESS-UNITS-READ','MASTERS-BUSINESS-UNITS-MANAGE','MASTERS-FACTORIES-READ','MASTERS-FACTORIES-MANAGE','MASTERS-BUILDINGS-READ','MASTERS-BUILDINGS-MANAGE','MASTERS-FLOORS-READ','MASTERS-FLOORS-MANAGE','MASTERS-DEPARTMENTS-READ','MASTERS-DEPARTMENTS-MANAGE','MASTERS-SECTIONS-READ','MASTERS-SECTIONS-MANAGE','MASTERS-LINES-READ','MASTERS-LINES-MANAGE','MASTERS-LOCATIONS-READ','MASTERS-LOCATIONS-MANAGE']) code
WHERE EXISTS(SELECT 1 FROM control_applications WHERE code='MASTERS')
ON CONFLICT(code) DO NOTHING;

-- Replace only known generated hierarchy entries; preserve other entries and existing page customizations.
UPDATE control_applications app
SET navigation = (
  SELECT jsonb_agg(replacement.item ORDER BY source.position,replacement.position)
  FROM jsonb_array_elements(app.navigation) WITH ORDINALITY source(item,position)
  CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN source.item IN ('{"label":"Organization hierarchy","link":"/masters/organization","icon":"bi-diagram-3","permission":"MASTERS-READ"}'::jsonb,'{"label":"Shared masters","link":"/masters","icon":"bi-diagram-3","permission":"MASTERS-READ"}'::jsonb)
    THEN (SELECT COALESCE(jsonb_agg(page),'[]'::jsonb) FROM jsonb_array_elements('[{"label":"Companies","link":"/masters/companies","icon":"bi-buildings","permission":"MASTERS-COMPANIES-READ"},{"label":"Business units","link":"/masters/business-units","icon":"bi-diagram-2","permission":"MASTERS-BUSINESS-UNITS-READ"},{"label":"Factories","link":"/masters/factories","icon":"bi-building-gear","permission":"MASTERS-FACTORIES-READ"},{"label":"Buildings","link":"/masters/buildings","icon":"bi-building","permission":"MASTERS-BUILDINGS-READ"},{"label":"Floors","link":"/masters/floors","icon":"bi-layers","permission":"MASTERS-FLOORS-READ"},{"label":"Departments","link":"/masters/departments","icon":"bi-briefcase","permission":"MASTERS-DEPARTMENTS-READ"},{"label":"Sections","link":"/masters/sections","icon":"bi-grid-1x2","permission":"MASTERS-SECTIONS-READ"},{"label":"Lines","link":"/masters/lines","icon":"bi-distribute-horizontal","permission":"MASTERS-LINES-READ"},{"label":"Locations","link":"/masters/locations","icon":"bi-geo-alt","permission":"MASTERS-LOCATIONS-READ"}]'::jsonb) page
      WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(app.navigation) existing WHERE existing->>'link'=page->>'link'))
    ELSE jsonb_build_array(source.item) END
  ) WITH ORDINALITY replacement(item,position)
)
WHERE app.code='MASTERS' AND EXISTS(
  SELECT 1 FROM jsonb_array_elements(app.navigation) item WHERE item IN ('{"label":"Organization hierarchy","link":"/masters/organization","icon":"bi-diagram-3","permission":"MASTERS-READ"}'::jsonb,'{"label":"Shared masters","link":"/masters","icon":"bi-diagram-3","permission":"MASTERS-READ"}'::jsonb)
);

