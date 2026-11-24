-- Upgrade the original generated catalog menu without changing grants, plans or customized navigation.
UPDATE control_applications
SET navigation = '[{"label":"Organization hierarchy","link":"/masters/organization","icon":"bi-diagram-3","permission":"MASTERS-READ"},{"label":"Units of measure","link":"/masters/units","icon":"bi-rulers","permission":"MASTERS-READ"},{"label":"Currencies","link":"/masters/currencies","icon":"bi-currency-exchange","permission":"MASTERS-READ"},{"label":"Employees","link":"/masters/employees","icon":"bi-people","permission":"MASTERS-READ"},{"label":"Contacts","link":"/masters/contacts","icon":"bi-person-lines-fill","permission":"MASTERS-READ"},{"label":"Vendors","link":"/masters/vendors","icon":"bi-buildings","permission":"MASTERS-READ"}]'::jsonb
WHERE code = 'MASTERS' AND landing_route = '/masters'
  AND navigation = '[{"label":"Shared masters","link":"/masters","icon":"bi-diagram-3","permission":"MASTERS-READ"}]'::jsonb;

