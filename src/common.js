const { randomUUID } = require("node:crypto");
const { query } = require("./database");
const { requireValue, customerScope } = require("./security");
const uuid = (v) =>
  typeof v === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    v,
  );
function id(value) {
  requireValue(uuid(value), "Invalid record ID");
  return value;
}
function integer(value, min, max, label) {
  requireValue(
    Number.isSafeInteger(value) && value >= min && value <= max,
    `${label} must be an integer from ${min} to ${max}`,
  );
  return value;
}
async function audit(db, user, action, target, customerId, details = {}) {
  await db.query(
    "INSERT INTO control_audit(actor_id,customer_id,action,target_id,details) VALUES($1,$2,$3,$4,$5)",
    [user?.id || null, customerId, action, target, JSON.stringify(details)],
  );
}
async function list(
  req,
  table,
  fields,
  {
    customer = false,
    where = [],
    values = [],
    order = "created_at DESC,id DESC",
  } = {},
) {
  if (customer) {
    const scope = customerScope(req.user, req.query.customer_id);
    if (scope) {
      values.push(id(scope));
      where.push(`customer_id=$${values.length}`);
    }
  }
  const page = Number(req.query.page || 1),
    pageSize = Number(req.query.pageSize || 20);
  integer(page, 1, 100000, "Page");
  integer(pageSize, 1, 100, "Page size");
  const filter = where.length ? ` WHERE ${where.join(" AND ")}` : "";
  const total = Number(
    (await query(`SELECT count(*) FROM ${table}${filter}`, values)).rows[0]
      .count,
  );
  const rows = (
    await query(
      `SELECT ${fields} FROM ${table}${filter} ORDER BY ${order} LIMIT $${values.length + 1} OFFSET $${values.length + 2}`,
      [...values, pageSize, (page - 1) * pageSize],
    )
  ).rows;
  return {
    items: rows,
    page,
    pageSize,
    total,
    totalPages: Math.ceil(total / pageSize),
  };
}
async function scopedRecord(db, table, recordId, user, lock = false) {
  const {
    rows: [row],
  } = await db.query(
    `SELECT * FROM ${table} WHERE id=$1${lock ? " FOR UPDATE" : ""}`,
    [id(recordId)],
  );
  requireValue(row, "Record not found", 404);
  customerScope(
    user,
    row.customer_id || (table === "control_customers" ? row.id : undefined),
  );
  return row;
}
module.exports = { uuid, id, integer, audit, list, scopedRecord, randomUUID };
