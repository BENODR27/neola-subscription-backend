require("dotenv").config();
const { query, pool } = require("../src/database");
const s = require("../src/security");
(async () => {
  s.requireValue(
    process.env.NODE_ENV !== "production",
    "Local outbox inspection is disabled in production",
  );
  const username = process.argv[2];
  s.requireValue(username, "Pass an exact local username");
  const { rows } = await query(
    "SELECT o.* FROM control_mail_outbox o JOIN control_users u ON u.id=o.user_id WHERE u.username=$1 ORDER BY o.created_at DESC LIMIT 10",
    [username],
  );
  if (!rows.length) console.log("No queued messages for this local account.");
  for (const row of rows)
    console.log(
      JSON.stringify({
        kind: row.kind,
        to: row.recipient,
        status: row.status,
        ...JSON.parse(s.decrypt(row.encrypted_payload)),
      }),
    );
})()
  .catch((e) => {
    console.error(e.message);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
