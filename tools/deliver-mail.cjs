require("dotenv").config();
const { query, pool } = require("../src/database");
const { decrypt, requireValue } = require("../src/security");
(async () => {
  const url = process.env.CONTROL_MAIL_WEBHOOK_URL;
  requireValue(
    url && new URL(url).protocol === "https:",
    "Configure an HTTPS CONTROL_MAIL_WEBHOOK_URL",
  );
  const { rows } = await query(
    "SELECT * FROM control_mail_outbox WHERE status='queued' ORDER BY created_at LIMIT 25",
  );
  for (const row of rows) {
    const response = await fetch(url, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(10000),
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${process.env.CONTROL_MAIL_WEBHOOK_TOKEN || ""}`,
        "Idempotency-Key": row.id,
      },
      body: JSON.stringify({
        id: row.id,
        to: row.recipient,
        ...JSON.parse(decrypt(row.encrypted_payload)),
      }),
    });
    if (response.ok)
      await query("UPDATE control_mail_outbox SET status='sent' WHERE id=$1", [
        row.id,
      ]);
    else throw Error("Mail provider rejected delivery");
  }
  console.log("Delivery queue processed");
})()
  .catch((e) => {
    console.error(e.message);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
