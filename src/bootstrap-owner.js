const { randomUUID } = require("node:crypto");
const { query, pool } = require("./database");
const { text, password, requireValue } = require("./security");
async function bootstrap() {
  const username = text(
    process.env.CONTROL_OWNER_USERNAME,
    "CONTROL_OWNER_USERNAME",
  ).toLowerCase();
  const display = text(
    process.env.CONTROL_OWNER_NAME || "NeoLA Platform Owner",
    "Owner name",
  );
  const exists = await query("SELECT 1 FROM control_users WHERE role=$1", [
    "platform_owner",
  ]);
  if (exists.rowCount && process.argv.includes("--if-empty")) {
    console.log("Existing platform owner preserved");
    return;
  }
  requireValue(
    !exists.rowCount,
    "A platform owner already exists; bootstrap never resets credentials",
    409,
  );
  const passwordHash = await password(process.env.CONTROL_OWNER_PASSWORD);
  await query(
    "INSERT INTO control_users(id,username,display_name,password_hash,role) VALUES($1,$2,$3,$4,'platform_owner')",
    [randomUUID(), username, display, passwordHash],
  );
  console.log("Created platform owner:", username);
}
if (require.main === module)
  bootstrap()
    .catch((e) => {
      console.error(e.message);
      process.exitCode = 1;
    })
    .finally(() => pool.end());
module.exports = bootstrap;
