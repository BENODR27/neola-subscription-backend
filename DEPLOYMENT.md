# Subscription API deployment

Host: **Provider server**. This repository builds independently; no shared external
Docker network is required. All services bind to `0.0.0.0` by default. Calls to
other services use their actual IP and published port, never `0.0.0.0`.

## Configure once

For a new configuration, copy `provider.env.example` to `.env.container` and
`.env.deploy.example` to `.env.deploy` without replacing existing files.
Fill the existing secrets and replace these destination placeholders:

```dotenv
DB_HOST=PROVIDER_DATABASE_IP
DB_PORT=5432
CONTROL_DB_NAME=neola_subscriptions
CONTROL_PORTAL_URL=https://PROVIDER_IP:5443
CONTROL_ALLOWED_ORIGINS=https://PROVIDER_IP:5443
CONTROL_ERP_ALLOWED_ORIGINS=https://CUSTOMER_IP:5443
```

Preserve database credentials, JWT issuer/audience, password hashes, instance ID/key
and the Console encryption key when restoring existing data. IAM, MMMS and storage
share the customer's JWT signing secret. Console logins are independent.
Set `STORAGE_VOLUME` in storage's deployment settings to its restored upload volume.
No frontend receives database passwords, signing private keys or activation keys.

## Run this repository

### First installation: base Console users

After migrations, copy `seed.env.example` to private `.env.seed` and configure
the owner username/password. Then:

```sh
docker compose --env-file .env.deploy -f compose.independent.yaml --profile maintenance run --rm --build seed
```

Optional npm alias: `npm run docker:seed`. Native CLI: `npm run db:seed:base`.
For a local test installation, set `CONTROL_SEED_TEST_USERS=true` and configure
the approver and customer usernames/passwords too. This option is refused in
production. The pending test customer can request a plan but receives no automatic
subscription, application entitlement or approval. Production seeds only the
initial owner; create real customers/staff through normal Console administration.

Repeat runs preserve existing password hashes, roles, IDs, customer membership,
disabled state and MFA/security settings. A username already assigned another
role or another existing bootstrap owner is not replaced. Missing credentials
abort the whole transaction, so no partial account set is created.

Commercial catalog import stays in the existing installation/catalog controls;
configure it after registering the ERP installation. Seeders do not read IAM's
database, invent plans or bypass purchase/trial approval. Restored databases need
migrations, not bootstrap seeds. Keep `.env.seed` private and out of Git.

For provider production deployment:

```sh
docker compose --env-file .env.deploy -f compose.independent.yaml -f compose.provider.yaml up -d --build
```

Optional npm alias: `npm run docker:provider`. The provider profile enforces
production security; do not use the local runtime profile for a sold installation.

Set `CONTROL_LICENSE_PRIVATE_KEY_HOST_FILE` in `.env.deploy` to the existing
provider signing private key. Keep it only on your provider server. The provider
profile requires signatures, verified operator emails and MFA. Its default two
trusted proxy hops assume a controlled HTTPS gateway plus the Console Nginx.

Put the provider frontend behind an HTTPS gateway for production. Port 5443 above
is an example external HTTPS port, not a new automatically started proxy. An
IP-based HTTPS endpoint needs a trusted TLS certificate valid for that IP. Existing
platform release documentation includes the gateway setup. Browser origins and
public links must match the real external HTTPS IP:port. Gateways forward to the
frontend HTTP port (ERP 5001, Console 5006). Restrict direct API/database ports to
trusted callers with the firewall.

Database migrations are explicit: run `npm run docker:migrate` during a maintenance
window before upgraded APIs. It never bootstraps accounts or resets passwords.

For local testing only, the base `compose.independent.yaml` and `.env.container.example`
remain available. The separate common-db test repository uses port 5433 and volume
`neola-test-pgdata`; set test API DB_HOST to its server IP and DB_PORT=5433. Keep
production customer/provider databases and credentials isolated. Databases and
uploads must already be restored; environment files do not migrate data. Never
commit real `.env` files or keys, delete volumes, or run account bootstrap on a
restored database.
