# NeoLA subscription API

Independent Docker deployment: [package setup and environment configuration](DEPLOYMENT.md).

Independent provider/customer console identity, catalogs, plans, trials, manual approvals, dedicated ERP instances and entitlement enforcement. Own PostgreSQL database; default local API port 7020.

See [development, Docker, operator workflow and ERP cutover](../docs/SUBSCRIPTION-MANAGEMENT.md) and [requirements](../reqs/SUBSCRIPTION-MANAGEMENT.MD). Start with `npm ci`, a new `.env` from `.env.example`, `npm run db:create`, `npm run db:migrate`, `npm run bootstrap:owner`, then `npm run dev`. No default deployed login is supplied.
# neola-subscription-backend
