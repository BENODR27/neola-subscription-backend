# Subscription API ownership

Read `../reqs/SUBSCRIPTION-MANAGEMENT.MD` and `../docs/SUBSCRIPTION-MANAGEMENT.md`. This service owns separate console authentication and commercial controls. It must never issue ERP employee JWTs or read maintenance tables. Preserve customer scoping, maker/checker approvals, immutable request snapshots, one trial per customer and audited transactions. Never expose activation keys on list/read endpoints or log passwords/keys. Changes to the private bridge must retain exact origin allowlists, instance-specific key verification, timeouts and no redirects.

Run `npm test` and `npm run test:integration`; integration uses only the documented isolated test databases. Do not enable subscription mode on existing user services or restart them without the deployment operator’s authorization. Additional applications require tested runtime enforcement before inclusion in `CONTROL_ENFORCED_APPLICATIONS`.
