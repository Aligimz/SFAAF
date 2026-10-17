# ELITE ROLEPLAY MANAGEMENT

A cloud-ready Arabic RTL MVP for managing FiveM/Discord roleplay staff. Includes PostgreSQL persistence, owner bootstrap, cookie-based sessions, server-side authorization, staff/sectors/tasks/shifts/gangs/complaints CRUD, user management, and audit logs.

## Current scope

- Working sign-in and one-time owner setup flow.
- Roles: `owner`, `manager`, `staff`, `viewer` (write access is currently owner/manager; delete and user management are owner-only).
- CRUD for staff, sectors, tasks, shifts, gangs, complaints.
- Audit trail and overview metrics.
- CSV export from list pages.
- Cloud deployment blueprint for Render.

## Important limitations

- Discord and FiveM integrations are **not active** by default. API credentials alone are not enough; the relevant OAuth2 flow, bot permissions, and/or FiveM resource must be configured and tested separately.
- This is a functional starter/MVP, not a finished enterprise product. Before handling sensitive real data, add automated tests, MFA, stronger permission granularity, data-retention policy, rate limits for all write endpoints, file-upload scanning if uploads are added, and review the deployment's database TLS/network settings.
- `sector_id` fields expect a numeric sector database ID. Add a proper dropdown backed by `/api/sectors` before production use if non-technical users will enter records.
- Avoid storing sensitive real-world personal information that the server does not need.

## Local run

Requires Node.js 20+ and PostgreSQL.

1. Create a PostgreSQL database.
2. Copy `.env.example` to `.env` and set `DATABASE_URL`, `JWT_SECRET` (32+ random characters), and `SETUP_KEY` (24+ random characters).
3. Install dependencies: `npm install`
4. Load environment variables using your shell or a local dotenv tool (dotenv is intentionally not bundled):
   - PowerShell example: `$env:DATABASE_URL='postgresql://...'; $env:JWT_SECRET='...'; $env:SETUP_KEY='...'; npm start`
5. Open `http://localhost:10000`.

The server creates tables automatically at startup. First-time setup asks for `SETUP_KEY` to create the first owner account. Once an owner exists, setup is closed.

## Deploy to Render

1. Put this project in a **private** Git repository.
2. Create a Render PostgreSQL database, then a Web Service from the repository, or use `render.yaml` as a starting blueprint.
3. Set `DATABASE_URL` to the database's internal connection string, `NODE_ENV=production`, a long random `JWT_SECRET`, and a separate long random `SETUP_KEY` in Render Environment settings. Never commit `.env` or secrets.
4. Deploy and open the generated `onrender.com` URL.
5. Create the owner account with the one-time setup form. Keep the setup key private; rotate it after setup.
6. Verify `/api/health`, sign in, create a sector and staff member, and verify data persists after a redeploy.
7. Configure backups and review database retention and billing before using production data.

## Suggested next development phase

- Add granular permissions by module and action.
- Add server-side validation schemas and automated integration tests.
- Add user password reset, MFA, account lockout, and security headers/CSP review.
- Add proper relations/dropdowns for sector/staff IDs.
- Add Discord OAuth2 and bot integration with least-privilege permissions.
- Build a FiveM Lua resource that authenticates to a protected API; do not expose API keys in client scripts.
