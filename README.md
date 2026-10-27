# AccessHub — Team Access Portal

AccessHub is a responsive team access portal for submitting access requests, reviewing a team's queue, and managing accounts through server-enforced roles. It is built on the existing React and Express project and stores accounts, sessions, and access requests in SQLite.

## Features

- Member registration, secure login/logout, and an editable personal profile
- Admin, Manager, and Member roles with centrally defined server permissions
- Admin user directory, role updates, account suspension/reactivation, and user provisioning
- Manager team dashboard and request review limited to the manager's assigned team
- Member dashboard limited to requests they submitted
- Persistent SQLite storage, session expiry, session invalidation, and account status enforcement
- Responsive interface with validation, empty states, and success/error feedback

## Technology stack

- Node.js 22.12 or newer (`node:sqlite` and the patched Vite toolchain are required)
- Express 4, React 18, and Vite 7
- SQLite via Node's built-in `node:sqlite` module
- PBKDF2-HMAC-SHA256 password hashing using Node's built-in crypto module
- HttpOnly cookie sessions stored server-side in SQLite
- Supertest and Node's built-in test runner

## Prerequisites

- Node.js 22.12+ and npm
- Windows PowerShell commands below assume the project is at `C:\Users\NJ\Documents\SKYLEAX_TASK_08`

## Local installation and startup

From PowerShell:

```powershell
cd "C:\Users\NJ\Documents\SKYLEAX_TASK_08"
npm.cmd install
Copy-Item .env.example .env
notepad .env
```

Before the first launch, set unique `ACCESSHUB_ADMIN_PASSWORD` and `ACCESSHUB_MANAGER_PASSWORD` values in `.env` (12 or more characters). Optionally set `ACCESSHUB_USER_PASSWORD` to provision the local Member account. The seed users are created only when the users table is empty. Do not use the example values as production passwords. Public Member registration also works without a seed account.

Start the development client and API:

```powershell
npm.cmd run dev
```

- Frontend: http://localhost:5173
- API health check: http://localhost:3002/api/health

The Vite development server proxies `/api` to Express. The API loads `.env` if present, while process/deployment environment values take precedence.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `NODE_ENV` | `development` | Set to `production` when deploying. |
| `PORT` | `3002` | Express listening port. |
| `ACCESSHUB_DB_PATH` | `./server/data/accesshub.db` | Persistent SQLite database location. |
| `ACCESSHUB_ADMIN_PASSWORD` | unset | Optional initial `admin@accesshub.local` seed password; minimum 12 characters. |
| `ACCESSHUB_MANAGER_PASSWORD` | unset | Optional initial `manager@accesshub.local` seed password; minimum 12 characters. |
| `ACCESSHUB_USER_PASSWORD` | unset | Optional initial `user@accesshub.local` seed password; minimum 12 characters. |
| `SESSION_COOKIE_SECURE` | false outside production | Set `true` to require HTTPS cookies in development; production always enables Secure. |
| `SESSION_COOKIE_SAME_SITE` | `lax` | Cookie policy: `lax`, `strict`, or `none`. `none` requires Secure cookies. |

The project reads these values from the process environment and an optional root `.env` file. Keep `.env` out of source control. `.env.example` contains blank credential placeholders only.

## Database setup and migrations

The server creates the SQLite directory and tables on startup. It migrates existing user tables to include password-hash iteration metadata and existing access-request tables to include request ownership. Existing password hashes remain verifiable with their recorded legacy iteration count. Set `ACCESSHUB_DB_PATH` to a durable mounted volume in production; the default local path is ignored by Git.

Privileged seed accounts are created only on an empty users table. Configure the desired seed passwords before the first server launch. If an existing database has users but no administrator, promote/provision an admin through a trusted database administration process; setting seed variables after the first user exists does not create privileged accounts.

## Authentication and role permissions

- Public registration always assigns the least-privileged `user` database role (shown as **Member** in the UI). A submitted privileged role is rejected.
- Passwords require at least 10 characters with uppercase, lowercase, and numeric characters. They are stored as PBKDF2-HMAC-SHA256 hashes with a per-user random salt and 600,000 iterations. Existing hashes retain their stored iteration count.
- Login issues a random, 12-hour, HttpOnly, SameSite cookie. Cookies are Secure in production. The token is validated against a server-side SQLite session on protected API requests; logout deletes that server-side record.
- Role permissions are defined centrally in `server/server.js` and enforced by Express middleware and resource checks—not by UI visibility alone.
- Admins can view/manage users and access all teams' requests.
- Managers can read and review/delete requests only for their assigned team and view an aggregate team summary. They cannot access user-administration endpoints.
- Members can create and view their own requests and read/update permitted profile fields. They cannot change role, team, or account status, or review/delete requests.
- Protected APIs return `401` without a valid session and `403` when the role or resource scope is not permitted. Admins cannot suspend or demote the last active administrator.

## Testing all three roles

On a new/empty database, set distinct seed passwords for Admin and Manager before startup. The optional seeded Member is not required; any visitor may register a Member account. Sign in to test:

1. **Member:** register in the interface, create a request, update the profile name/email, and confirm that the dashboard shows only their own requests. Admin and team-management endpoints are forbidden.
2. **Manager:** sign in as `manager@accesshub.local`; view the assigned team's summary and review its requests. User management and requests outside the assigned team are forbidden.
3. **Admin:** sign in as `admin@accesshub.local`; review all requests, open User management, provision accounts, change other users' roles, and suspend/reactivate accounts.

Never use fixed demo passwords in production. Use separate strong passwords from your deployment secret manager.

## Automated tests

```powershell
cd "C:\Users\NJ\Documents\SKYLEAX_TASK_08"
npm.cmd test
```

Tests use an isolated SQLite test database and cover registration validation/duplicates, password hashing and verification, login/logout, protected routes, all three roles, request ownership/team boundaries, profile access, privilege escalation, account suspension, and admin operations.

## Production build and run

```powershell
cd "C:\Users\NJ\Documents\SKYLEAX_TASK_08"
npm.cmd run build
npm.cmd start
```

Set `NODE_ENV=production`, `PORT`, `ACCESSHUB_DB_PATH`, and initial privileged seed secrets in the deployment environment. The server serves `dist` when the production build exists. Use HTTPS, a durable private SQLite volume (or migrate to a managed database for multiple instances), backups, and a secret manager. Restrict filesystem access to the database and `.env`; never expose or commit secrets, password hashes, or session data. For Render, configure a persistent disk and keep generated seed values as protected environment secrets; `render.yaml` contains the service setup.
