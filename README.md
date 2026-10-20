# AccessHub — Team Access Portal

AccessHub is a collaborative access-management dashboard for tracking software, system, and facility requests. Team leads can review requests, approve or deny access, and monitor workload without juggling spreadsheets.

## Features

- Secure registration and login with password hashing and session cookies
- Role-based access control for Admin, Manager, and User roles
- Protected dashboard, profile, and admin user management
- Manager-only team summary and access review features
- Request intake form for employee access needs
- Review queue with status filters and search
- Approve, reject, and reopen access requests from the dashboard
- SQLite-backed persistence for request records
- Quick metrics for pending, approved, rejected, and revoked requests
- Responsive React UI with a secure service dashboard layout

## Project structure

- `server/` — Express API, SQLite persistence layer, auth, and authorization logic
- `src/` — React frontend UI and styling
- `server/data/accesshub.db` — local SQLite database file
- `vite.config.js` — Vite dev server config with API proxy

## Prerequisites

- Node.js 22.5+
- npm

## Run locally

```powershell
cd "C:\Users\NJ\Documents\SKYLEAX_TASK_08"
npm.cmd install
npm.cmd run dev
```

The app starts:

- Frontend: http://localhost:5173
- API: http://localhost:3002/api/health

Public registration creates User-role accounts. To seed privileged local accounts on a **new, empty database**, set one or more of these environment variables before starting the server:

- `ACCESSHUB_ADMIN_PASSWORD` — seeds `admin@accesshub.local`
- `ACCESSHUB_MANAGER_PASSWORD` — seeds `manager@accesshub.local`
- `ACCESSHUB_USER_PASSWORD` — seeds `user@accesshub.local`

Each configured seed password must be at least 12 characters. Choose your own strong values and keep them in your local environment or deployment secret store; do not commit them. Seed accounts are only created while the users table is empty. The application does not ship with default demo passwords.

## Production build

```powershell
cd "C:\Users\NJ\Documents\SKYLEAX_TASK_08"
npm.cmd run build
npm.cmd start
```

Set the environment variables below before production startup. The Express app serves the built frontend from `dist` when present.

```powershell
$env:NODE_ENV = 'production'
$env:PORT = '3002'
$env:ACCESSHUB_DB_PATH = 'C:\Users\NJ\Documents\SKYLEAX_TASK_08\server\data\accesshub.db'
$env:ACCESSHUB_ADMIN_PASSWORD = '<strong-admin-password>'
$env:ACCESSHUB_MANAGER_PASSWORD = '<strong-manager-password>'
$env:ACCESSHUB_USER_PASSWORD = '<strong-user-password>'
$env:SESSION_COOKIE_SECURE = 'true'
$env:SESSION_COOKIE_SAME_SITE = 'lax'
```

### Deployment (Render)

This project is structured as a single Node.js service that serves the built React frontend and the Express API from the same app. A Render Web Service suits it well:

- Build command: `npm install && npm run build`
- Start command: `npm start`
- Persistent SQLite path: `/var/data/accesshub.db`
- Required environment variables: `NODE_ENV`, `PORT`, `ACCESSHUB_DB_PATH`, `ACCESSHUB_ADMIN_PASSWORD`, `ACCESSHUB_MANAGER_PASSWORD`, `ACCESSHUB_USER_PASSWORD`, `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_SAME_SITE`

The repository includes a ready-to-use [render.yaml](./render.yaml) for that setup.

## Authentication and authorization

- Public registration is limited to the `user` role only.
- Passwords are hashed with PBKDF2 and compared with `timingSafeEqual`.
- Login creates a server-managed session using an HTTP-only cookie.
- Logout clears the session cookie and deletes the session record.
- Protected routes return `401` when unauthenticated and `403` when role permissions are missing.

## API endpoints

### Public auth

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/session`

### Protected endpoints

- `GET /api/requests`
- `POST /api/requests`
- `PATCH /api/requests/:id`
- `DELETE /api/requests/:id`
- `GET /api/stats`
- `GET /api/users` (admin only)
- `POST /api/users` (admin only)
- `GET /api/users/:id` (self or admin)
- `PATCH /api/users/:id` (self except role change, or admin)
- `GET /api/team/summary` (manager or admin)

## Testing

```powershell
cd "C:\Users\NJ\Documents\SKYLEAX_TASK_08"
npm.cmd test
```

The automated tests cover public registration rules, secure login, session management, unauthorized access handling, admin user management, manager team access, and protected access request workflows.
