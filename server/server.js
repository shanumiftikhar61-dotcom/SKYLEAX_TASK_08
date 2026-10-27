import express from 'express';
import dotenv from 'dotenv';
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID, randomBytes, pbkdf2Sync, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
dotenv.config({ path: path.join(projectRoot, '.env') });
const dbDirectory = path.join(projectRoot, 'server', 'data');
const dbPath = process.env.ACCESSHUB_DB_PATH || path.join(dbDirectory, 'accesshub.db');
const distPath = path.join(projectRoot, 'dist');

fs.mkdirSync(path.dirname(dbPath), { recursive: true });

const app = express();
const port = Number(process.env.PORT || 3002);
const isProduction = process.env.NODE_ENV === 'production';
const cookieSecure = isProduction || process.env.SESSION_COOKIE_SECURE === 'true';
const cookieSameSite = process.env.SESSION_COOKIE_SAME_SITE || 'lax';
if (!['lax', 'strict', 'none'].includes(cookieSameSite.toLowerCase())) {
  throw new Error('SESSION_COOKIE_SAME_SITE must be lax, strict, or none.');
}
if (cookieSameSite.toLowerCase() === 'none' && !cookieSecure) {
  throw new Error('SameSite=None cookies require SESSION_COOKIE_SECURE=true.');
}
const db = new DatabaseSync(dbPath);
const SESSION_COOKIE = 'accesshub_session';
const VALID_ROLES = ['admin', 'manager', 'user'];
const ROLE_PERMISSIONS = {
  admin: ['requests:read', 'requests:create', 'requests:review', 'requests:delete', 'users:manage', 'teams:read', 'profile:read', 'profile:update'],
  manager: ['requests:read', 'requests:create', 'requests:review', 'requests:delete', 'teams:read', 'profile:read', 'profile:update'],
  user: ['requests:read', 'requests:create', 'profile:read', 'profile:update'],
};
const VALID_STATUS = ['pending', 'approved', 'rejected', 'revoked'];
const VALID_REQUEST_TYPES = new Set(['software', 'facility', 'data', 'system', 'other']);

function normalizeText(value) {
  return typeof value === 'string' ? value.trim() : '';
}

const PASSWORD_ITERATIONS = 600000;

function createHash(password, saltValue = randomBytes(16).toString('hex'), iterations = PASSWORD_ITERATIONS) {
  const hash = pbkdf2Sync(password, saltValue, iterations, 64, 'sha256').toString('hex');
  return { salt: saltValue, hash, iterations };
}

function verifyPassword(password, saltValue, expectedHash, iterations = PASSWORD_ITERATIONS) {
  const attempt = pbkdf2Sync(password, saltValue, iterations, 64, 'sha256').toString('hex');
  const actual = Buffer.from(attempt, 'hex');
  const expected = Buffer.from(expectedHash, 'hex');
  if (actual.length !== expected.length) {
    return false;
  }
  return timingSafeEqual(actual, expected);
}

function sanitizeUser(user) {
  return {
    id: user.id,
    email: user.email,
    fullName: user.full_name,
    role: user.role,
    team: user.team,
    status: user.status,
    createdAt: user.created_at,
    updatedAt: user.updated_at,
  };
}

function serializeRequest(row) {
  return {
    id: row.id,
    employee: row.employee,
    team: row.team,
    role: row.role,
    accessType: row.accessType,
    justification: row.justification,
    priority: row.priority,
    status: row.status,
    reviewer: row.reviewer,
    requestedAt: row.requestedAt,
    reviewedAt: row.reviewedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function parseCookies(headerValue = '') {
  const cookies = {};
  for (const chunk of (headerValue || '').split(';')) {
    const trimmed = chunk.trim();
    if (!trimmed) continue;
    const separatorIndex = trimmed.indexOf('=');
    if (separatorIndex === -1) continue;
    const key = trimmed.slice(0, separatorIndex);
    const value = trimmed.slice(separatorIndex + 1);
    cookies[key] = value;
  }
  return cookies;
}

function getSessionToken(req) {
  const sessionCookie = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  return sessionCookie || null;
}

function createSessionRecord(userId) {
  const token = `${randomUUID()}-${randomUUID()}`;
  const now = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 12).toISOString();
  const sessionId = randomUUID();

  db.prepare(
    'INSERT INTO sessions (id, user_id, token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)',
  ).run(sessionId, userId, token, expiresAt, now);

  return { token, expiresAt };
}

function getUserByEmail(email) {
  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  return row || null;
}

function getUserById(userId) {
  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  return row || null;
}

function ensureTables() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      password_iterations INTEGER NOT NULL DEFAULT 100000,
      full_name TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'manager', 'user')),
      team TEXT NOT NULL DEFAULT 'General',
      status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      token TEXT UNIQUE NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS access_requests (
      id TEXT PRIMARY KEY,
      created_by TEXT,
      employee TEXT NOT NULL,
      team TEXT NOT NULL,
      role TEXT NOT NULL,
      accessType TEXT NOT NULL,
      justification TEXT NOT NULL,
      priority TEXT NOT NULL DEFAULT 'medium',
      status TEXT NOT NULL DEFAULT 'pending',
      reviewer TEXT,
      requestedAt TEXT NOT NULL,
      reviewedAt TEXT,
      createdAt TEXT NOT NULL,
      updatedAt TEXT NOT NULL
    );

  `);

  const requestColumns = db.prepare('PRAGMA table_info(access_requests)').all();
  if (!requestColumns.some((column) => column.name === 'created_by')) {
    db.exec('ALTER TABLE access_requests ADD COLUMN created_by TEXT');
  }
  const userColumns = db.prepare('PRAGMA table_info(users)').all();
  if (!userColumns.some((column) => column.name === 'password_iterations')) {
    db.exec('ALTER TABLE users ADD COLUMN password_iterations INTEGER NOT NULL DEFAULT 100000');
  }
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_requests_created_by ON access_requests(created_by);
    CREATE INDEX IF NOT EXISTS idx_requests_team_status ON access_requests(team, status);
  `);
}

function seedUsers() {
  const count = db.prepare('SELECT COUNT(*) AS count FROM users').get().count;
  if (count > 0) return;

  const users = [
    { email: 'admin@accesshub.local', password: process.env.ACCESSHUB_ADMIN_PASSWORD, fullName: 'System Administrator', role: 'admin', team: 'Operations' },
    { email: 'manager@accesshub.local', password: process.env.ACCESSHUB_MANAGER_PASSWORD, fullName: 'Team Manager', role: 'manager', team: 'Engineering' },
    { email: 'user@accesshub.local', password: process.env.ACCESSHUB_USER_PASSWORD, fullName: 'Standard User', role: 'user', team: 'Support' },
  ].filter((user) => user.password);

  for (const user of users) {
    if (user.password.length < 12) {
      throw new Error(`The configured seed password for role "${user.role}" must be at least 12 characters.`);
    }
  }

  const insert = db.prepare(
    'INSERT INTO users (id, email, password_hash, password_salt, password_iterations, full_name, role, team, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
  );

  for (const item of users) {
    const now = new Date().toISOString();
    const { salt, hash, iterations } = createHash(item.password);
    insert.run(
      randomUUID(),
      item.email,
      hash,
      salt,
      iterations,
      item.fullName,
      item.role,
      item.team,
      'active',
      now,
      now,
    );
  }
}

function validateRequestPayload(payload) {
  const errors = [];
  const employee = normalizeText(payload.employee);
  const team = normalizeText(payload.team);
  const role = normalizeText(payload.role);
  const accessType = normalizeText(payload.accessType);
  const justification = normalizeText(payload.justification);
  const priority = normalizeText(payload.priority || 'medium');
  const status = normalizeText(payload.status || 'pending');

  if (employee.length < 2) errors.push('Employee name is required (minimum 2 characters).');
  if (employee.length > 100) errors.push('Employee name must not exceed 100 characters.');
  if (team.length < 2) errors.push('Team is required (minimum 2 characters).');
  if (team.length > 80) errors.push('Team must not exceed 80 characters.');
  if (role.length < 2) errors.push('Role is required (minimum 2 characters).');
  if (role.length > 100) errors.push('Role must not exceed 100 characters.');
  if (!VALID_REQUEST_TYPES.has(accessType)) errors.push('Access type must be software, facility, data, system, or other.');
  if (justification.length < 10) errors.push('Justification must be at least 10 characters long.');
  if (justification.length > 2000) errors.push('Justification must not exceed 2000 characters.');
  if (!['low', 'medium', 'high'].includes(priority)) errors.push('Priority must be low, medium, or high.');
  if (!VALID_STATUS.includes(status)) errors.push('Status must be pending, approved, rejected, or revoked.');

  return { errors, employee, team, role, accessType, justification, priority, status };
}

function validateUserInput(payload, mode = 'register') {
  const errors = [];
  const email = normalizeText(payload.email).toLowerCase();
  const password = typeof payload.password === 'string' ? payload.password : '';
  const fullName = normalizeText(payload.fullName || payload.full_name || payload.name);
  const team = normalizeText(payload.team || 'General');

  if (email.length > 254) errors.push('Email address must not exceed 254 characters.');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    errors.push('A valid email address is required.');
  }
  if (password.length > 128) errors.push('Password must not exceed 128 characters.');
  if (password.length < 10 || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
    errors.push('Password must be at least 10 characters and include uppercase, lowercase, and numeric characters.');
  }
  if (fullName.length < 2) {
    errors.push('Full name is required.');
  } else if (fullName.length > 100) {
    errors.push('Full name must not exceed 100 characters.');
  }
  if (team.length > 80) errors.push('Team must not exceed 80 characters.');
  if (mode === 'register' && payload.role && normalizeText(payload.role) !== 'user') {
    errors.push('Only public registration for the User role is allowed.');
  }

  return { errors, email, password, fullName, team };
}

function hasPermission(user, permission) {
  return Boolean(user && ROLE_PERMISSIONS[user.role]?.includes(permission));
}

function requireAuth(req, res, next) {
  const token = getSessionToken(req);
  if (!token) {
    return res.status(401).json({ success: false, error: { message: 'Authentication required.' } });
  }

  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) {
    clearSessionCookie(res);
    return res.status(401).json({ success: false, error: { message: 'Session expired or invalid.' } });
  }

  if (new Date(session.expires_at).getTime() <= Date.now()) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    clearSessionCookie(res);
    return res.status(401).json({ success: false, error: { message: 'Session expired.' } });
  }

  const user = getUserById(session.user_id);
  if (!user) {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    clearSessionCookie(res);
    return res.status(401).json({ success: false, error: { message: 'User session not found.' } });
  }

  if (user.status !== 'active') {
    db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
    clearSessionCookie(res);
    return res.status(401).json({ success: false, error: { message: 'This account is inactive.' } });
  }

  req.user = sanitizeUser(user);
  req.sessionToken = token;
  next();
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!hasPermission(req.user, permission)) {
      return res.status(403).json({ success: false, error: { message: 'Forbidden: insufficient permissions.' } });
    }
    next();
  };
}

function clearSessionCookie(res) {
  res.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    sameSite: cookieSameSite,
    secure: cookieSecure,
    path: '/',
  });
}

function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: cookieSameSite,
    secure: cookieSecure,
    path: '/',
    maxAge: 1000 * 60 * 60 * 12,
  };
}

app.use(express.json({ limit: '1mb' }));

app.get('/api/health', (_req, res) => {
  res.json({ success: true, data: { ok: true } });
});

app.post('/api/auth/register', (req, res) => {
  const payload = req.body || {};

  if (payload.role && normalizeText(payload.role) !== 'user') {
    return res.status(400).json({
      success: false,
      error: { message: 'Only public registration for the User role is allowed.' },
    });
  }

  const validation = validateUserInput(payload, 'register');

  if (validation.errors.length > 0) {
    return res.status(400).json({ success: false, error: { message: 'Validation failed', details: validation.errors } });
  }

  if (getUserByEmail(validation.email)) {
    return res.status(409).json({ success: false, error: { message: 'An account with that email already exists.' } });
  }

  const now = new Date().toISOString();
  const userId = randomUUID();
  const { salt, hash, iterations } = createHash(validation.password);

  db.prepare(
    'INSERT INTO users (id, email, password_hash, password_salt, password_iterations, full_name, role, team, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
  ).run(
    userId,
    validation.email,
    hash,
    salt,
    iterations,
    validation.fullName,
    'user',
    validation.team,
    'active',
    now,
    now,
  );

  const user = getUserById(userId);
  const session = createSessionRecord(userId);
  res.cookie(SESSION_COOKIE, session.token, cookieOptions());

  res.status(201).json({
    success: true,
    data: {
      user: sanitizeUser(user),
      session: { expiresAt: session.expiresAt },
    },
  });
});

app.post('/api/auth/login', (req, res) => {
  const payload = req.body || {};
  const email = normalizeText(payload.email || '').toLowerCase();
  const password = typeof payload.password === 'string' ? payload.password : '';

  if (!email || !password) {
    return res.status(400).json({ success: false, error: { message: 'Email and password are required.' } });
  }

  const user = getUserByEmail(email);
  if (!user) {
    return res.status(401).json({ success: false, error: { message: 'Invalid email or password.' } });
  }

  if (password.length > 128) {
    return res.status(400).json({ success: false, error: { message: 'Password must not exceed 128 characters.' } });
  }
  if (user.status !== 'active') {
    return res.status(401).json({ success: false, error: { message: 'Invalid email or password.' } });
  }

  const valid = verifyPassword(password, user.password_salt, user.password_hash, user.password_iterations);
  if (!valid) {
    return res.status(401).json({ success: false, error: { message: 'Invalid email or password.' } });
  }

  const previousToken = getSessionToken(req);
  if (previousToken) db.prepare('DELETE FROM sessions WHERE token = ?').run(previousToken);
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(user.id);
  const session = createSessionRecord(user.id);
  res.cookie(SESSION_COOKIE, session.token, cookieOptions());

  res.json({
    success: true,
    data: {
      user: sanitizeUser(user),
      session: { expiresAt: session.expiresAt },
    },
  });
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  const token = req.sessionToken;
  db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  clearSessionCookie(res);
  res.json({ success: true, data: { message: 'Logged out successfully.' } });
});

app.get('/api/auth/session', requireAuth, (req, res) => {
  res.json({ success: true, data: { user: req.user } });
});

app.get('/api/users', requireAuth, requirePermission('users:manage'), (_req, res) => {
  const rows = db.prepare('SELECT * FROM users ORDER BY created_at DESC').all();
  res.json({ success: true, data: rows.map(sanitizeUser) });
});

app.post('/api/users', requireAuth, requirePermission('users:manage'), (req, res) => {
  const payload = req.body || {};
  const validation = validateUserInput(payload, 'admin');
  if (validation.errors.length > 0) {
    return res.status(400).json({ success: false, error: { message: 'Validation failed', details: validation.errors } });
  }

  if (getUserByEmail(validation.email)) {
    return res.status(409).json({ success: false, error: { message: 'A user with that email already exists.' } });
  }

  const role = normalizeText(payload.role || 'user');
  if (!VALID_ROLES.includes(role)) {
    return res.status(400).json({ success: false, error: { message: 'Role is invalid.' } });
  }

  const now = new Date().toISOString();
  const userId = randomUUID();
  const { salt, hash, iterations } = createHash(validation.password);

  db.prepare(
    'INSERT INTO users (id, email, password_hash, password_salt, password_iterations, full_name, role, team, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
  ).run(
    userId,
    validation.email,
    hash,
    salt,
    iterations,
    validation.fullName,
    role,
    validation.team,
    'active',
    now,
    now,
  );

  const created = getUserById(userId);
  res.status(201).json({ success: true, data: sanitizeUser(created) });
});

app.get('/api/users/:id', requireAuth, requirePermission('profile:read'), (req, res) => {
  const targetId = req.params.id;
  const profileUser = getUserById(targetId);
  if (!profileUser) {
    return res.status(404).json({ success: false, error: { message: 'User not found.' } });
  }

  if (req.user.role !== 'admin' && req.user.id !== targetId) {
    return res.status(403).json({ success: false, error: { message: 'You can only view your own profile.' } });
  }

  res.json({ success: true, data: sanitizeUser(profileUser) });
});

app.patch('/api/users/:id', requireAuth, requirePermission('profile:update'), (req, res) => {
  const targetId = req.params.id;
  const targetUser = getUserById(targetId);
  if (!targetUser) {
    return res.status(404).json({ success: false, error: { message: 'User not found.' } });
  }

  const isAdmin = req.user.role === 'admin';
  const isSelf = req.user.id === targetId;

  if (!isAdmin && !isSelf) {
    return res.status(403).json({ success: false, error: { message: 'You cannot modify another user profile.' } });
  }

  const payload = req.body || {};
  const roleUpdate = payload.role !== undefined ? normalizeText(payload.role) : null;

  if (roleUpdate && !isAdmin) {
    return res.status(403).json({ success: false, error: { message: 'You cannot change your role.' } });
  }

  const allowedFields = isAdmin
    ? ['fullName', 'full_name', 'email', 'team', 'status', 'role']
    : ['fullName', 'full_name', 'email'];

  const updates = {};
  for (const field of allowedFields) {
    if (payload[field] !== undefined) {
      updates[field] = payload[field];
    }
  }

  if (!isAdmin && (payload.role !== undefined || payload.status !== undefined || payload.team !== undefined)) {
    return res.status(403).json({ success: false, error: { message: 'Only administrators can change role, status, or team.' } });
  }

  if (isSelf && (payload.role !== undefined || payload.status !== undefined)) {
    return res.status(400).json({ success: false, error: { message: 'You cannot change your own role or account status.' } });
  }

  if (!Object.keys(updates).length) {
    return res.status(400).json({ success: false, error: { message: 'No supported profile changes were provided.' } });
  }

  const nextFullName = normalizeText(updates.fullName ?? updates.full_name ?? targetUser.full_name);
  const nextEmail = normalizeText((updates.email ?? targetUser.email)).toLowerCase();
  const nextTeam = normalizeText(updates.team ?? targetUser.team);
  const nextStatus = normalizeText(updates.status ?? targetUser.status);
  const nextRole = isAdmin && updates.role !== undefined ? normalizeText(updates.role) : targetUser.role;
  if (nextTeam.length < 2) {
    return res.status(400).json({ success: false, error: { message: 'Team must be at least 2 characters.' } });
  }
  if (!['active', 'suspended'].includes(nextStatus)) {
    return res.status(400).json({ success: false, error: { message: 'Status must be active or suspended.' } });
  }

  if (nextFullName.length < 2) {
    return res.status(400).json({ success: false, error: { message: 'Full name must be at least 2 characters.' } });
  }
  if (nextFullName.length > 100 || nextEmail.length > 254 || nextTeam.length > 80) {
    return res.status(400).json({ success: false, error: { message: 'Name, email, or team exceeds its maximum length.' } });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(nextEmail)) {
    return res.status(400).json({ success: false, error: { message: 'A valid email address is required.' } });
  }
  if (!VALID_ROLES.includes(nextRole)) {
    return res.status(400).json({ success: false, error: { message: 'Role is invalid.' } });
  }
  if (targetUser.role === 'admin' && (nextRole !== 'admin' || nextStatus !== 'active')) {
    const activeAdmins = db.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND status = 'active'").get().count;
    if (activeAdmins <= 1) {
      return res.status(409).json({ success: false, error: { message: 'The last active administrator cannot be demoted or suspended.' } });
    }
  }

  const existingEmailUser = db.prepare('SELECT * FROM users WHERE email = ? AND id != ?').get(nextEmail, targetId);
  if (existingEmailUser) {
    return res.status(409).json({ success: false, error: { message: 'Another user already uses that email address.' } });
  }

  db.prepare(
    'UPDATE users SET email = ?, full_name = ?, role = ?, team = ?, status = ?, updated_at = ? WHERE id = ?',
  ).run(nextEmail, nextFullName, nextRole, nextTeam, nextStatus, new Date().toISOString(), targetId);
  if (nextStatus !== 'active') {
    db.prepare('DELETE FROM sessions WHERE user_id = ?').run(targetId);
  }

  const updatedUser = getUserById(targetId);
  res.json({ success: true, data: sanitizeUser(updatedUser) });
});

app.get('/api/team/summary', requireAuth, requirePermission('teams:read'), (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const teamName = isAdmin ? null : req.user.team;

  const teamFilterClause = teamName ? 'WHERE team = ?' : '';
  const teamParameters = teamName ? [teamName] : [];

  const members = db.prepare(`SELECT * FROM users ${teamFilterClause} ORDER BY full_name ASC`).all(...teamParameters);
  const accessRequests = db.prepare(
    `SELECT status, COUNT(*) AS total FROM access_requests ${teamName ? 'WHERE team = ?' : ''} GROUP BY status`,
  ).all(...(teamName ? [teamName] : []));

  const summary = {
    team: teamName || 'All teams',
    totalMembers: members.length,
    managers: members.filter((user) => user.role === 'manager').length,
    admins: members.filter((user) => user.role === 'admin').length,
    users: members.filter((user) => user.role === 'user').length,
    pendingRequests: 0,
    approvedRequests: 0,
    rejectedRequests: 0,
    revokedRequests: 0,
  };

  for (const row of accessRequests) {
    const key = row.status === 'pending' ? 'pendingRequests' : row.status === 'approved' ? 'approvedRequests' : row.status === 'rejected' ? 'rejectedRequests' : 'revokedRequests';
    summary[key] = Number(row.total);
  }

  res.json({ success: true, data: summary });
});

app.get('/api/requests', requireAuth, requirePermission('requests:read'), (req, res) => {
  const { status, team } = req.query;
  let query = 'SELECT * FROM access_requests';
  const params = [];
  if (req.user.role === 'user') {
    query += ' WHERE created_by = ?';
    params.push(req.user.id);
  } else if (req.user.role === 'manager') {
    query += ' WHERE team = ?';
    params.push(req.user.team);
  }

  if ((status || team) && !query.includes(' WHERE ')) {
    const clauses = [];
    if (status) {
      clauses.push('status = ?');
      params.push(status);
    }
    if (team) {
      clauses.push('team = ?');
      params.push(team);
    }
    query += ` WHERE ${clauses.join(' AND ')}`;
  } else if (status || team) {
    const clauses = [];
    if (status) {
      clauses.push('status = ?');
      params.push(status);
    }
    if (team) {
      if (req.user.role === 'manager' && team !== req.user.team) {
        return res.status(403).json({ success: false, error: { message: 'Managers can only access their own team.' } });
      }
      if (req.user.role === 'user' && team !== req.user.team) {
        return res.status(403).json({ success: false, error: { message: 'You can only access your own requests.' } });
      }
      if (req.user.role === 'admin') {
        clauses.push('team = ?');
        params.push(team);
      }
    }
    if (clauses.length) query += ` AND ${clauses.join(' AND ')}`;
  }

  query += ' ORDER BY requestedAt DESC';

  const rows = db.prepare(query).all(...params);
  res.json({ success: true, data: rows.map(serializeRequest) });
});

app.get('/api/stats', requireAuth, requirePermission('requests:read'), (req, res) => {
  const scope = req.user.role === 'user' ? 'created_by = ?' : req.user.role === 'manager' ? 'team = ?' : '';
  const scopeValue = req.user.role === 'user' ? req.user.id : req.user.team;
  const counts = db.prepare(
    `SELECT status, COUNT(*) AS total FROM access_requests ${scope ? `WHERE ${scope}` : ''} GROUP BY status`,
  ).all(...(scope ? [scopeValue] : []));
  const stats = { total: 0, pending: 0, approved: 0, rejected: 0, revoked: 0 };

  for (const row of counts) {
    stats.total += Number(row.total);
    stats[row.status] = Number(row.total);
  }

  res.json({ success: true, data: stats });
});

app.post('/api/requests', requireAuth, requirePermission('requests:create'), (req, res) => {
  const payload = req.body || {};
  const result = validateRequestPayload({ ...payload, status: 'pending' });

  if (result.errors.length > 0) {
    return res.status(400).json({ success: false, error: { message: 'Validation failed', details: result.errors } });
  }

  const now = new Date().toISOString();
  const accessRequest = {
    id: randomUUID(),
    created_by: req.user.id,
    employee: result.employee,
    team: req.user.role === 'admin' ? result.team : req.user.team,
    role: result.role,
    accessType: result.accessType,
    justification: result.justification,
    priority: result.priority,
    status: result.status,
    reviewer: req.user.fullName,
    requestedAt: now,
    reviewedAt: result.status === 'pending' ? null : now,
    createdAt: now,
    updatedAt: now,
  };

  db.prepare(`
    INSERT INTO access_requests (
      id, employee, team, role, accessType, justification, priority, status,
      reviewer, requestedAt, reviewedAt, createdAt, updatedAt, created_by
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    accessRequest.id,
    accessRequest.employee,
    accessRequest.team,
    accessRequest.role,
    accessRequest.accessType,
    accessRequest.justification,
    accessRequest.priority,
    accessRequest.status,
    accessRequest.reviewer,
    accessRequest.requestedAt,
    accessRequest.reviewedAt,
    accessRequest.createdAt,
    accessRequest.updatedAt,
    accessRequest.created_by,
  );

  res.status(201).json({ success: true, data: serializeRequest(accessRequest) });
});

app.patch('/api/requests/:id', requireAuth, requirePermission('requests:review'), (req, res) => {
  const { id } = req.params;
  const existingRecord = db.prepare('SELECT * FROM access_requests WHERE id = ?').get(id);

  if (!existingRecord) {
    return res.status(404).json({ success: false, error: { message: 'Access request not found.' } });
  }
  if (req.user.role === 'manager' && existingRecord.team !== req.user.team) {
    return res.status(403).json({ success: false, error: { message: 'Managers can only review requests for their own team.' } });
  }

  const payload = req.body || {};
  const updates = {
    employee: req.user.role === 'admin' && payload.employee !== undefined ? normalizeText(payload.employee) : existingRecord.employee,
    team: req.user.role === 'admin' && payload.team !== undefined ? normalizeText(payload.team) : existingRecord.team,
    role: req.user.role === 'admin' && payload.role !== undefined ? normalizeText(payload.role) : existingRecord.role,
    accessType: req.user.role === 'admin' && payload.accessType !== undefined ? normalizeText(payload.accessType) : existingRecord.accessType,
    justification: req.user.role === 'admin' && payload.justification !== undefined ? normalizeText(payload.justification) : existingRecord.justification,
    priority: req.user.role === 'admin' && payload.priority !== undefined ? normalizeText(payload.priority) : existingRecord.priority,
    status: payload.status !== undefined ? normalizeText(payload.status) : existingRecord.status,
    reviewer: req.user.role === 'admin' && payload.reviewer !== undefined ? normalizeText(payload.reviewer) : existingRecord.reviewer,
  };

  const validation = validateRequestPayload({
    employee: updates.employee,
    team: updates.team,
    role: updates.role,
    accessType: updates.accessType,
    justification: updates.justification,
    priority: updates.priority,
    status: updates.status,
  });

  if (validation.errors.length > 0) {
    return res.status(400).json({ success: false, error: { message: 'Validation failed', details: validation.errors } });
  }

  const now = new Date().toISOString();
  const nextReviewer = req.user.fullName;

  db.prepare(`
    UPDATE access_requests
    SET employee = ?, team = ?, role = ?, accessType = ?, justification = ?, priority = ?, status = ?, reviewer = ?, reviewedAt = ?, updatedAt = ?
    WHERE id = ?
  `).run(
    updates.employee,
    updates.team,
    updates.role,
    updates.accessType,
    updates.justification,
    updates.priority,
    updates.status,
    nextReviewer,
    updates.status === 'pending' ? null : now,
    now,
    id,
  );

  const updated = db.prepare('SELECT * FROM access_requests WHERE id = ?').get(id);
  res.json({ success: true, data: serializeRequest(updated) });
});

app.delete('/api/requests/:id', requireAuth, requirePermission('requests:delete'), (req, res) => {
  const { id } = req.params;
  const existing = db.prepare('SELECT * FROM access_requests WHERE id = ?').get(id);

  if (!existing) {
    return res.status(404).json({ success: false, error: { message: 'Access request not found.' } });
  }
  if (req.user.role === 'manager' && existing.team !== req.user.team) {
    return res.status(403).json({ success: false, error: { message: 'Managers can only delete requests for their own team.' } });
  }

  db.prepare('DELETE FROM access_requests WHERE id = ?').run(id);
  res.json({ success: true, data: { id } });
});

if (fs.existsSync(distPath)) {
  app.use(express.static(distPath));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) return next();
    res.sendFile(path.join(distPath, 'index.html'));
  });
}

app.use((err, _req, res, _next) => {
  console.error(err);
  const status = [400, 413].includes(err.status) ? err.status : 500;
  const message = status === 400 ? 'Invalid request body.' : status === 413 ? 'Request body is too large.' : 'Internal server error.';
  res.status(status).json({ success: false, error: { message } });
});

ensureTables();
seedUsers();

if (process.env.NODE_ENV !== 'test') {
  app.listen(port, '0.0.0.0', () => {
    console.log(`AccessHub API listening on http://localhost:${port}`);
  });
}

export default app;
