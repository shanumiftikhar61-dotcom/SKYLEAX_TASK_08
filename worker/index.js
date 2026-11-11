const SESSION_COOKIE = 'accesshub_session';
const SESSION_SECONDS = 60 * 60 * 12;
const PASSWORD_ITERATIONS = 600000;
const VALID_ROLES = ['admin', 'manager', 'user'];
const VALID_STATUSES = ['pending', 'approved', 'rejected', 'revoked'];
const VALID_REQUEST_TYPES = new Set(['software', 'facility', 'data', 'system', 'other']);
const ROLE_PERMISSIONS = {
  admin: ['requests:read', 'requests:create', 'requests:review', 'requests:delete', 'users:manage', 'teams:read', 'profile:read', 'profile:update'],
  manager: ['requests:read', 'requests:create', 'requests:review', 'requests:delete', 'teams:read', 'profile:read', 'profile:update'],
  user: ['requests:read', 'requests:create', 'profile:read', 'profile:update'],
};

let schemaReady = false;
let schemaSetup;

const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), {
  status,
  headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers },
});
const failure = (message, status, details) => json({
  success: false,
  error: { message, ...(details ? { details } : {}) },
}, status);
const normalizeText = (value) => typeof value === 'string' ? value.trim() : '';
const nowIso = () => new Date().toISOString();
const uuid = () => crypto.randomUUID();
const rows = async (statement) => (await statement.all()).results || [];

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(value) {
  if (typeof value !== 'string' || value.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(value)) {
    return new Uint8Array();
  }
  return Uint8Array.from(value.match(/.{2}/g), (byte) => Number.parseInt(byte, 16));
}

function bytesToBase64Url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function randomToken() {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

async function digestHex(value) {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))));
}

async function createPasswordHash(password, salt = crypto.getRandomValues(new Uint8Array(16))) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({
    name: 'PBKDF2',
    hash: 'SHA-256',
    salt,
    iterations: PASSWORD_ITERATIONS,
  }, key, 512);
  return { salt: bytesToHex(salt), hash: bytesToHex(new Uint8Array(bits)), iterations: PASSWORD_ITERATIONS };
}

async function verifyPassword(password, saltValue, expectedHash, iterations) {
  const salt = hexToBytes(saltValue);
  const expected = hexToBytes(expectedHash);
  if (!salt.length || expected.length !== 64 || !Number.isInteger(iterations) || iterations < 1 || iterations > 2000000) {
    return false;
  }
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({
    name: 'PBKDF2',
    hash: 'SHA-256',
    salt,
    iterations,
  }, key, expected.length * 8));
  let difference = 0;
  for (let index = 0; index < expected.length; index += 1) difference |= bits[index] ^ expected[index];
  return difference === 0;
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

async function ensureSchema(db) {
  if (schemaReady) return;
  if (!schemaSetup) {
    schemaSetup = (async () => {
      await db.prepare(`CREATE TABLE IF NOT EXISTS users (
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
      )`).run();
      await db.prepare(`CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`).run();
      await db.prepare(`CREATE TABLE IF NOT EXISTS access_requests (
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
      )`).run();
      await db.prepare(`CREATE TABLE IF NOT EXISTS admin_bootstrap (
        id INTEGER PRIMARY KEY CHECK(id = 1),
        completed_at TEXT NOT NULL
      )`).run();

      const userColumns = await rows(db.prepare('PRAGMA table_info(users)'));
      if (!userColumns.some((column) => column.name === 'password_iterations')) {
        await db.prepare('ALTER TABLE users ADD COLUMN password_iterations INTEGER NOT NULL DEFAULT 100000').run();
      }
      const requestColumns = await rows(db.prepare('PRAGMA table_info(access_requests)'));
      if (!requestColumns.some((column) => column.name === 'created_by')) {
        await db.prepare('ALTER TABLE access_requests ADD COLUMN created_by TEXT').run();
      }
      await db.prepare('CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)').run();
      await db.prepare('CREATE INDEX IF NOT EXISTS idx_requests_created_by ON access_requests(created_by)').run();
      await db.prepare('CREATE INDEX IF NOT EXISTS idx_requests_team_status ON access_requests(team, status)').run();
    })();
  }

  try {
    await schemaSetup;
    schemaReady = true;
  } finally {
    schemaSetup = undefined;
  }
}

function validateUserInput(payload, mode = 'register') {
  const errors = [];
  const email = normalizeText(payload.email).toLowerCase();
  const password = typeof payload.password === 'string' ? payload.password : '';
  const fullName = normalizeText(payload.fullName || payload.full_name || payload.name);
  const team = normalizeText(payload.team || 'General');

  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.push('A valid email address is required.');
  if (password.length > 128) errors.push('Password must not exceed 128 characters.');
  if (password.length < 10 || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/[0-9]/.test(password)) {
    errors.push('Password must be at least 10 characters and include uppercase, lowercase, and numeric characters.');
  }
  if (fullName.length < 2) errors.push('Full name is required.');
  else if (fullName.length > 100) errors.push('Full name must not exceed 100 characters.');
  if (team.length > 80) errors.push('Team must not exceed 80 characters.');
  if (mode === 'register' && payload.role && normalizeText(payload.role) !== 'user') {
    errors.push('Only public registration for the User role is allowed.');
  }
  return { errors, email, password, fullName, team };
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
  if (!VALID_STATUSES.includes(status)) errors.push('Status must be pending, approved, rejected, or revoked.');
  return { errors, employee, team, role, accessType, justification, priority, status };
}

function cookieValue(request) {
  for (const part of (request.headers.get('Cookie') || '').split(';')) {
    const [name, ...value] = part.trim().split('=');
    if (name === SESSION_COOKIE) return value.join('=') || '';
  }
  return '';
}

function sessionCookie(token) {
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_SECONDS}`;
}

function clearCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

async function createSession(db, userId) {
  const token = randomToken();
  const expiresAt = new Date(Date.now() + SESSION_SECONDS * 1000).toISOString();
  await db.prepare('INSERT INTO sessions (id, user_id, token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)')
    .bind(uuid(), userId, await digestHex(token), expiresAt, nowIso()).run();
  return { token, expiresAt };
}

async function getUserById(db, id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
}

async function getUserByEmail(db, email) {
  return db.prepare('SELECT * FROM users WHERE email = ?').bind(email.toLowerCase()).first();
}

function hasPermission(user, permission) {
  return Boolean(user && ROLE_PERMISSIONS[user.role]?.includes(permission));
}

async function authenticatedUser(request, db) {
  const token = cookieValue(request);
  if (!token) return { error: failure('Authentication required.', 401) };
  const tokenHash = await digestHex(token);
  const session = await db.prepare('SELECT * FROM sessions WHERE token = ?').bind(tokenHash).first();
  if (!session) return { error: failure('Session expired or invalid.', 401, undefined) , clear: true };
  if (new Date(session.expires_at).getTime() <= Date.now()) {
    await db.prepare('DELETE FROM sessions WHERE token = ?').bind(tokenHash).run();
    return { error: failure('Session expired.', 401), clear: true };
  }
  const user = await getUserById(db, session.user_id);
  if (!user || user.status !== 'active') {
    await db.prepare('DELETE FROM sessions WHERE token = ?').bind(tokenHash).run();
    return { error: failure(user ? 'This account is inactive.' : 'User session not found.', 401), clear: true };
  }
  return { user: sanitizeUser(user), tokenHash };
}

async function bodyJson(request) {
  const raw = await request.text();
  if (new TextEncoder().encode(raw).length > 1024 * 1024) return { error: failure('Request body is too large.', 413) };
  if (!raw) return { value: {} };
  try {
    const value = JSON.parse(raw);
    if (!value || typeof value !== 'object' || Array.isArray(value)) return { error: failure('Invalid request body.', 400) };
    return { value };
  } catch {
    return { error: failure('Invalid request body.', 400) };
  }
}

async function apiFetch(request, env) {
  const { DB: db } = env;
  const url = new URL(request.url);
  const method = request.method.toUpperCase();
  const pathname = url.pathname;
  await ensureSchema(db);

  if (method === 'GET' && pathname === '/api/health') {
    return json({ success: true, data: { ok: true } });
  }

  if (method === 'POST' && pathname === '/api/auth/bootstrap-admin') {
    return bootstrapAdmin(request, db, env);
  }

  if (method === 'POST' && ['/api/auth/register', '/api/auth/login'].includes(pathname)) {
    const parsed = await bodyJson(request);
    if (parsed.error) return parsed.error;
    if (pathname === '/api/auth/register') return registerUser(parsed.value, db);
    return loginUser(parsed.value, request, db);
  }

  const auth = await authenticatedUser(request, db);
  if (auth.error) {
    return auth.clear
      ? new Response(auth.error.body, { status: 401, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Set-Cookie': clearCookie() } })
      : auth.error;
  }
  const { user } = auth;

  if (method === 'POST' && pathname === '/api/auth/logout') {
    await db.prepare('DELETE FROM sessions WHERE token = ?').bind(auth.tokenHash).run();
    return json({ success: true, data: { message: 'Logged out successfully.' } }, 200, { 'Set-Cookie': clearCookie() });
  }
  if (method === 'GET' && pathname === '/api/auth/session') {
    return json({ success: true, data: { user } });
  }
  if (method === 'GET' && pathname === '/api/users') {
    if (!hasPermission(user, 'users:manage')) return failure('Forbidden: insufficient permissions.', 403);
    const users = await rows(db.prepare('SELECT * FROM users ORDER BY created_at DESC'));
    return json({ success: true, data: users.map(sanitizeUser) });
  }
  if (method === 'POST' && pathname === '/api/users') {
    if (!hasPermission(user, 'users:manage')) return failure('Forbidden: insufficient permissions.', 403);
    const parsed = await bodyJson(request);
    if (parsed.error) return parsed.error;
    return provisionUser(parsed.value, db);
  }
  if (method === 'GET' && pathname === '/api/team/summary') {
    if (!hasPermission(user, 'teams:read')) return failure('Forbidden: insufficient permissions.', 403);
    return teamSummary(user, db);
  }
  if (method === 'GET' && pathname === '/api/requests') {
    if (!hasPermission(user, 'requests:read')) return failure('Forbidden: insufficient permissions.', 403);
    return listRequests(url, user, db);
  }
  if (method === 'GET' && pathname === '/api/stats') {
    if (!hasPermission(user, 'requests:read')) return failure('Forbidden: insufficient permissions.', 403);
    return requestStats(user, db);
  }
  if (method === 'POST' && pathname === '/api/requests') {
    if (!hasPermission(user, 'requests:create')) return failure('Forbidden: insufficient permissions.', 403);
    const parsed = await bodyJson(request);
    if (parsed.error) return parsed.error;
    return createRequest(parsed.value, user, db);
  }

  const userMatch = pathname.match(/^\/api\/users\/([^/]+)$/);
  if (userMatch && ['GET', 'PATCH'].includes(method)) {
    if (!hasPermission(user, method === 'GET' ? 'profile:read' : 'profile:update')) {
      return failure('Forbidden: insufficient permissions.', 403);
    }
    let targetId;
    try {
      targetId = decodeURIComponent(userMatch[1]);
    } catch {
      return failure('User not found.', 404);
    }
    if (method === 'GET') return getProfile(targetId, user, db);
    const parsed = await bodyJson(request);
    if (parsed.error) return parsed.error;
    return updateProfile(targetId, parsed.value, user, db);
  }

  const requestMatch = pathname.match(/^\/api\/requests\/([^/]+)$/);
  if (requestMatch && ['PATCH', 'DELETE'].includes(method)) {
    const permission = method === 'PATCH' ? 'requests:review' : 'requests:delete';
    if (!hasPermission(user, permission)) return failure('Forbidden: insufficient permissions.', 403);
    let requestId;
    try {
      requestId = decodeURIComponent(requestMatch[1]);
    } catch {
      return failure('Access request not found.', 404);
    }
    if (method === 'DELETE') return deleteRequest(requestId, user, db);
    const parsed = await bodyJson(request);
    if (parsed.error) return parsed.error;
    return updateRequest(requestId, parsed.value, user, db);
  }

  return failure('API route not found.', 404);
}

async function registerUser(payload, db) {
  if (payload.role && normalizeText(payload.role) !== 'user') {
    return failure('Only public registration for the User role is allowed.', 400);
  }
  const validation = validateUserInput(payload);
  if (validation.errors.length) return failure('Validation failed', 400, validation.errors);
  if (await getUserByEmail(db, validation.email)) return failure('An account with that email already exists.', 409);

  const now = nowIso();
  const userId = uuid();
  const password = await createPasswordHash(validation.password);
  await db.prepare(`INSERT INTO users
    (id, email, password_hash, password_salt, password_iterations, full_name, role, team, status, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, 'user', ?, 'active', ?, ?)`)
    .bind(userId, validation.email, password.hash, password.salt, password.iterations, validation.fullName, validation.team, now, now).run();
  const session = await createSession(db, userId);
  const user = await getUserById(db, userId);
  return json({ success: true, data: { user: sanitizeUser(user), session: { expiresAt: session.expiresAt } } }, 201, {
    'Set-Cookie': sessionCookie(session.token),
  });
}

async function loginUser(payload, request, db) {
  const email = normalizeText(payload.email).toLowerCase();
  const password = typeof payload.password === 'string' ? payload.password : '';
  if (!email || !password) return failure('Email and password are required.', 400);
  if (password.length > 128) return failure('Password must not exceed 128 characters.', 400);
  const user = await getUserByEmail(db, email);
  if (!user || user.status !== 'active' || !await verifyPassword(password, user.password_salt, user.password_hash, user.password_iterations)) {
    return failure('Invalid email or password.', 401);
  }

  const previousToken = cookieValue(request);
  const statements = [];
  if (previousToken) statements.push(db.prepare('DELETE FROM sessions WHERE token = ?').bind(await digestHex(previousToken)));
  statements.push(db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id));
  await db.batch(statements);
  const session = await createSession(db, user.id);
  return json({ success: true, data: { user: sanitizeUser(user), session: { expiresAt: session.expiresAt } } }, 200, {
    'Set-Cookie': sessionCookie(session.token),
  });
}

async function bootstrapAdmin(request, db, env) {
  const secret = request.headers.get('X-Bootstrap-Secret') || '';
  if (!env.BOOTSTRAP_SECRET || !secret || !await constantTimeEqual(secret, env.BOOTSTRAP_SECRET)) {
    return failure('Bootstrap authorization failed.', 403);
  }
  const parsed = await bodyJson(request);
  if (parsed.error) return parsed.error;
  const validation = validateUserInput({ ...parsed.value, team: parsed.value.team || 'Operations' }, 'bootstrap');
  if (validation.errors.length) return failure('Validation failed', 400, validation.errors);
  if (await getUserByEmail(db, validation.email)) return failure('An account with that email already exists.', 409);

  const now = nowIso();
  const claim = uuid();
  const userId = uuid();
  const sessionId = uuid();
  const token = randomToken();
  const tokenHash = await digestHex(token);
  const expiresAt = new Date(Date.now() + SESSION_SECONDS * 1000).toISOString();
  const password = await createPasswordHash(validation.password);
  const results = await db.batch([
    db.prepare(`INSERT INTO admin_bootstrap (id, completed_at)
      SELECT 1, ? WHERE NOT EXISTS (SELECT 1 FROM users WHERE role = 'admin')
      ON CONFLICT(id) DO NOTHING`).bind(claim),
    db.prepare(`INSERT INTO users
      (id, email, password_hash, password_salt, password_iterations, full_name, role, team, status, created_at, updated_at)
      SELECT ?, ?, ?, ?, ?, ?, 'admin', ?, 'active', ?, ?
      WHERE EXISTS (SELECT 1 FROM admin_bootstrap WHERE id = 1 AND completed_at = ?)
      AND NOT EXISTS (SELECT 1 FROM users WHERE role = 'admin')`)
      .bind(userId, validation.email, password.hash, password.salt, password.iterations, validation.fullName, validation.team, now, now, claim),
    db.prepare(`INSERT INTO sessions (id, user_id, token, expires_at, created_at)
      SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM users WHERE id = ?)`)
      .bind(sessionId, userId, tokenHash, expiresAt, now, userId),
    db.prepare('UPDATE admin_bootstrap SET completed_at = ? WHERE id = 1 AND completed_at = ?').bind(now, claim),
  ]);
  if (!results[1]?.meta?.changes) return failure('Administrator bootstrap has already been completed or an administrator exists.', 409);
  const user = await getUserById(db, userId);
  return json({ success: true, data: { user: sanitizeUser(user), session: { expiresAt } } }, 201, {
    'Set-Cookie': sessionCookie(token),
  });
}

async function constantTimeEqual(left, right) {
  const [leftHash, rightHash] = await Promise.all([digestHex(left), digestHex(right)]);
  const leftBytes = hexToBytes(leftHash);
  const rightBytes = hexToBytes(rightHash);
  let difference = 0;
  for (let index = 0; index < leftBytes.length; index += 1) difference |= leftBytes[index] ^ rightBytes[index];
  return difference === 0;
}

async function provisionUser(payload, db) {
  const validation = validateUserInput(payload, 'admin');
  if (validation.errors.length) return failure('Validation failed', 400, validation.errors);
  if (await getUserByEmail(db, validation.email)) return failure('A user with that email already exists.', 409);
  const role = normalizeText(payload.role || 'user');
  if (!VALID_ROLES.includes(role)) return failure('Role is invalid.', 400);
  const now = nowIso();
  const userId = uuid();
  const password = await createPasswordHash(validation.password);
  await db.prepare(`INSERT INTO users
    (id, email, password_hash, password_salt, password_iterations, full_name, role, team, status, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`)
    .bind(userId, validation.email, password.hash, password.salt, password.iterations, validation.fullName, role, validation.team, now, now).run();
  return json({ success: true, data: sanitizeUser(await getUserById(db, userId)) }, 201);
}

async function getProfile(targetId, user, db) {
  const profile = await getUserById(db, targetId);
  if (!profile) return failure('User not found.', 404);
  if (user.role !== 'admin' && user.id !== targetId) return failure('You can only view your own profile.', 403);
  return json({ success: true, data: sanitizeUser(profile) });
}

async function updateProfile(targetId, payload, user, db) {
  const target = await getUserById(db, targetId);
  if (!target) return failure('User not found.', 404);
  const isAdmin = user.role === 'admin';
  const isSelf = user.id === targetId;
  if (!isAdmin && !isSelf) return failure('You cannot modify another user profile.', 403);
  if (payload.role !== undefined && !isAdmin) return failure('You cannot change your role.', 403);
  if (!isAdmin && (payload.role !== undefined || payload.status !== undefined || payload.team !== undefined)) {
    return failure('Only administrators can change role, status, or team.', 403);
  }
  if (isSelf && (payload.role !== undefined || payload.status !== undefined)) {
    return failure('You cannot change your own role or account status.', 400);
  }
  const supported = isAdmin
    ? ['fullName', 'full_name', 'email', 'team', 'status', 'role']
    : ['fullName', 'full_name', 'email'];
  if (!supported.some((field) => payload[field] !== undefined)) return failure('No supported profile changes were provided.', 400);

  const nextFullName = normalizeText(payload.fullName ?? payload.full_name ?? target.full_name);
  const nextEmail = normalizeText(payload.email ?? target.email).toLowerCase();
  const nextTeam = normalizeText(payload.team ?? target.team);
  const nextStatus = normalizeText(payload.status ?? target.status);
  const nextRole = isAdmin && payload.role !== undefined ? normalizeText(payload.role) : target.role;
  if (nextTeam.length < 2) return failure('Team must be at least 2 characters.', 400);
  if (!['active', 'suspended'].includes(nextStatus)) return failure('Status must be active or suspended.', 400);
  if (nextFullName.length < 2) return failure('Full name must be at least 2 characters.', 400);
  if (nextFullName.length > 100 || nextEmail.length > 254 || nextTeam.length > 80) {
    return failure('Name, email, or team exceeds its maximum length.', 400);
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(nextEmail)) return failure('A valid email address is required.', 400);
  if (!VALID_ROLES.includes(nextRole)) return failure('Role is invalid.', 400);
  if (target.role === 'admin' && (nextRole !== 'admin' || nextStatus !== 'active')) {
    const count = await db.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND status = 'active'").first();
    if (count.count <= 1) return failure('The last active administrator cannot be demoted or suspended.', 409);
  }
  const existing = await db.prepare('SELECT id FROM users WHERE email = ? AND id != ?').bind(nextEmail, targetId).first();
  if (existing) return failure('Another user already uses that email address.', 409);

  await db.prepare(`UPDATE users SET email = ?, full_name = ?, role = ?, team = ?, status = ?, updated_at = ?
    WHERE id = ?`).bind(nextEmail, nextFullName, nextRole, nextTeam, nextStatus, nowIso(), targetId).run();
  if (nextStatus !== 'active') await db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(targetId).run();
  return json({ success: true, data: sanitizeUser(await getUserById(db, targetId)) });
}

async function teamSummary(user, db) {
  const team = user.role === 'admin' ? null : user.team;
  const where = team ? ' WHERE team = ?' : '';
  const params = team ? [team] : [];
  const members = await rows(db.prepare(`SELECT role FROM users${where}`).bind(...params));
  const counts = await rows(db.prepare(`SELECT status, COUNT(*) AS total FROM access_requests${where} GROUP BY status`).bind(...params));
  const summary = {
    team: team || 'All teams',
    totalMembers: members.length,
    managers: members.filter((member) => member.role === 'manager').length,
    admins: members.filter((member) => member.role === 'admin').length,
    users: members.filter((member) => member.role === 'user').length,
    pendingRequests: 0,
    approvedRequests: 0,
    rejectedRequests: 0,
    revokedRequests: 0,
  };
  for (const row of counts) {
    const key = `${row.status}Requests`;
    if (Object.hasOwn(summary, key)) summary[key] = Number(row.total);
  }
  return json({ success: true, data: summary });
}

async function listRequests(url, user, db) {
  const status = url.searchParams.get('status');
  const team = url.searchParams.get('team');
  if (team && user.role === 'manager' && team !== user.team) return failure('Managers can only access their own team.', 403);
  if (team && user.role === 'user' && team !== user.team) return failure('You can only access your own requests.', 403);
  const clauses = [];
  const params = [];
  if (user.role === 'user') {
    clauses.push('created_by = ?');
    params.push(user.id);
  } else if (user.role === 'manager') {
    clauses.push('team = ?');
    params.push(user.team);
  }
  if (status) {
    clauses.push('status = ?');
    params.push(status);
  }
  if (team && user.role === 'admin') {
    clauses.push('team = ?');
    params.push(team);
  }
  const query = `SELECT * FROM access_requests${clauses.length ? ` WHERE ${clauses.join(' AND ')}` : ''} ORDER BY requestedAt DESC`;
  return json({ success: true, data: (await rows(db.prepare(query).bind(...params))).map(serializeRequest) });
}

async function requestStats(user, db) {
  const scope = user.role === 'user' ? 'created_by = ?' : user.role === 'manager' ? 'team = ?' : '';
  const value = user.role === 'user' ? user.id : user.team;
  const counts = await rows(db.prepare(`SELECT status, COUNT(*) AS total FROM access_requests${scope ? ` WHERE ${scope}` : ''} GROUP BY status`).bind(...(scope ? [value] : [])));
  const stats = { total: 0, pending: 0, approved: 0, rejected: 0, revoked: 0 };
  for (const row of counts) {
    stats.total += Number(row.total);
    stats[row.status] = Number(row.total);
  }
  return json({ success: true, data: stats });
}

async function createRequest(payload, user, db) {
  const result = validateRequestPayload({ ...payload, status: 'pending' });
  if (result.errors.length) return failure('Validation failed', 400, result.errors);
  const now = nowIso();
  const item = {
    id: uuid(),
    created_by: user.id,
    employee: result.employee,
    team: user.role === 'admin' ? result.team : user.team,
    role: result.role,
    accessType: result.accessType,
    justification: result.justification,
    priority: result.priority,
    status: 'pending',
    reviewer: user.fullName,
    requestedAt: now,
    reviewedAt: null,
    createdAt: now,
    updatedAt: now,
  };
  await db.prepare(`INSERT INTO access_requests
    (id, employee, team, role, accessType, justification, priority, status, reviewer, requestedAt, reviewedAt, createdAt, updatedAt, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(item.id, item.employee, item.team, item.role, item.accessType, item.justification, item.priority, item.status,
      item.reviewer, item.requestedAt, item.reviewedAt, item.createdAt, item.updatedAt, item.created_by).run();
  return json({ success: true, data: serializeRequest(item) }, 201);
}

async function updateRequest(id, payload, user, db) {
  const existing = await db.prepare('SELECT * FROM access_requests WHERE id = ?').bind(id).first();
  if (!existing) return failure('Access request not found.', 404);
  if (user.role === 'manager' && existing.team !== user.team) {
    return failure('Managers can only review requests for their own team.', 403);
  }
  const isAdmin = user.role === 'admin';
  const updates = {
    employee: isAdmin && payload.employee !== undefined ? normalizeText(payload.employee) : existing.employee,
    team: isAdmin && payload.team !== undefined ? normalizeText(payload.team) : existing.team,
    role: isAdmin && payload.role !== undefined ? normalizeText(payload.role) : existing.role,
    accessType: isAdmin && payload.accessType !== undefined ? normalizeText(payload.accessType) : existing.accessType,
    justification: isAdmin && payload.justification !== undefined ? normalizeText(payload.justification) : existing.justification,
    priority: isAdmin && payload.priority !== undefined ? normalizeText(payload.priority) : existing.priority,
    status: payload.status !== undefined ? normalizeText(payload.status) : existing.status,
  };
  const validation = validateRequestPayload(updates);
  if (validation.errors.length) return failure('Validation failed', 400, validation.errors);
  const now = nowIso();
  await db.prepare(`UPDATE access_requests SET employee = ?, team = ?, role = ?, accessType = ?, justification = ?,
    priority = ?, status = ?, reviewer = ?, reviewedAt = ?, updatedAt = ? WHERE id = ?`)
    .bind(updates.employee, updates.team, updates.role, updates.accessType, updates.justification, updates.priority,
      updates.status, user.fullName, updates.status === 'pending' ? null : now, now, id).run();
  return json({ success: true, data: serializeRequest(await db.prepare('SELECT * FROM access_requests WHERE id = ?').bind(id).first()) });
}

async function deleteRequest(id, user, db) {
  const existing = await db.prepare('SELECT * FROM access_requests WHERE id = ?').bind(id).first();
  if (!existing) return failure('Access request not found.', 404);
  if (user.role === 'manager' && existing.team !== user.team) {
    return failure('Managers can only delete requests for their own team.', 403);
  }
  await db.prepare('DELETE FROM access_requests WHERE id = ?').bind(id).run();
  return json({ success: true, data: { id } });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname.startsWith('/api/')) return await apiFetch(request, env);
      if (env.ASSETS) return env.ASSETS.fetch(request);
      return new Response('Not found', { status: 404 });
    } catch (error) {
      console.error('AccessHub Worker request failed:', error);
      return failure('Internal server error.', 500);
    }
  },
};
