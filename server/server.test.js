import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import request from 'supertest';

process.env.NODE_ENV = 'test';
const seedPasswords = {
  admin: randomBytes(32).toString('base64url'),
  manager: randomBytes(32).toString('base64url'),
  user: randomBytes(32).toString('base64url'),
};
process.env.ACCESSHUB_ADMIN_PASSWORD = seedPasswords.admin;
process.env.ACCESSHUB_MANAGER_PASSWORD = seedPasswords.manager;
process.env.ACCESSHUB_USER_PASSWORD = seedPasswords.user;
const testDbPath = path.join(process.cwd(), 'server', 'data', 'accesshub.test.db');
fs.rmSync(testDbPath, { force: true });
process.env.ACCESSHUB_DB_PATH = testDbPath;
const app = (await import('./server.js')).default;

const makeEmail = (label = 'person') => `${label}-${Date.now()}-${Math.random().toString(16).slice(2)}@example.com`;
const makePassword = () => randomBytes(32).toString('base64url');
const validRegistration = (overrides = {}) => ({
  email: makeEmail(),
  password: makePassword(),
  fullName: 'Morgan Rivera',
  team: 'Support',
  ...overrides,
});
const login = async (agent, role) => agent.post('/api/auth/login').send({
  email: `${role}@accesshub.local`,
  password: seedPasswords[role],
});
const createRequest = (agent, overrides = {}) => agent.post('/api/requests').send({
  employee: 'Morgan Rivera',
  team: 'Support',
  role: 'Analyst',
  accessType: 'software',
  priority: 'medium',
  justification: 'Needs access for the project work assigned this quarter.',
  ...overrides,
});

test('registers a Member account, hashes its password, and never returns hash material', async () => {
  const input = validRegistration();
  const response = await request(app).post('/api/auth/register').send(input);
  assert.equal(response.status, 201);
  assert.equal(response.body.data.user.role, 'user');
  assert.equal(response.body.data.user.email, input.email);
  assert.ok(response.headers['set-cookie'][0].includes('HttpOnly'));
  assert.ok(response.headers['set-cookie'][0].toLowerCase().includes('samesite=lax'));
  assert.equal(JSON.stringify(response.body).includes(input.password), false);
  assert.equal('password_hash' in response.body.data.user, false);
  assert.equal('password_salt' in response.body.data.user, false);

  const database = new DatabaseSync(testDbPath);
  const stored = database.prepare('SELECT password_hash, password_salt, password_iterations FROM users WHERE email = ?').get(input.email);
  database.close();
  assert.notEqual(stored.password_hash, input.password);
  assert.notEqual(stored.password_salt, input.password);
  assert.equal(stored.password_iterations, 600000);
});

test('rejects invalid registration input and does not permit self-assigned privileged roles', async () => {
  const invalid = await request(app).post('/api/auth/register').send({
    email: 'not-an-email',
    password: 'weak',
    fullName: '',
  });
  assert.equal(invalid.status, 400);
  assert.match(invalid.body.error.details.join(' '), /valid email|password/i);

  const attemptedEscalation = await request(app).post('/api/auth/register').send(
    validRegistration({ role: 'admin' }),
  );
  assert.equal(attemptedEscalation.status, 400);
  assert.match(attemptedEscalation.body.error.message, /public registration/i);
});

test('rejects duplicate email addresses without exposing account details', async () => {
  const input = validRegistration();
  assert.equal((await request(app).post('/api/auth/register').send(input)).status, 201);
  const duplicate = await request(app).post('/api/auth/register').send({
    ...input,
    email: input.email.toUpperCase(),
  });
  assert.equal(duplicate.status, 409);
  assert.match(duplicate.body.error.message, /already exists/i);
});

test('logs in with the stored password hash and rejects an incorrect password', async () => {
  const agent = request.agent(app);
  const valid = await login(agent, 'user');
  assert.equal(valid.status, 200);
  assert.equal(valid.body.data.user.role, 'user');

  const invalid = await request(app).post('/api/auth/login').send({
    email: 'user@accesshub.local',
    password: 'IncorrectPassword123',
  });
  assert.equal(invalid.status, 401);
  assert.match(invalid.body.error.message, /invalid email or password/i);
});

test('logout invalidates the server-side session', async () => {
  const agent = request.agent(app);
  assert.equal((await login(agent, 'user')).status, 200);
  assert.equal((await agent.get('/api/auth/session')).status, 200);
  assert.equal((await agent.post('/api/auth/logout')).status, 200);
  assert.equal((await agent.get('/api/auth/session')).status, 401);
});

test('unauthenticated requests receive 401 and malformed sessions are rejected', async () => {
  assert.equal((await request(app).get('/api/requests')).status, 401);
  const malformed = await request(app)
    .get('/api/auth/session')
    .set('Cookie', 'accesshub_session=invalid-session-token');
  assert.equal(malformed.status, 401);
});

test('Members can create and retrieve only their own pending requests', async () => {
  const member = request.agent(app);
  await login(member, 'user');
  const created = await createRequest(member, { status: 'approved' });
  assert.equal(created.status, 201);
  assert.equal(created.body.data.status, 'pending');
  assert.equal(created.body.data.team, 'Support');

  const listed = await member.get('/api/requests');
  assert.equal(listed.status, 200);
  assert.ok(listed.body.data.some((item) => item.id === created.body.data.id));
  assert.equal((await member.get('/api/requests').query({ team: 'Engineering' })).status, 403);
  assert.equal((await member.patch(`/api/requests/${created.body.data.id}`).send({ status: 'approved' })).status, 403);
  assert.equal((await member.delete(`/api/requests/${created.body.data.id}`)).status, 403);
});

test('Admin can access permitted user and request operations', async () => {
  const admin = request.agent(app);
  await login(admin, 'admin');

  const createdUser = await admin.post('/api/users').send(validRegistration({
    role: 'manager',
    team: 'Design',
  }));
  assert.equal(createdUser.status, 201);
  assert.equal(createdUser.body.data.role, 'manager');

  const users = await admin.get('/api/users');
  assert.equal(users.status, 200);
  assert.ok(users.body.data.some((user) => user.id === createdUser.body.data.id));
  assert.equal(JSON.stringify(users.body).includes('password_hash'), false);

  const accessRequest = await createRequest(admin, { team: 'Operations' });
  assert.equal(accessRequest.status, 201);
  assert.equal((await admin.get('/api/requests')).status, 200);
  const reviewed = await admin.patch(`/api/requests/${accessRequest.body.data.id}`).send({ status: 'approved' });
  assert.equal(reviewed.status, 200);
  assert.equal(reviewed.body.data.status, 'approved');
  assert.equal((await admin.delete(`/api/requests/${accessRequest.body.data.id}`)).status, 200);
});

test('Managers can review only their team and cannot access administration', async () => {
  const manager = request.agent(app);
  await login(manager, 'manager');
  const ownRequest = await createRequest(manager, { team: 'Support' });
  assert.equal(ownRequest.body.data.team, 'Engineering');
  const managerRequests = await manager.get('/api/requests');
  assert.ok(managerRequests.body.data.some((item) => item.id === ownRequest.body.data.id));
  assert.equal((await manager.patch(`/api/requests/${ownRequest.body.data.id}`).send({ status: 'approved' })).status, 200);
  assert.equal((await manager.get('/api/team/summary')).status, 200);
  assert.equal((await manager.get('/api/users')).status, 403);
  assert.equal((await manager.post('/api/users').send(validRegistration({ role: 'admin' }))).status, 403);

  const admin = request.agent(app);
  await login(admin, 'admin');
  const outsideTeamRequest = await createRequest(admin, { team: 'Operations' });
  assert.equal(
    (await manager.patch(`/api/requests/${outsideTeamRequest.body.data.id}`).send({ status: 'approved' })).status,
    403,
  );
});

test('Members are denied admin and manager-only operations', async () => {
  const member = request.agent(app);
  await login(member, 'user');
  assert.equal((await member.get('/api/users')).status, 403);
  assert.equal((await member.get('/api/team/summary')).status, 403);
});

test('profile reads and permitted updates are limited to the authenticated user', async () => {
  const member = request.agent(app);
  const loginResponse = await login(member, 'user');
  const ownId = loginResponse.body.data.user.id;
  const ownProfile = await member.get(`/api/users/${ownId}`);
  assert.equal(ownProfile.status, 200);

  const otherRegistration = await request(app).post('/api/auth/register').send(validRegistration());
  const otherId = otherRegistration.body.data.user.id;
  assert.equal((await member.get(`/api/users/${otherId}`)).status, 403);
  assert.equal((await member.patch(`/api/users/${otherId}`).send({ fullName: 'Changed Name' })).status, 403);

  const updated = await member.patch(`/api/users/${ownId}`).send({ fullName: 'Morgan Updated' });
  assert.equal(updated.status, 200);
  assert.equal(updated.body.data.fullName, 'Morgan Updated');
  assert.equal(updated.body.data.role, 'user');
});

test('members cannot escalate their role or change team or account status', async () => {
  const member = request.agent(app);
  const loginResponse = await login(member, 'user');
  const ownId = loginResponse.body.data.user.id;
  for (const payload of [{ role: 'admin' }, { team: 'Operations' }, { status: 'suspended' }]) {
    assert.equal((await member.patch(`/api/users/${ownId}`).send(payload)).status, 403);
  }
  assert.equal((await member.get('/api/auth/session')).body.data.user.role, 'user');
});

test('administrative account suspension invalidates existing sessions', async () => {
  const input = validRegistration();
  const registration = await request(app).post('/api/auth/register').send(input);
  const targetId = registration.body.data.user.id;
  const admin = request.agent(app);
  await login(admin, 'admin');
  const suspended = await admin.patch(`/api/users/${targetId}`).send({ status: 'suspended' });
  assert.equal(suspended.status, 200);
  assert.equal(suspended.body.data.status, 'suspended');

  const member = request.agent(app);
  const suspendedLogin = await member.post('/api/auth/login').send({
    email: registration.body.data.user.email,
    password: input.password,
  });
  assert.equal(suspendedLogin.status, 401);
});

test('access request creation remains available to authenticated users', async () => {
  const admin = request.agent(app);
  assert.equal((await login(admin, 'admin')).status, 200);
  const created = await createRequest(admin, {
    employee: 'Avery Gomez',
    team: 'Security',
    role: 'Analyst',
    accessType: 'system',
    priority: 'high',
    justification: 'Needs incident response credentials for the security pipeline.',
  });
  assert.equal(created.status, 201);
  assert.equal(created.body.data.employee, 'Avery Gomez');
  assert.equal((await admin.get('/api/stats')).status, 200);
});

test('startup migrates existing SQLite accounts and access requests without losing records', () => {
  const migrationDbPath = path.join(process.cwd(), 'server', 'data', 'accesshub.migration.test.db');
  fs.rmSync(migrationDbPath, { force: true });
  const legacy = new DatabaseSync(migrationDbPath);
  legacy.exec(`
    CREATE TABLE users (
      id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL, full_name TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'manager', 'user')),
      team TEXT NOT NULL DEFAULT 'General', status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE sessions (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token TEXT UNIQUE NOT NULL,
      expires_at TEXT NOT NULL, created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE access_requests (
      id TEXT PRIMARY KEY, employee TEXT NOT NULL, team TEXT NOT NULL, role TEXT NOT NULL,
      accessType TEXT NOT NULL, justification TEXT NOT NULL, priority TEXT NOT NULL DEFAULT 'medium',
      status TEXT NOT NULL DEFAULT 'pending', reviewer TEXT, requestedAt TEXT NOT NULL,
      reviewedAt TEXT, createdAt TEXT NOT NULL, updatedAt TEXT NOT NULL
    );
    INSERT INTO users VALUES (
      'legacy-user', 'legacy@example.test', 'legacy-hash', 'legacy-salt',
      'Legacy User', 'user', 'Support', 'active', '2025-01-01', '2025-01-01'
    );
    INSERT INTO access_requests VALUES (
      'legacy-request', 'Legacy User', 'Support', 'Analyst', 'software',
      'Existing request must remain available after migration.', 'medium', 'pending',
      NULL, '2025-01-01', NULL, '2025-01-01', '2025-01-01'
    );
  `);
  legacy.close();

  try {
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', "await import('./server/server.js')"], {
      cwd: process.cwd(),
      encoding: 'utf8',
      env: { ...process.env, NODE_ENV: 'test', ACCESSHUB_DB_PATH: migrationDbPath },
    });
    assert.equal(child.status, 0, child.stderr);

    const migrated = new DatabaseSync(migrationDbPath);
    assert.equal(migrated.prepare('SELECT COUNT(*) AS count FROM users').get().count, 1);
    assert.equal(migrated.prepare('SELECT password_iterations FROM users WHERE id = ?').get('legacy-user').password_iterations, 100000);
    assert.equal(migrated.prepare('SELECT COUNT(*) AS count FROM access_requests WHERE id = ?').get('legacy-request').count, 1);
    assert.ok(migrated.prepare('PRAGMA table_info(access_requests)').all().some((column) => column.name === 'created_by'));
    migrated.close();
  } finally {
    fs.rmSync(migrationDbPath, { force: true });
  }
});
