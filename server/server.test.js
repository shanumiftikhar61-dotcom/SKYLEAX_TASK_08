import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
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

const makeEmail = (label) => `${label}-${Date.now()}-${Math.random().toString(16).slice(2)}@example.com`;
const makePassword = () => randomBytes(32).toString('base64url');

test('public registration defaults to User and rejects privileged roles', async () => {
  const registrationPassword = makePassword();
  const response = await request(app)
    .post('/api/auth/register')
    .send({
      email: makeEmail('privileged-role'),
      password: registrationPassword,
      fullName: 'Privileged Role User',
      role: 'admin',
      team: 'Finance',
    });

  assert.equal(response.status, 400);
  assert.match(response.body.error.message, /User role/i);

  const validRegister = await request(app)
    .post('/api/auth/register')
    .send({
      email: makeEmail('public-user'),
      password: registrationPassword,
      fullName: 'Public User',
      team: 'Finance',
    });

  assert.equal(validRegister.status, 201);
  assert.equal(validRegister.body.data.user.role, 'user');
  assert.equal(validRegister.body.data.user.team, 'Finance');
});

test('login creates a server-managed session for authenticated access', async () => {
  const agent = request.agent(app);
  const response = await agent.post('/api/auth/login').send({
    email: 'user@accesshub.local',
    password: seedPasswords.user,
  });

  assert.equal(response.status, 200);
  assert.equal(response.body.data.user.role, 'user');

  const protectedResponse = await agent.get('/api/requests');
  assert.equal(protectedResponse.status, 200);
  assert.equal(protectedResponse.body.success, true);
});

test('unauthorized requests return 401 and role checks reject forbidden access', async () => {
  const noAuthResponse = await request(app).get('/api/requests');
  assert.equal(noAuthResponse.status, 401);

  const userAgent = request.agent(app);
  await userAgent.post('/api/auth/login').send({
    email: 'user@accesshub.local',
    password: seedPasswords.user,
  });

  const usersResponse = await userAgent.get('/api/users');
  assert.equal(usersResponse.status, 403);

  const summaryResponse = await userAgent.get('/api/team/summary');
  assert.equal(summaryResponse.status, 403);
});

test('admin can manage users and regular users cannot access other private profiles', async () => {
  const adminAgent = request.agent(app);
  await adminAgent.post('/api/auth/login').send({
    email: 'admin@accesshub.local',
    password: seedPasswords.admin,
  });

  const userRegistration = await request(app)
    .post('/api/auth/register')
    .send({
      email: makeEmail('other-user'),
      password: makePassword(),
      fullName: 'Other User',
      team: 'Support',
    });

  const otherUserId = userRegistration.body.data.user.id;

  const adminList = await adminAgent.get('/api/users');
  assert.equal(adminList.status, 200);
  assert.ok(adminList.body.data.some((user) => user.id === otherUserId));

  const userAgent = request.agent(app);
  await userAgent.post('/api/auth/login').send({
    email: 'user@accesshub.local',
    password: seedPasswords.user,
  });

  const forbiddenProfile = await userAgent.get(`/api/users/${otherUserId}`);
  assert.equal(forbiddenProfile.status, 403);

  const adminUpdate = await adminAgent.patch(`/api/users/${otherUserId}`).send({ role: 'manager' });
  assert.equal(adminUpdate.status, 200);
  assert.equal(adminUpdate.body.data.role, 'manager');
});

test('users cannot change their own role and managers can view team summary', async () => {
  const managerAgent = request.agent(app);
  await managerAgent.post('/api/auth/login').send({
    email: 'manager@accesshub.local',
    password: seedPasswords.manager,
  });

  const teamSummary = await managerAgent.get('/api/team/summary');
  assert.equal(teamSummary.status, 200);
  assert.ok(teamSummary.body.data.totalMembers >= 1);

  const userAgent = request.agent(app);
  const login = await userAgent.post('/api/auth/login').send({
    email: 'user@accesshub.local',
    password: seedPasswords.user,
  });

  const selfPatch = await userAgent.patch(`/api/users/${login.body.data.user.id}`).send({ role: 'admin' });
  assert.equal(selfPatch.status, 403);
  assert.match(selfPatch.body.error.message, /role/i);

  const selfProfile = await userAgent.get(`/api/users/${login.body.data.user.id}`);
  assert.equal(selfProfile.status, 200);
  assert.equal(selfProfile.body.data.email, 'user@accesshub.local');
});

test('access request features remain protected and usable for authenticated users', async () => {
  const agent = request.agent(app);
  const login = await agent.post('/api/auth/login').send({
    email: 'admin@accesshub.local',
    password: seedPasswords.admin,
  });

  assert.equal(login.status, 200);

  const createRequest = await agent.post('/api/requests').send({
    employee: 'Avery Gomez',
    team: 'Security',
    role: 'Analyst',
    accessType: 'system',
    priority: 'high',
    justification: 'Needs emergency incident response credentials for the security pipeline.',
  });

  assert.equal(createRequest.status, 201);
  assert.equal(createRequest.body.data.employee, 'Avery Gomez');

  const list = await agent.get('/api/requests').query({ status: 'pending' });
  assert.equal(list.status, 200);
  assert.ok(Array.isArray(list.body.data));
});
