const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const request = require('supertest');

// Uses a real Postgres database (DATABASE_URL, defaulting to a local test
// DB) -- the schema is dropped and recreated before the suite runs, so
// every run starts from a clean slate.
const TEST_DB_URL = process.env.TEST_DATABASE_URL
  || 'postgresql://postgres:postgres@localhost:5432/dpi_dashboard_test';

// IMPORTANT: this must happen before requiring '../src/app', because
// src/db.js reads process.env.DATABASE_URL exactly once, at module-load
// time, to build its connection pool. Setting the env var after the app
// is already required would be too late -- the app would keep talking to
// whatever database was live when it first loaded.
process.env.DATABASE_URL = TEST_DB_URL;
const createApp = require('../src/app');

let pool;
let app;

beforeAll(async () => {
  pool = new Pool({ connectionString: TEST_DB_URL });

  await pool.query('DROP TABLE IF EXISTS events, rules, devices, users CASCADE');
  const schema = fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8');
  await pool.query(schema);

  app = createApp();
});

afterAll(async () => {
  await pool.end();
  const appPool = require('../src/db');
  await appPool.end();
});

describe('Full flow: signup -> add device -> pair -> set rule -> agent polls -> agent reports', () => {
  let token;
  let deviceId;
  let pairingCode;
  let apiKey;

  test('user can sign up', async () => {
    const res = await request(app)
      .post('/api/auth/signup')
      .send({ email: 'haseeb@example.com', password: 'hunter2pass' });
    expect(res.status).toBe(201);
    expect(res.body.token).toBeDefined();
    token = res.body.token;
  });

  test('rejects a second signup with the same email', async () => {
    const res = await request(app)
      .post('/api/auth/signup')
      .send({ email: 'haseeb@example.com', password: 'somethingelse' });
    expect(res.status).toBe(409);
  });

  test('dashboard can create a device and gets a pairing code', async () => {
    const res = await request(app)
      .post('/api/devices')
      .set('Authorization', `Bearer ${token}`)
      .send({ name: "Haseeb's Laptop" });
    expect(res.status).toBe(201);
    expect(res.body.pairingCode).toMatch(/^\d{6}$/);
    deviceId = res.body.id;
    pairingCode = res.body.pairingCode;
  });

  test('rejects device creation without a token', async () => {
    const res = await request(app).post('/api/devices').send({ name: 'No auth' });
    expect(res.status).toBe(401);
  });

  test('agent can enroll using the pairing code and receives an API key', async () => {
    const res = await request(app).post('/api/devices/enroll').send({ pairingCode });
    expect(res.status).toBe(200);
    expect(res.body.deviceId).toBe(deviceId);
    expect(res.body.apiKey).toHaveLength(64);
    apiKey = res.body.apiKey;
  });

  test('the same pairing code cannot be used twice', async () => {
    const res = await request(app).post('/api/devices/enroll').send({ pairingCode });
    expect(res.status).toBe(404);
  });

  test('dashboard creates a global rule and a device-specific rule', async () => {
    const globalRule = await request(app)
      .post('/api/rules')
      .set('Authorization', `Bearer ${token}`)
      .send({ type: 'domain', value: 'youtube.com' });
    expect(globalRule.status).toBe(201);

    const scopedRule = await request(app)
      .post('/api/rules')
      .set('Authorization', `Bearer ${token}`)
      .send({ deviceId, type: 'app', value: 'Facebook' });
    expect(scopedRule.status).toBe(201);
  });

  test('agent polling with the correct API key sees both applicable rules', async () => {
    const res = await request(app)
      .get(`/api/rules/for-device/${deviceId}`)
      .set('x-api-key', apiKey);
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(2);
    const values = res.body.map((r) => r.value).sort();
    expect(values).toEqual(['Facebook', 'youtube.com']);
  });

  test('agent polling with a wrong API key is rejected', async () => {
    const res = await request(app)
      .get(`/api/rules/for-device/${deviceId}`)
      .set('x-api-key', 'not-the-real-key');
    expect(res.status).toBe(401);
  });

  test('agent can report a batch of events', async () => {
    const res = await request(app)
      .post(`/api/events/${deviceId}`)
      .set('x-api-key', apiKey)
      .send({
        events: [
          { domain: 'www.youtube.com', action: 'blocked' },
          { domain: 'github.com', action: 'forwarded' },
        ],
      });
    expect(res.status).toBe(201);
    expect(res.body.inserted).toBe(2);
  });

  test('dashboard can see the reported events via the JOIN query', async () => {
    const res = await request(app)
      .get('/api/events')
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(2);
    expect(res.body[0].device_name).toBe("Haseeb's Laptop");
  });

  test('a rule can be deleted', async () => {
    const rules = await request(app)
      .get('/api/rules')
      .set('Authorization', `Bearer ${token}`);
    const ruleId = rules.body[0].id;

    const del = await request(app)
      .delete(`/api/rules/${ruleId}`)
      .set('Authorization', `Bearer ${token}`);
    expect(del.status).toBe(204);
  });

  test('deleting the device cascades and removes its rules and events', async () => {
    await pool.query('DELETE FROM devices WHERE id = $1', [deviceId]);
    const remainingRules = await pool.query('SELECT * FROM rules WHERE device_id = $1', [deviceId]);
    const remainingEvents = await pool.query('SELECT * FROM events WHERE device_id = $1', [deviceId]);
    expect(remainingRules.rows).toHaveLength(0);
    expect(remainingEvents.rows).toHaveLength(0);
  });
});
