const express = require('express');
const pool = require('../db');
const { requireUser, requireAgent } = require('../middleware/auth');

const router = express.Router();

// Agent: report a batch of events. A single multi-row INSERT rather than
// one query per event -- cheaper, and atomic (either the whole batch lands
// or none of it does).
router.post('/:deviceId', requireAgent, async (req, res) => {
  const { events } = req.body;
  if (!Array.isArray(events) || events.length === 0) {
    return res.status(400).json({ error: 'events must be a non-empty array' });
  }

  const values = [];
  const placeholders = events.map((e, i) => {
    const base = i * 3;
    values.push(req.device.id, e.domain, e.action);
    return `($${base + 1}, $${base + 2}, $${base + 3})`;
  });

  await pool.query(
    `INSERT INTO events (device_id, domain, action) VALUES ${placeholders.join(', ')}`,
    values
  );

  await pool.query(
    `UPDATE devices SET last_seen = now(), status = 'online' WHERE id = $1`,
    [req.device.id]
  );

  res.status(201).json({ inserted: events.length });
});

// Dashboard: recent events across all (or one) of the user's devices.
// A real JOIN -- events don't store owner_user_id directly, so proving
// "this event belongs to a device I own" requires joining through devices.
router.get('/', requireUser, async (req, res) => {
  const { deviceId, limit } = req.query;
  const cappedLimit = Math.min(parseInt(limit, 10) || 100, 500);

  const params = [req.userId];
  let deviceFilter = '';
  if (deviceId) {
    params.push(deviceId);
    deviceFilter = `AND devices.id = $${params.length}`;
  }
  params.push(cappedLimit);

  const { rows } = await pool.query(
    `SELECT events.id, events.domain, events.action, events.timestamp,
            devices.id AS device_id, devices.name AS device_name
     FROM events
     JOIN devices ON events.device_id = devices.id
     WHERE devices.owner_user_id = $1 ${deviceFilter}
     ORDER BY events.timestamp DESC
     LIMIT $${params.length}`,
    params
  );

  res.json(rows);
});

module.exports = router;
