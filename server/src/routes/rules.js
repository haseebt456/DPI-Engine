const express = require('express');
const pool = require('../db');
const { requireUser, requireAgent } = require('../middleware/auth');

const router = express.Router();

router.post('/', requireUser, async (req, res) => {
  const { deviceId, type, value } = req.body;
  if (!type || !value) return res.status(400).json({ error: 'type and value are required' });
  if (!['domain', 'app', 'ip'].includes(type)) {
    return res.status(400).json({ error: 'type must be domain, app, or ip' });
  }

  if (deviceId) {
    const owned = await pool.query(
      'SELECT id FROM devices WHERE id = $1 AND owner_user_id = $2',
      [deviceId, req.userId]
    );
    if (owned.rows.length === 0) return res.status(404).json({ error: 'Device not found' });
  }

  const { rows } = await pool.query(
    `INSERT INTO rules (owner_user_id, device_id, type, value)
     VALUES ($1, $2, $3, $4) RETURNING *`,
    [req.userId, deviceId || null, type, value]
  );
  res.status(201).json(rows[0]);
});

router.get('/', requireUser, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT * FROM rules WHERE owner_user_id = $1 ORDER BY created_at DESC',
    [req.userId]
  );
  res.json(rows);
});

router.delete('/:ruleId', requireUser, async (req, res) => {
  const { rows } = await pool.query(
    'DELETE FROM rules WHERE id = $1 AND owner_user_id = $2 RETURNING id',
    [req.params.ruleId, req.userId]
  );
  if (rows.length === 0) return res.status(404).json({ error: 'Rule not found' });
  res.status(204).send();
});

// Agent: poll for rules that apply to it -- either scoped specifically to
// this device, or marked global (device_id IS NULL) for this owner.
router.get('/for-device/:deviceId', requireAgent, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM rules
     WHERE owner_user_id = $1 AND (device_id = $2 OR device_id IS NULL)`,
    [req.device.owner_user_id, req.device.id]
  );
  res.json(rows);
});

module.exports = router;
