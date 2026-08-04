const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const pool = require('../db');
const { requireUser } = require('../middleware/auth');

const router = express.Router();

function generatePairingCode() {
  return String(crypto.randomInt(100000, 999999));
}

// Dashboard: "Add device" -> creates a placeholder row with a pairing code.
router.post('/', requireUser, async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });

  const pairingCode = generatePairingCode();
  const expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  const { rows } = await pool.query(
    `INSERT INTO devices (owner_user_id, name, pairing_code, pairing_code_expires)
     VALUES ($1, $2, $3, $4)
     RETURNING id, name, pairing_code, pairing_code_expires`,
    [req.userId, name, pairingCode, expires]
  );
  const device = rows[0];

  res.status(201).json({
    id: device.id,
    name: device.name,
    pairingCode: device.pairing_code,
    pairingCodeExpires: device.pairing_code_expires,
  });
});

// Dashboard: list this user's devices (never expose the API key hash or pairing code).
router.get('/', requireUser, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, name, enrolled, last_seen, status, created_at
     FROM devices WHERE owner_user_id = $1
     ORDER BY created_at DESC`,
    [req.userId]
  );
  res.json(rows);
});

// Agent: submit the pairing code once, receive a permanent API key in return.
router.post('/enroll', async (req, res) => {
  const { pairingCode } = req.body;
  if (!pairingCode) return res.status(400).json({ error: 'pairingCode is required' });

  const { rows } = await pool.query(
    'SELECT * FROM devices WHERE pairing_code = $1 AND enrolled = false',
    [pairingCode]
  );
  const device = rows[0];
  if (!device) return res.status(404).json({ error: 'Invalid or already-used pairing code' });
  if (new Date(device.pairing_code_expires) < new Date()) {
    return res.status(410).json({ error: 'Pairing code expired' });
  }

  const apiKey = crypto.randomBytes(32).toString('hex');
  const apiKeyHash = await bcrypt.hash(apiKey, 10);

  await pool.query(
    `UPDATE devices
     SET api_key_hash = $1, enrolled = true, pairing_code = NULL,
         pairing_code_expires = NULL, status = 'online', last_seen = now()
     WHERE id = $2`,
    [apiKeyHash, device.id]
  );

  res.json({ deviceId: device.id, apiKey });
});

module.exports = router;
