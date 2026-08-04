const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const pool = require('../db');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';

function requireUser(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

async function requireAgent(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'Missing API key' });

  const deviceId = req.params.deviceId;
  const { rows } = await pool.query('SELECT * FROM devices WHERE id = $1', [deviceId]);
  const device = rows[0];
  if (!device || !device.api_key_hash) {
    return res.status(401).json({ error: 'Unknown device' });
  }

  const valid = await bcrypt.compare(apiKey, device.api_key_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid API key' });

  req.device = device;
  next();
}

module.exports = { requireUser, requireAgent, JWT_SECRET };
