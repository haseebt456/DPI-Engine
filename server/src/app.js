const express = require('express');
const cors = require('cors');

const authRoutes = require('./routes/auth');
const deviceRoutes = require('./routes/devices');
const ruleRoutes = require('./routes/rules');
const eventRoutes = require('./routes/events');

function createApp() {
  const app = express();
  app.use(cors());
  app.use(express.json());

  app.get('/health', (req, res) => res.json({ status: 'ok' }));

  app.use('/api/auth', authRoutes);
  app.use('/api/devices', deviceRoutes);
  app.use('/api/rules', ruleRoutes);
  app.use('/api/events', eventRoutes);

  // Centralized error handler -- catches anything thrown/rejected in a
  // route that wasn't already handled, so a bug can't crash the process.
  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}

module.exports = createApp;
