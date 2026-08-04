require('dotenv').config();
const createApp = require('./app');
const pool = require('./db');

const PORT = process.env.PORT || 4000;

async function start() {
  await pool.query('SELECT 1'); // fail fast if the database isn't reachable
  console.log('Connected to PostgreSQL');

  const app = createApp();
  app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
}

start().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
