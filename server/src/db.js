const { Pool } = require('pg');

// A pool, not a single client -- Express handles requests concurrently,
// so each request should be able to grab its own connection rather than
// queuing behind a single shared one.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://postgres:haseeb@localhost:5432/dpi_dashboard',
});

module.exports = pool;
