const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key';

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Method Not Allowed' }) };
  }

  try {
    const { action, email, password } = JSON.parse(event.body);

    if (!email || !password) {
      return { statusCode: 400, body: JSON.stringify({ error: 'Email and password are required' }) };
    }

    const client = await pool.connect();

    try {
      await client.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          email VARCHAR(255) UNIQUE NOT NULL,
          password VARCHAR(255) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);

      if (action === 'register') {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await client.query(
          'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email',
          [email, hashedPassword]
        );
        
        const user = result.rows[0];
        const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

        return {
          statusCode: 200,
          body: JSON.stringify({ message: 'Registration successful!', token })
        };
      } else if (action === 'login') {
        const result = await client.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
          return { statusCode: 400, body: JSON.stringify({ error: 'Invalid email or password' }) };
        }

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
          return { statusCode: 400, body: JSON.stringify({ error: 'Invalid email or password' }) };
        }

        const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });

        return {
          statusCode: 200,
          body: JSON.stringify({ message: 'Login successful!', token })
        };
      } else {
        return { statusCode: 400, body: JSON.stringify({ error: 'Invalid action' }) };
      }
    } finally {
      client.release();
    }
  } catch (err) {
    console.error('Auth error:', err);
    return { statusCode: 500, body: JSON.stringify({ error: 'Internal server error: ' + err.message }) };
  }
};