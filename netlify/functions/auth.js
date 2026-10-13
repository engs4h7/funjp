const { neon } = require('@neondatabase/serverless');

exports.handler = async function(event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    const { action, email, password } = JSON.parse(event.body);
    const sql = neon(process.env.DATABASE_URL);

    await sql`
      CREATE TABLE IF NOT EXISTS app_users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;

    if (action === 'signup') {
      const existing = await sql`SELECT * FROM app_users WHERE email = ${email}`;
      if (existing.length > 0) {
        return { statusCode: 400, body: JSON.stringify({ error: 'Email already registered.' }) };
      }
      const result = await sql`
        INSERT INTO app_users (email, password) VALUES (${email}, ${password}) RETURNING id, email
      `;
      return { statusCode: 200, body: JSON.stringify({ user: result[0] }) };
    } 
    
    if (action === 'login') {
      const users = await sql`SELECT * FROM app_users WHERE email = ${email} AND password = ${password}`;
      if (users.length === 0) {
        return { statusCode: 401, body: JSON.stringify({ error: 'Invalid email or password.' }) };
      }
      return { statusCode: 200, body: JSON.stringify({ user: { id: users[0].id, email: users[0].email } }) };
    }

    return { statusCode: 400, body: JSON.stringify({ error: 'Invalid action.' }) };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: err.message }) };
  }
};