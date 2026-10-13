const { neon } = require('@neondatabase/serverless');

exports.handler = async function(event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    const { userId } = JSON.parse(event.body);
    const sql = neon(process.env.DATABASE_URL);

    const users = await sql`SELECT id, email FROM app_users WHERE id = ${userId}`;
    if (users.length === 0) {
      return { statusCode: 401, body: JSON.stringify({ error: 'User not found.' }) };
    }

    return { statusCode: 200, body: JSON.stringify({ user: users[0] }) };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: err.message }) };
  }
};