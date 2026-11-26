// Test cases for sql-built-from-parameter. Run: opengrep scan --test --taint-intrafile rules/
// Written before the rule. A db helper in its own file builds SQL from what its caller passed in: the route that
// calls it (with req.body) is in another file, so sql-built-from-request cannot see the request.
const pool = require('./pool');
const db = require('./db');

// --- SQL text built from a parameter ---

function login(username, password) {
  const q = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
  // ruleid: sql-built-from-parameter
  return pool.query(q);
}

async function search(term) {
  // ruleid: sql-built-from-parameter
  return pool.query(`SELECT * FROM products WHERE name ILIKE '%${term}%'`);
}

const ordersFor = (userId, sort) =>
  // ruleid: sql-built-from-parameter
  pool.query(`SELECT * FROM orders WHERE user_id = $1 ORDER BY ${sort} DESC`, [userId]);

class UserRepo {
  constructor(conn) { this.conn = conn; }
  byEmail(email) {
    // ruleid: sql-built-from-parameter
    return this.conn.query(`SELECT * FROM users WHERE email = '${email}'`);
  }
}

module.exports.update = function (id, fields) {
  const sets = Object.keys(fields).map((k) => `${k} = '${fields[k]}'`);
  // ruleid: sql-built-from-parameter
  return db.query(`UPDATE users SET ${sets.join(', ')} WHERE id = ${id}`);
};

async function remove(prisma, id) {
  // ruleid: sql-built-from-parameter
  return prisma.$executeRawUnsafe(`DELETE FROM "Post" WHERE id = ${id}`);
}

// --- Safe: placeholders, numbers, escaped names ---

function byId(id) {
  // ok: sql-built-from-parameter
  return pool.query('SELECT * FROM users WHERE id = $1', [id]);
}

function page(limit, offset) {
  // ok: sql-built-from-parameter
  return pool.query(`SELECT * FROM t LIMIT ${Number(limit)} OFFSET ${parseInt(offset, 10)}`);
}

function exportTable(client, table) {
  // ok: sql-built-from-parameter
  return client.query(`SELECT * FROM ${quoteIdent(table)}`);
}

function inList(ids) {
  const marks = ids.map(() => '?').join(',');
  // ok: sql-built-from-parameter
  return db.all(`SELECT * FROM t WHERE id IN (${marks})`, ids);
}

function savepoint(tx) {
  const name = 'sp_1';
  // ok: sql-built-from-parameter
  return tx.query(`SAVEPOINT ${name}`);
}

// --- Request objects are sql-built-from-request's job: not reported here ---

function handler(req, res) {
  // ok: sql-built-from-parameter
  return pool.query(`SELECT * FROM t WHERE id = ${req.query.id}`);
}

// --- Not SQL ---

function greet(name) {
  // ok: sql-built-from-parameter
  return console.log(`hello ${name}`);
}

function cached(cache, key) {
  // ok: sql-built-from-parameter
  return cache.get(`user = '${key}'`);
}

// A fragment joined with +: fixed text the caller wrote, like WHERE ${where}.
function filtered(db, frag) {
  // ok: sql-built-from-parameter
  return db.query('SELECT * FROM t WHERE ' + frag);
}

// --- Seen as false findings on two apps: the SQL is not built from a value here ---

// A wrapper that takes the whole SQL text and its values: the caller decides, and placeholders are the norm.
function shopQuery(client, text, params) {
  // ok: sql-built-from-parameter
  return client.query(text, params);
}

// A fragment of SQL the code put together (the caller passes fixed text such as "status = 'open'").
function userWhere(client, where, params) {
  // ok: sql-built-from-parameter
  return client.query(`SELECT * FROM users WHERE ${where} LIMIT 1`, params);
}

// An HTTP client is not a database.
function download(client, url, options) {
  // ok: sql-built-from-parameter
  return client.get(url, options);
}
