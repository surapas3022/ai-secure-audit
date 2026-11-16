// Test cases for express-session-lookup-plain-object. Run: opengrep scan --test rules/
const express = require('express');
const crypto = require('crypto');
const app = express();
const db = { adminSessions: {}, sessions: {}, codes: {} };
const sessions = {};
const apiKeys = {};

function cookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').map((c) => c.trim().split('=')));
}
const hashToken = (t) => crypto.createHash('sha256').update(String(t)).digest('hex');

// The case that was found: cookie admin=constructor passes.
function requireAdmin(req, res, next) {
  const t = cookies(req).admin;
  // ruleid: express-session-lookup-plain-object
  if (t && db.adminSessions[t]) return next();
  res.status(401).end();
}

app.get('/me', (req, res) => {
  // ruleid: express-session-lookup-plain-object
  if (!sessions[req.cookies.sid]) return res.status(401).end();
  res.json({});
});

app.get('/data', (req, res) => {
  const key = req.get('x-api-key');
  // ruleid: express-session-lookup-plain-object
  if (key in apiKeys) return res.json({});
  res.status(403).end();
});

app.get('/token', (req, res) => {
  // ruleid: express-session-lookup-plain-object
  res.json({ ok: sessions[req.query.token] ? true : false });
});

// A hash of the token is looked up instead.
function requireAdminHashed(req, res, next) {
  const t = cookies(req).admin;
  // ok: express-session-lookup-plain-object
  if (t && db.adminSessions[hashToken(t)]) return next();
  res.status(401).end();
}

// Own-property check first.
app.get('/me2', (req, res) => {
  const sid = req.cookies.sid;
  // ok: express-session-lookup-plain-object
  if (Object.hasOwn(sessions, sid) && sessions[sid]) return res.json({});
  res.status(401).end();
});

// A Map has no built-in keys.
const store = new Map();
app.get('/me3', (req, res) => {
  // ok: express-session-lookup-plain-object
  if (!store.get(req.cookies.sid)) return res.status(401).end();
  res.json({});
});

// Upper-cased codes cannot spell a built-in key, and "codes" is not a session store.
app.post('/join', (req, res) => {
  const code = String(req.body.code || '').toUpperCase();
  // ok: express-session-lookup-plain-object
  if (!db.codes[code]) return res.status(404).end();
  res.json({});
});

// A key the server chose, not the request.
app.get('/admin-count', (req, res) => {
  // ok: express-session-lookup-plain-object
  if (db.adminSessions['current']) return res.json({ n: 1 });
  res.json({ n: 0 });
});

// Writing a session is not a check.
app.post('/login', (req, res) => {
  const t = crypto.randomBytes(32).toString('hex');
  // ok: express-session-lookup-plain-object
  sessions[t] = { at: Date.now() };
  res.json({ t });
});

// A store made without a prototype.
const tokens = Object.create(null);
app.get('/me4', (req, res) => {
  // ok: express-session-lookup-plain-object
  if (!tokens[req.cookies.sid]) return res.status(401).end();
  res.json({});
});
