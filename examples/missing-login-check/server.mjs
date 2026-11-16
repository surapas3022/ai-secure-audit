#!/usr/bin/env node
// A tiny team-notes API with the mistakes from learn/04: some routes do not check the login, the admin route trusts
// a role the web page sends, and the login check passes for a token named "constructor".
//
//   node examples/missing-login-check/server.mjs           (the mistakes)
//   node examples/missing-login-check/server.mjs --fixed   (deny by default, role from the session, a Map)
//
// No dependencies. Listens on 127.0.0.1 only, keeps everything in memory, and every token is random per run.
// All names and notes are made up.
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';

const FIXED = process.argv.includes('--fixed');
const PORT = Number(process.env.PORT) || 4200;

const token = () => randomBytes(12).toString('hex');
const people = [
  { name: 'alice', role: 'member', email: 'alice@example.com' },
  { name: 'boss', role: 'admin', email: 'boss@example.com' },
];
// MISTAKE: a plain object. It already has keys such as "constructor" and "toString".
// FIXED: a Map, which only has the keys put into it.
const sessions = FIXED ? new Map() : {};
const tokens = {};
for (const p of people) {
  tokens[p.name] = token();
  if (FIXED) sessions.set(tokens[p.name], p);
  else sessions[tokens[p.name]] = p;
}
const notes = [
  { id: 1, text: 'Team lunch on Friday' },
  { id: 2, text: 'Supplier price list: ask boss before sharing' },
];

function send(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body, null, 2) + '\n');
}

// The routes anyone may call without logging in. Everything else needs a login in the fixed version.
const PUBLIC = new Set(['GET /api/health']);

createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const route = `${req.method} ${url.pathname}`;
  const t = (/^Bearer (\w+)$/.exec(req.headers.authorization || '') || [])[1];

  if (route === 'GET /api/health') return send(res, 200, { ok: true });

  if (FIXED) {
    // FIXED: deny by default. One check before every route; a new route is closed until someone opens it on purpose.
    const user = t && sessions.get(t);
    if (!PUBLIC.has(route) && !user) return send(res, 401, { error: 'log in first' });
    req.user = user;
  }

  // MISTAKE: the export was added later, above the login check, and never got one.
  if (route === 'GET /api/notes/export') {
    res.writeHead(200, { 'content-type': 'text/csv' });
    return res.end(`id,text\n${notes.map((n) => `${n.id},"${n.text}"`).join('\n')}\n`);
  }

  if (!FIXED) {
    // MISTAKE: the login check is written per route, and it looks the token up in a plain object.
    if (!sessions[t]) return send(res, 401, { error: 'log in first' });
    req.user = sessions[t];
  }

  if (route === 'GET /api/me') return send(res, 200, { name: req.user.name, role: req.user.role });
  if (route === 'GET /api/notes') return send(res, 200, notes);

  if (route === 'GET /api/admin/users') {
    // MISTAKE: the page hides the admin menu from members and sends X-Role: admin only for admins, and the API
    // believes that header. FIXED: the role comes from the session on the server.
    const role = FIXED ? req.user.role : req.headers['x-role'];
    if (role !== 'admin') return send(res, 403, { error: 'admins only' });
    return send(res, 200, people);
  }
  send(res, 404, { error: 'not found' });
}).listen(PORT, '127.0.0.1', () => {
  console.log(`Team notes API (${FIXED ? 'FIXED: deny by default' : 'MISTAKE: missing and weak login checks'}) on http://127.0.0.1:${PORT}`);
  console.log(`alice's token: ${tokens.alice}   (member)`);
  console.log(`boss's token:  ${tokens.boss}   (admin)`);
  console.log('Press Ctrl+C to stop.');
});
