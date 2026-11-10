#!/usr/bin/env node
// A tiny shop API with the mistake from learn/02: it checks who you are, but not whether the order is yours.
//
//   node examples/other-users-data/server.mjs           (the mistake)
//   node examples/other-users-data/server.mjs --fixed   (checks the owner on every request)
//
// No dependencies. Listens on 127.0.0.1 only, keeps everything in memory, and every token is random per run.
// All names, addresses and phone numbers are made up.
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';

const FIXED = process.argv.includes('--fixed');
const PORT = Number(process.env.PORT) || 4100;

const token = () => randomBytes(12).toString('hex');
const users = {
  alice: { name: 'alice', token: token() },
  bob: { name: 'bob', token: token() },
};
const orders = {
  1: { id: 1, owner: 'alice', item: 'Headphones', address: '12 Example Road, Bangkok', phone: '080-000-0001' },
  2: { id: 2, owner: 'bob', item: 'Rice cooker', address: '34 Sample Street, Chiang Mai', phone: '080-000-0002' },
  3: { id: 3, owner: 'alice', item: 'Phone case', address: '12 Example Road, Bangkok', phone: '080-000-0001' },
  4: { id: 4, owner: 'bob', item: 'Desk lamp', address: '34 Sample Street, Chiang Mai', phone: '080-000-0002' },
};

function currentUser(req) {
  const m = /^Bearer (\w+)$/.exec(req.headers.authorization || '');
  return m ? Object.values(users).find((u) => u.token === m[1]) : null;
}

function send(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body, null, 2) + '\n');
}

function readJson(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (c) => { raw += c; if (raw.length > 10_000) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(raw || '{}')); } catch { resolve(null); } });
  });
}

createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const user = currentUser(req);
  // Authentication: who are you? Both versions do this.
  if (!user) return send(res, 401, { error: 'log in first' });

  // List: the mistake version returns everyone's orders and leaves filtering to the web page.
  if (req.method === 'GET' && url.pathname === '/api/orders') {
    const all = Object.values(orders);
    return send(res, 200, FIXED ? all.filter((o) => o.owner === user.name) : all);
  }

  const m = /^\/api\/orders\/(\d+)$/.exec(url.pathname);
  if (!m) return send(res, 404, { error: 'not found' });
  const order = orders[m[1]];

  // Authorization: is this order yours? Only the fixed version asks.
  // It answers 404, not 403, so a stranger cannot even tell that the order exists.
  if (!order || (FIXED && order.owner !== user.name)) return send(res, 404, { error: 'order not found' });

  if (req.method === 'GET') return send(res, 200, order);
  if (req.method === 'PUT') {
    const body = await readJson(req);
    if (!body || typeof body.address !== 'string') return send(res, 400, { error: 'send {"address": "..."}' });
    order.address = body.address.slice(0, 200);
    return send(res, 200, order);
  }
  send(res, 405, { error: 'method not allowed' });
}).listen(PORT, '127.0.0.1', () => {
  console.log(`Shop API (${FIXED ? 'FIXED: checks the owner' : 'MISTAKE: does not check the owner'}) on http://127.0.0.1:${PORT}`);
  console.log(`alice's token: ${users.alice.token}   (alice owns orders 1 and 3)`);
  console.log(`bob's token:   ${users.bob.token}   (bob owns orders 2 and 4)`);
  console.log('Press Ctrl+C to stop.');
});
