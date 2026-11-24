import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { mkdtempSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { probe, scanPorts, parsePorts, PORT_LIST, RISKY_PORTS } from '../src/live/ports.js';

const host = 'a.test';
const addr = (results, family = 4, unreachable = null) => ({ ip: family === 4 ? '203.0.113.9' : '2001:db8::9', family, results, unreachable });
const parse = (results) => parsePorts({ addrs: [addr(results)] }, { host });
const A4 = { address: '203.0.113.9', family: 4 };
const A6 = { address: '2001:db8::9', family: 6 };

test('open risky ports become findings with a severity that fits the danger', () => {
  const { findings } = parse({ 2375: 'open', 6379: 'open', 21: 'open', 3000: 'open' });
  const by = Object.fromEntries(findings.map((f) => [f.source.rule_id, f.severity.normalized]));
  assert.deepEqual(by, { 2375: 'critical', 6379: 'high', 21: 'medium', 3000: 'low' });
  assert.ok(findings.every((f) => f.category === 'network' && f.fix.length > 30 && /Nothing was sent/.test(f.evidence[0].detail)));
});

test('closed, filtered and unclear ports are never findings', () => {
  const { findings } = parse({ 6379: 'closed', 5432: 'filtered', 27017: 'error:EHOSTUNREACH', 3306: 'closed' });
  assert.equal(findings.length, 0);
});

test('SSH, mail, HTTP and HTTPS are information, not findings', () => {
  const r = parse({ 22: 'open', 25: 'open', 80: 'open', 443: 'open', 6379: 'closed' });
  assert.equal(r.findings.length, 0);
  assert.deepEqual(r.info, ['22 (SSH) on IPv4', '25 (SMTP (mail)) on IPv4', '80 (HTTP) on IPv4', '443 (HTTPS) on IPv4']);
});

test('a port that could not be tried is said so, not counted as closed', () => {
  const r = parse({ 6379: 'closed', 5432: 'error:ENETUNREACH' });
  assert.match(r.notices[0].message, /1 of 2 ports on 203\.0\.113\.9 could not be tried/);
});

test('if no connection could be tried at all, the check failed: it must not look like "all closed"', async () => {
  await assert.rejects(scanPorts(host, { resolve: async () => [A4, A6], probeFn: async () => 'error:ENETUNREACH' }), /no connection could be tried/);
  await assert.rejects(scanPorts(host, { resolve: async () => { const e = new Error('x'); e.code = 'ENOTFOUND'; throw e; } }), /could not resolve a\.test \(ENOTFOUND\)/);
});

test('only the fixed list is tried: a short, sorted, unique list of single ports, never a range', () => {
  assert.ok(PORT_LIST.length <= 40);
  assert.deepEqual(PORT_LIST, [...new Set(PORT_LIST)].sort((a, b) => a - b));
  assert.ok(PORT_LIST.every((p) => Number.isInteger(p) && p > 0 && p < 65536));
  assert.ok(Object.keys(RISKY_PORTS).every((p) => PORT_LIST.includes(Number(p))));
});

test('at most `concurrency` probes run at the same time, and every port is tried once', async () => {
  let inflight = 0; let peak = 0; const seen = [];
  const probeFn = async (ip, p) => { inflight++; peak = Math.max(peak, inflight); seen.push(p); await new Promise((r) => setTimeout(r, 5)); inflight--; return 'closed'; };
  await scanPorts(host, { resolve: async () => [A4], probeFn, concurrency: 4 });
  assert.ok(peak <= 4);
  assert.deepEqual(seen.sort((a, b) => a - b), PORT_LIST);
});

test('the host name is resolved once; only the first IPv4 and the first IPv6 address are tried', async () => {
  let lookups = 0; const ips = new Set();
  const many = [A4, { address: '203.0.113.10', family: 4 }, A6, { address: '2001:db8::10', family: 6 }];
  await scanPorts(host, { resolve: async () => { lookups++; return many; }, probeFn: async (ip) => { ips.add(ip); return 'closed'; } });
  assert.equal(lookups, 1);
  assert.deepEqual([...ips].sort(), ['2001:db8::9', '203.0.113.9']);
});

test('a port open only over IPv6 is found (the forgotten-firewall case), and open on both gives one finding with two places', () => {
  const only6 = parsePorts({ addrs: [addr({ 5432: 'closed' }, 4), addr({ 5432: 'open' }, 6)] }, { host });
  assert.equal(only6.findings.length, 1);
  assert.deepEqual(only6.findings[0].evidence.map((e) => e.location), ['[2001:db8::9]:5432']);
  const both = parsePorts({ addrs: [addr({ 6379: 'open' }, 4), addr({ 6379: 'open' }, 6)] }, { host });
  assert.equal(both.findings.length, 1);
  assert.deepEqual(both.findings[0].evidence.map((e) => e.location), ['203.0.113.9:6379', '[2001:db8::9]:6379']);
});

test('one address family that cannot be reached is said so; the other family still counts', async () => {
  const probeFn = async (ip, p) => (ip.includes(':') ? 'error:ENETUNREACH' : p === 6379 ? 'open' : 'closed');
  const scan = await scanPorts(host, { resolve: async () => [A4, A6], probeFn });
  const r = parsePorts(scan, { host });
  assert.equal(r.findings.length, 1);
  assert.match(r.notices[0].message, /IPv6 address 2001:db8::9 could not be tried/);
  assert.match(r.addresses[1], /not reachable from here/);
});

test('a real probe: open, closed, and it sends nothing', async () => {
  let received = 0;
  const srv = createServer((s) => { s.on('data', (d) => { received += d.length; }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const { port } = srv.address();
  assert.equal(await probe('127.0.0.1', port), 'open');
  await new Promise((r) => setTimeout(r, 100));
  srv.close();
  assert.equal(await probe('127.0.0.1', port), 'closed');
  assert.equal(received, 0, 'the probe must not write to the socket');
});

test('--ports on a host that is not listed is refused before any connection; --no-tls alone is refused', () => {
  const cache = mkdtempSync(join(tmpdir(), 'asa-cache-'));
  const cwd = mkdtempSync(join(tmpdir(), 'asa-cwd-'));
  writeFileSync(join(cwd, 'targets.yml'), 'targets:\n  - host: a.test\n');
  const bin = fileURLToPath(new URL('../bin/ai-secure-audit.js', import.meta.url));
  const run = (args) => spawnSync(process.execPath, [bin, 'live', ...args], { cwd, encoding: 'utf8', env: { ...process.env, AI_SECURE_AUDIT_CACHE: cache } });
  let r = run(['other.test', '--ports']);
  assert.equal(r.status, 2); assert.match(r.stderr, /refusing/);
  r = run(['a.test', '--no-tls']);
  assert.equal(r.status, 2); assert.match(r.stderr, /nothing to check/);
  assert.deepEqual(readdirSync(cache), []);
});

// ---- what an open port proves depends on the address ----
import { addressScope } from '../src/live/ports.js';

const openOn = (ip, port = '3389') => ({ addrs: [{ family: ip.includes(':') ? 6 : 4, ip, results: { [port]: 'open' } }] });

test('address scope: loopback, private and public, including the edges of each range', () => {
  const want = {
    '127.0.0.1': 'loopback', '127.255.255.254': 'loopback', '::1': 'loopback', '0.0.0.0': 'loopback',
    '10.0.0.1': 'private', '172.16.0.1': 'private', '172.31.255.255': 'private', '192.168.0.1': 'private',
    '169.254.10.10': 'private', '100.64.0.1': 'private', '100.127.255.255': 'private', 'fc00::1': 'private', 'fdff::1': 'private', 'fe80::1': 'private',
    '::ffff:10.0.0.1': 'private', '::ffff:127.0.0.1': 'loopback',
    '172.15.255.255': 'public', '172.32.0.1': 'public', '100.128.0.1': 'public', '192.169.0.1': 'public', '11.0.0.1': 'public',
    '8.8.8.8': 'public', '::ffff:8.8.8.8': 'public', '2001:db8::1': 'public', '2606:4700::1': 'public',
  };
  for (const [ip, scope] of Object.entries(want)) assert.equal(addressScope(ip), scope, ip);
});

test('a finding never says "from the internet" in its title, whatever the address', () => {
  for (const ip of ['127.0.0.1', '::1', '10.1.2.3', '8.8.8.8']) {
    const [f] = parsePorts(openOn(ip), { host: 'h' }).findings;
    assert.match(f.title, /Remote Desktop \(RDP\) accepts connections$/, ip);
    assert.doesNotMatch(f.title, /internet/i);
  }
});

test('the evidence says only what the address shows: public may be reachable by anyone, loopback and private may not', () => {
  const detail = (ip) => parsePorts(openOn(ip), { host: 'h' }).findings[0].evidence[0].detail;
  assert.match(detail('8.8.8.8'), /accepted from the computer that ran this check/);
  assert.match(detail('8.8.8.8'), /If you ran this from outside your own network, anyone on the internet can do the same/);
  assert.match(detail('127.0.0.1'), /this computer itself.*not that it can be reached from outside/);
  assert.match(detail('::1'), /this computer itself/);
  assert.match(detail('192.168.1.10'), /private network address.*not from the internet/);
  assert.doesNotMatch(detail('127.0.0.1') + detail('192.168.1.10'), /anyone on the internet can do the same/);
});

test('the fix text still tells people not to expose the port, and the severity is unchanged by the address', () => {
  const a = parsePorts(openOn('127.0.0.1'), { host: 'h' }).findings[0];
  const b = parsePorts(openOn('8.8.8.8'), { host: 'h' }).findings[0];
  assert.equal(a.severity.normalized, b.severity.normalized);
  assert.equal(a.fix, b.fix);
  assert.match(a.fix, /firewall/);
});
