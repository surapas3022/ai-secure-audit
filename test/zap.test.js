import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseZap, zapDockerArgs, zapUrl } from '../src/live/zap.js';

const read = (n) => JSON.parse(readFileSync(new URL(`./fixtures/${n}.json`, import.meta.url), 'utf8'));
const url = 'http://host.docker.internal:14501';

test('a weak site: the header, cookie and disclosure mistakes become findings, one per alert', () => {
  const { findings } = parseZap(read('zap-weak'), { url });
  const ids = findings.map((f) => f.source.rule_id).sort();
  assert.deepEqual(ids, ['10010', '10020-1', '10021', '10036-2', '10037', '10038-1', '10054-1', '10202', '20020-3', '90003'].sort());
  assert.ok(findings.every((f) => f.category === 'web' && f.fix.length > 10 && !/</.test(f.fix)));
});

test('a hardened site gives no findings: advice and noise are left out', () => {
  assert.equal(parseZap(read('zap-clean'), { url }).findings.length, 0);
});

test('noise alerts are never findings, even at risk 1 or 2', () => {
  const alert = (pluginid, riskcode) => ({ pluginid, alertRef: String(pluginid), name: `n${pluginid}`, riskcode, instances: [{ uri: 'http://x/', method: 'GET' }] });
  const noisy = [10019, 10049, 10027, 10109, 10063, 90004, 10017, 10096, 10055].map((p) => alert(p, '2'));
  assert.equal(parseZap({ site: [{ alerts: noisy }] }, { url }).findings.length, 0);
});

test('an alert that trusts the server\'s own banner is capped at medium and labelled; a real high stays high', () => {
  const inst = [{ uri: 'http://x/', method: 'GET', evidence: 'Apache/2.2.14' }];
  const r = parseZap({ site: [{ alerts: [
    { pluginid: '20020', alertRef: '20020-3', name: 'Apache with known vulnerabilities', riskcode: '3', instances: inst },
    { pluginid: '10202', alertRef: '10202', name: 'No CSRF token', riskcode: '3', instances: inst },
  ] }] }, { url });
  const by = Object.fromEntries(r.findings.map((f) => [f.source.rule_id, f]));
  assert.equal(by['20020-3'].severity.normalized, 'medium');
  assert.match(by['20020-3'].evidence[0].detail, /what the server says about itself/);
  assert.equal(by['10202'].severity.normalized, 'high');
});

test('many places for one alert: first 3 are listed and the total is said', () => {
  const instances = Array.from({ length: 5 }, (_, i) => ({ uri: `http://x/${i}`, method: 'GET' }));
  const [f] = parseZap({ site: [{ alerts: [{ pluginid: '10021', alertRef: '10021', name: 'nosniff', riskcode: '1', count: '12', instances }] }] }, { url }).findings;
  assert.equal(f.evidence.length, 3);
  assert.match(f.evidence[0].detail, /12 places in total/);
});

test('no site in the result means the check did not run (error), not "no problems"', () => {
  assert.throws(() => parseZap({ site: [] }, { url }), /found no site/);
  assert.throws(() => parseZap(null, { url }), /found no site/);
});

test('ZAP is always the passive baseline: never a full, active or API scan', () => {
  const a = zapDockerArgs({ image: 'ghcr.io/zaproxy/zaproxy@sha256:abc', dir: '/tmp/z', url: 'https://a.test' });
  assert.ok(a.includes('zap-baseline.py'));
  for (const bad of ['zap-full-scan.py', 'zap-api-scan.py', 'zap.sh', '-a', '--auto', '-j', '-z']) assert.ok(!a.includes(bad), bad);
  assert.equal(a[a.indexOf('-t') + 1], 'https://a.test');
  assert.ok(a.includes('no-new-privileges'));
  assert.ok(a.some((x) => x.includes('@sha256:')), 'image is pinned by digest');
});

test('local servers are reached through host.docker.internal; default ports are left out; remote hosts are untouched', () => {
  assert.equal(zapUrl({ scheme: 'http', host: 'localhost', port: 14501 }), 'http://host.docker.internal:14501');
  assert.equal(zapUrl({ scheme: 'http', host: '127.0.0.1', port: 80 }), 'http://host.docker.internal');
  assert.equal(zapUrl({ scheme: 'https', host: 'dev.example.com', port: 443 }), 'https://dev.example.com');
  assert.equal(zapUrl({ scheme: 'https', host: 'dev.example.com', port: 8443 }), 'https://dev.example.com:8443');
});

test('the lock pins the ZAP image by digest', () => {
  const lock = JSON.parse(readFileSync(new URL('../tools.lock.json', import.meta.url), 'utf8'));
  assert.match(lock.live_tools.zap.image, /^ghcr\.io\/zaproxy\/zaproxy@sha256:[0-9a-f]{64}$/);
});

test('an http target without --zap is refused with a clear reason, and nothing is downloaded or started', () => {
  const cache = mkdtempSync(join(tmpdir(), 'asa-cache-'));
  const cwd = mkdtempSync(join(tmpdir(), 'asa-cwd-'));
  writeFileSync(join(cwd, 'targets.yml'), 'targets:\n  - host: a.test\n    scheme: http\n');
  const bin = new URL('../bin/ai-secure-audit.js', import.meta.url).pathname;
  const r = spawnSync(process.execPath, [bin, 'live', 'a.test'], { cwd, encoding: 'utf8', env: { ...process.env, AI_SECURE_AUDIT_CACHE: cache } });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /plain http.*--zap/);
  assert.deepEqual(readdirSync(cache), []);
});
