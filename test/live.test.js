import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseTestssl, testsslArgs } from '../src/live/testssl.js';
import { treeFromTarGz } from '../src/extract.js';
import { treeHash } from '../src/tools.js';

const at = { host: 'localhost', port: 14443 };
const fixture = JSON.parse(readFileSync(new URL('./fixtures/testssl.json', import.meta.url), 'utf8'));

test('a real testssl result becomes a few findings, not one per line', () => {
  const { findings } = parseTestssl(fixture, at);
  const ids = findings.map((f) => f.source.rule_id).sort();
  assert.deepEqual(ids, ['HSTS', 'cert_chain_of_trust', 'cert_subjectAltName', 'cert_trust']);
  assert.ok(fixture.length > 100);
});

test('noise and testssl\'s own messages never become findings', () => {
  const { findings, notices } = parseTestssl(fixture, at);
  const ids = findings.map((f) => f.source.rule_id);
  for (const noise of ['overall_grade', 'cert_revocation', 'security_headers', 'LUCKY13', 'engine_problem', 'cmdline_fast_depreciation', 'cipherlist_OBSOLETED']) {
    assert.ok(!ids.includes(noise), noise);
  }
  assert.ok(!findings.some((f) => /^cipher-/.test(f.source.rule_id)));
  assert.deepEqual(notices.map((n) => n.id), ['RC4']);
});

test('a test that could not run is a notice, never a silent pass', () => {
  const { findings, notices } = parseTestssl(fixture, at);
  assert.ok(!findings.some((f) => f.source.rule_id === 'RC4'));
  assert.match(notices[0].message, /could not check "RC4 ciphers are offered"/);
});

test('severities: old protocols and vulnerabilities are rated, a critical certificate problem is capped at high', () => {
  const rows = [
    { id: 'TLS1_2', severity: 'OK', finding: 'offered' },
    { id: 'TLS1', severity: 'MEDIUM', finding: 'offered (deprecated)' },
    { id: 'heartbleed', severity: 'CRITICAL', finding: 'VULNERABLE' },
    { id: 'cert_chain_of_trust', severity: 'CRITICAL', finding: 'failed (self signed).' },
    { id: 'BEAST', severity: 'OK', finding: 'not vulnerable' },
  ];
  const by = Object.fromEntries(parseTestssl(rows, at).findings.map((f) => [f.source.rule_id, f.severity.normalized]));
  assert.deepEqual(by, { TLS1: 'medium', heartbleed: 'critical', cert_chain_of_trust: 'high' });
});

test('no TLS answer means the check did not run (error), not "no problems"', () => {
  assert.throws(() => parseTestssl([{ id: 'engine_problem', severity: 'WARN', finding: 'x' }], at), /could not talk TLS/);
  assert.throws(() => parseTestssl(null, at), /could not talk TLS/);
});

test('testssl is called with one host, one address and no options that need a missing command or send more traffic', () => {
  const a = testsslArgs('a.example', 443, '/tmp/x.json');
  assert.equal(a.at(-1), 'a.example:443');
  assert.ok(a.includes('--ip') && a[a.indexOf('--ip') + 1] === 'one');
  for (const bad of ['--connect-timeout', '--openssl-timeout', '--fast', '--sneaky']) assert.ok(!a.includes(bad), bad);
});

// A tiny tar writer, enough to feed treeFromTarGz.
function tar(entries) {
  const blocks = [];
  for (const [name, content, type = '0', mode = '644'] of entries) {
    const data = Buffer.from(content);
    const h = Buffer.alloc(512);
    h.write(name, 0); h.write(mode.padStart(7, '0') + '\0', 100); h.write(data.length.toString(8).padStart(11, '0') + '\0', 124);
    h.write(type, 156);
    blocks.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

test('the folder reader strips the top folder and keeps modes', () => {
  const files = treeFromTarGz(tar([['top/', '', '5'], ['top/a.sh', 'echo', '0', '755'], ['top/etc/b.txt', 'b']]), 1);
  assert.deepEqual(files.map((f) => [f.path, f.mode]), [['a.sh', 0o755], ['etc/b.txt', 0o644]]);
});

test('the folder reader refuses paths that could land outside the target and entries that are not plain files', () => {
  assert.throws(() => treeFromTarGz(tar([['top/../../evil', 'x']]), 1), /unsafe path/);
  assert.throws(() => treeFromTarGz(tar([['/abs/evil', 'x']]), 1), /unsafe path/);
  assert.throws(() => treeFromTarGz(tar([['top/link', '', '2']]), 1), /unsupported entry type/);
});

test('the folder hash does not depend on archive order, and changes when a byte, a name or the exec bit changes', () => {
  const f = (path, text, mode = 0o644) => ({ path, mode, data: Buffer.from(text) });
  const base = [f('a', '1'), f('b', '2')];
  assert.equal(treeHash(base), treeHash([...base].reverse()));
  assert.notEqual(treeHash(base), treeHash([f('a', '1'), f('b', '3')]));
  assert.notEqual(treeHash(base), treeHash([f('a', '1'), f('c', '2')]));
  assert.notEqual(treeHash(base), treeHash([f('a', '1'), f('b', '2', 0o755)]));
});

test('live refuses without a targets file or for a host not listed, and downloads nothing', () => {
  const cache = mkdtempSync(join(tmpdir(), 'asa-cache-'));
  const cwd = mkdtempSync(join(tmpdir(), 'asa-cwd-'));
  const bin = fileURLToPath(new URL('../bin/ai-secure-audit.js', import.meta.url));
  const run = (args) => spawnSync(process.execPath, [bin, 'live', ...args], { cwd, encoding: 'utf8', env: { ...process.env, AI_SECURE_AUDIT_CACHE: cache } });
  let r = run(['a.example']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /no targets file/);
  writeFileSync(join(cwd, 'targets.yml'), 'targets:\n  - host: a.example\n');
  r = run(['b.example']);
  assert.equal(r.status, 2);
  assert.match(r.stderr, /refusing/);
  assert.deepEqual(readdirSync(cache), []);
});

test('the lock pins the live tool by folder hash and lists only platforms with bash', () => {
  const lock = JSON.parse(readFileSync(new URL('../tools.lock.json', import.meta.url), 'utf8'));
  const t = lock.live_tools.testssl;
  assert.match(t.tree_sha256, /^[0-9a-f]{64}$/);
  assert.ok(t.url.startsWith('https://github.com/testssl/testssl.sh/archive/refs/tags/v'));
  assert.ok(!t.platforms.some((p) => p.startsWith('win32') || p.endsWith('musl')));
});
