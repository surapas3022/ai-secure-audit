import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import gitleaks from '../src/scanners/gitleaks.js';
import osv from '../src/scanners/osv.js';
import opengrep from '../src/scanners/opengrep.js';
import { sortAndNumber } from '../src/findings.js';

const fixture = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}.json`, import.meta.url), 'utf8'));
const ctx = { root: '/tmp/asa-fixture', isGit: true, fileExists: () => true };

test('gitleaks: one finding per secret location, no secret or personal data copied', () => {
  const f = gitleaks.parse(fixture('gitleaks'), ctx);
  assert.equal(f.length, 1);
  assert.equal(f[0].evidence[0].location, 'index.js:1');
  assert.equal(f[0].severity.normalized, 'high');
  const text = JSON.stringify(f);
  for (const banned of ['REDACTED', 'fixture@example.invalid', 'sk_live']) assert.ok(!text.includes(banned), banned);
});

test('gitleaks: null report (no leaks) gives no findings', () => {
  assert.deepEqual(gitleaks.parse(null, ctx), []);
});

test('osv-scanner: one finding per advisory group, relative path, fix version', () => {
  const f = osv.parse(fixture('osv-scanner'), ctx);
  assert.equal(f.length, 6);
  assert.ok(f.every((x) => x.evidence[0].location === 'package-lock.json'));
  assert.ok(f.every((x) => x.fix.includes('4.17.21') || x.fix.startsWith('Upgrade')));
  assert.ok(f.every((x) => ['critical', 'high', 'medium', 'low'].includes(x.severity.normalized)));
});

test('osv-scanner: no report (no lockfiles) gives no findings', () => {
  assert.deepEqual(osv.parse(null, ctx), []);
});

test('secrets sort before dependencies', () => {
  const all = [...osv.parse(fixture('osv-scanner'), ctx), ...gitleaks.parse(fixture('gitleaks'), ctx)];
  assert.equal(sortAndNumber(all)[0].category, 'secret');
  assert.equal(JSON.stringify(sortAndNumber(all)), JSON.stringify(sortAndNumber([...all].reverse())));
});

test('ordering does not depend on input order', () => {
  const one = gitleaks.parse(fixture('gitleaks'), ctx)[0];
  const all = [one, { ...one, fingerprint: `${one.fingerprint}:b`, severity: { ...one.severity, normalized: 'low' } }];
  const a = JSON.stringify(sortAndNumber(all));
  const b = JSON.stringify(sortAndNumber([...all].reverse()));
  assert.equal(a, b);
  assert.equal(sortAndNumber(all)[0].category, 'secret');
});

test('gitleaks: a secret in a deleted file is marked as git history only', () => {
  const f = gitleaks.parse(fixture('gitleaks'), { ...ctx, fileExists: () => false });
  assert.equal(f[0].evidence[0].history_only, true);
  assert.deepEqual(f[0].evidence[0].commits, ['0327e0e']);
});

test('opengrep: rule id without the config path, relative location, first line only', () => {
  const f = opengrep.parse(fixture('opengrep'), ctx);
  assert.deepEqual(f.map((x) => x.evidence[0].location), ['routes.js:7', 'routes.js:13', 'routes.js:18', 'routes.js:24', 'routes.js:27']);
  assert.ok(f.every((x) => x.source.rule_id === 'express-route-no-rate-limit'));
  assert.ok(f.every((x) => x.category === 'code' && x.severity.normalized === 'medium'));
  assert.ok(f.every((x) => !x.evidence[0].detail.includes('\n')));
  assert.ok(f.every((x) => x.title.length > 0 && x.fix.length > 0));
});

test('opengrep: no results gives no findings', () => {
  assert.deepEqual(opengrep.parse({ results: [] }, ctx), []);
  assert.deepEqual(opengrep.parse(null, ctx), []);
});

test('opengrep: local rules only, rule test files and installed code are never scanned', () => {
  const args = opengrep.args({ root: '/tmp/asa-fixture' }, '/tmp/out.json');
  assert.ok(args.includes('--disable-version-check'));
  assert.ok(args[args.indexOf('--config') + 1].endsWith('rules/') || args[args.indexOf('--config') + 1].endsWith('rules\\'));
  const excluded = args.filter((a, i) => args[i - 1] === '--exclude');
  for (const x of ['node_modules', 'express-route-no-rate-limit.js']) assert.ok(excluded.includes(x), x);
});
