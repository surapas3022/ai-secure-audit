import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import gitleaks from '../src/scanners/gitleaks.js';
import osv from '../src/scanners/osv.js';
import trivy from '../src/scanners/trivy.js';
import { sortAndNumber } from '../src/findings.js';

const fixture = (name) => JSON.parse(readFileSync(new URL(`./fixtures/${name}.json`, import.meta.url), 'utf8'));
const ctx = { root: '/tmp/asa-fixture' };

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

test('trivy: only failed checks', () => {
  const f = trivy.parse(fixture('trivy'), ctx);
  assert.deepEqual(f.map((x) => x.source.rule_id).sort(), ['DS-0002', 'DS-0026']);
});

test('ordering does not depend on input order', () => {
  const all = [...gitleaks.parse(fixture('gitleaks'), ctx), ...osv.parse(fixture('osv-scanner'), ctx), ...trivy.parse(fixture('trivy'), ctx)];
  const a = JSON.stringify(sortAndNumber(all));
  const b = JSON.stringify(sortAndNumber([...all].reverse()));
  assert.equal(a, b);
  assert.equal(sortAndNumber(all)[0].category, 'secret');
});
