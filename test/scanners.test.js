import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import gitleaks from '../src/scanners/gitleaks.js';
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
