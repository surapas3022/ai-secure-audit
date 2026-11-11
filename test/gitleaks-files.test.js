import { test } from 'node:test';
import assert from 'node:assert/strict';
import gitleaks from '../src/scanners/gitleaks.js';

const root = '/tmp/asa-fixture';
const ctx = { root, isGit: true, fileExists: () => true, isIgnored: () => false };
const leak = (file, pass, extra = {}) => ({
  RuleID: 'stripe-access-token', Description: 'Stripe key', StartLine: 1,
  File: pass === 'files' ? `${root}/${file}` : file, Secret: 'REDACTED', Match: 'REDACTED', pass, ...extra,
});
const evidence = (f) => f.evidence[0];

test('a key seen only in the files is marked as not committed, with its own fix', () => {
  const [f] = gitleaks.parse([leak('config.js', 'files')], ctx);
  assert.equal(evidence(f).not_committed, true);
  assert.equal(evidence(f).location, 'config.js:1');
  assert.match(f.fix, /before you commit/);
});

test('the same key in history and in the files is one finding, and is not "not committed"', () => {
  const found = gitleaks.parse([leak('config.js', 'history', { Commit: 'abcdef1234' }), leak('config.js', 'files')], ctx);
  assert.equal(found.length, 1);
  assert.equal(evidence(found[0]).not_committed, undefined);
  assert.deepEqual(evidence(found[0]).commits, ['abcdef1']);
  assert.match(found[0].fix, /stays in git history/);
});

test('without git nothing is called "not committed"', () => {
  const [f] = gitleaks.parse([leak('config.js', 'files')], { ...ctx, isGit: false });
  assert.equal(evidence(f).not_committed, undefined);
});

test('a git-ignored source file is left out, but a committed one is not', () => {
  const ignored = { ...ctx, isIgnored: () => true };
  assert.equal(gitleaks.parse([leak('.env', 'files')], ignored).length, 0);
  assert.equal(gitleaks.parse([leak('.env', 'history', { Commit: 'abcdef1234' })], ignored).length, 1);
});

test('a key in deployed build output is reported even when git ignores the folder', () => {
  for (const file of ['dist/assets/index-a1.js', 'build/static/js/main.js', '.next/static/chunks/app.js',
    '.output/public/_nuxt/a.js', '.svelte-kit/output/client/a.js', 'web/dist/a.js']) {
    const [f] = gitleaks.parse([leak(file, 'files')], { ...ctx, isIgnored: () => true });
    assert.equal(evidence(f).built, true, file);
    assert.equal(evidence(f).not_committed, undefined, file);
    assert.equal(f.severity.normalized, 'high', file);
  }
});

test('framework internals are not reported, including folders named build or dist inside them', () => {
  for (const file of ['.next/server/app.js', '.next/cache/x.json', '.next/build/a.js', '.next/standalone/.next/a.js',
    '.nuxt/dist/client/a.js', '.output/server/index.mjs', '.svelte-kit/generated/a.js']) {
    assert.equal(gitleaks.parse([leak(file, 'files')], ctx).length, 0, file);
  }
});

test('a generic match in build output is medium and says it may be a false alarm; a named rule is not', () => {
  const [generic] = gitleaks.parse([leak('dist/a.js', 'files', { RuleID: 'generic-api-key' })], ctx);
  assert.equal(generic.severity.normalized, 'medium');
  assert.match(generic.fix, /false alarm/);
  const [source] = gitleaks.parse([leak('src/a.js', 'files', { RuleID: 'generic-api-key' })], ctx);
  assert.equal(source.severity.normalized, 'high');
});

test('scanning a subfolder keeps only its history and gives paths from that folder', () => {
  const sub = { ...ctx, prefix: 'apps/one/' };
  const found = gitleaks.parse([
    leak('apps/one/a.js', 'history', { Commit: 'abcdef1234' }),
    leak('apps/two/b.js', 'history', { Commit: 'abcdef1234' }),
    leak('a.js', 'files'),
  ], sub);
  assert.deepEqual(found.map((f) => evidence(f).location), ['a.js:1']);
  assert.deepEqual(evidence(found[0]).commits, ['abcdef1']);
});

test('history pass runs only when there is a commit to read', () => {
  const prep = { config: 'c.toml' };
  const names = (c) => gitleaks.passes(c, '/tmp/raw', prep).map((p) => p.name);
  assert.deepEqual(names({ ...ctx, commit: 'abc1234' }), ['history', 'files']);
  assert.deepEqual(names({ ...ctx, commit: null }), ['files']);
  assert.deepEqual(names({ ...ctx, isGit: false, commit: null }), ['files']);
});

test('nothing secret is copied into findings', () => {
  const text = JSON.stringify(gitleaks.parse([leak('config.js', 'files', { Email: 'a@example.invalid', Author: 'Someone' })], ctx));
  for (const banned of ['REDACTED', 'a@example.invalid', 'Someone']) assert.ok(!text.includes(banned), banned);
});

test('a key taken out of a file that is still there is marked as git history only', () => {
  const [f] = gitleaks.parse([leak('config.js', 'history', { Commit: 'abcdef1234' })], ctx);
  assert.equal(evidence(f).history_only, true);
  assert.deepEqual(evidence(f).commits, ['abcdef1']);
});

test('a key still in the file is not history only, even on another line or in a git-ignored file', () => {
  const still = gitleaks.parse([leak('config.js', 'history', { Commit: 'abcdef1234' }), leak('config.js', 'files')], ctx);
  assert.equal(evidence(still[0]).history_only, undefined);
  const moved = gitleaks.parse([leak('config.js', 'history', { Commit: 'abcdef1234' }), leak('config.js', 'files', { StartLine: 5 })], ctx);
  assert.ok(moved.every((f) => evidence(f).history_only === undefined));
  const ignored = gitleaks.parse([leak('.env', 'history', { Commit: 'abcdef1234' }), leak('.env', 'files')], { ...ctx, isIgnored: () => true });
  assert.equal(evidence(ignored[0]).history_only, undefined);
});

test('a key not committed yet is never history only', () => {
  const [f] = gitleaks.parse([leak('config.js', 'files')], { ...ctx, fileExists: () => false });
  assert.equal(evidence(f).history_only, undefined);
});
