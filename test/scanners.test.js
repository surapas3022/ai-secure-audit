import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import gitleaks from '../src/scanners/gitleaks.js';
import osv from '../src/scanners/osv.js';
import trivy from '../src/scanners/trivy.js';
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

test('trivy: only failed checks', () => {
  const f = trivy.parse(fixture('trivy'), ctx);
  assert.deepEqual(f.map((x) => x.source.rule_id).sort(), ['DS-0002', 'DS-0026']);
  assert.ok(f.every((x) => x.category === 'config'));
});

test('trivy: no report gives no findings', () => {
  assert.deepEqual(trivy.parse(null, ctx), []);
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
  for (const x of ['node_modules', 'express-route-no-rate-limit.js', 'nestjs-route-no-throttle.ts', 'express-vote-route-no-identity.js', 'express-session-lookup-plain-object.js', 'sql-built-from-request.ts', 'js-html-from-user-text.js', 'js-code-from-text.js']) assert.ok(excluded.includes(x), x);
  assert.ok(args.includes('--taint-intrafile'));
});

test('opengrep: internal rules are never shown, and drop the findings that name them in suppressed-by', () => {
  const r = (id, meta, line) => ({ check_id: `x.rules.${id}`, path: '/tmp/asa-fixture/a.ts', start: { line }, extra: { message: 'T. Fix.', severity: 'WARNING', metadata: meta, lines: 'x' } });
  const route = r('nestjs-route-no-throttle', { 'suppressed-by': 'nestjs-global-throttler' }, 7);
  const global = r('nestjs-global-throttler', { internal: true }, 3);
  assert.deepEqual(opengrep.parse({ results: [route] }, ctx).map((f) => f.evidence[0].location), ['a.ts:7']);
  assert.deepEqual(opengrep.parse({ results: [route, global] }, ctx), []);
  assert.deepEqual(opengrep.parse({ results: [global] }, ctx), []);
});

test('osv-scanner: the fix version ignores GIT ranges (commit hashes)', () => {
  const json = { results: [{ source: { path: '/tmp/asa-fixture/requirements.txt' }, packages: [{
    package: { name: 'requests', version: '2.19.1', ecosystem: 'PyPI' },
    vulnerabilities: [{ id: 'PYSEC-2018-28', summary: 's', affected: [{ package: { name: 'requests' }, ranges: [
      { type: 'GIT', events: [{ introduced: '0' }, { fixed: 'c45d7c49ea75133e52ab22a8e9e13173938e36ff' }] },
      { type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '2.20.0' }] },
    ] }] }],
    groups: [{ ids: ['PYSEC-2018-28'], aliases: ['CVE-2018-18074'], max_severity: '9.8' }],
  }] }] };
  assert.match(osv.parse(json, ctx)[0].fix, /^Upgrade requests to 2\.20\.0 or later/);
});

test('opengrep: several taint paths to one line are one finding', () => {
  const r = (line, col) => ({ check_id: 'x.rules.sql-built-from-request', path: '/tmp/asa-fixture/a.ts', start: { line, col },
    extra: { message: 'T. Fix.', severity: 'ERROR', metadata: {}, lines: 'db.query(x)' } });
  const got = opengrep.parse({ results: [r(5, 1), r(5, 1), r(5, 9), r(7, 1)] }, ctx);
  assert.deepEqual(got.map((f) => f.evidence[0].location), ['a.ts:5', 'a.ts:7']);
});

test('opengrep: files it could not read, read in part, or stopped on are listed for the report', () => {
  const at = (p, line) => ({ file: `/tmp/asa-fixture/${p}`, start: { line, col: 1, offset: 0 }, end: { line, col: 5, offset: 4 } });
  const json = { results: [], errors: [
    { code: 3, level: 'warn', type: 'Syntax error', path: '/tmp/asa-fixture/src/f.js', spans: [at('src/f.js', 3)], message: 'Syntax error at line ...' },
    { code: 3, level: 'warn', type: ['PartialParsing', [at('src/user.service.ts', 14)]], path: '/tmp/asa-fixture/src/user.service.ts',
      spans: [at('src/user.service.ts', 14), at('src/user.service.ts', 30)], message: 'Syntax error at line ...' },
    { code: 3, level: 'warn', type: ['PartialParsing', [at('src/user.service.ts', 14)]], path: '/tmp/asa-fixture/src/user.service.ts',
      spans: [at('src/user.service.ts', 14)], message: 'again' },
    { code: 2, level: 'warn', type: 'Timeout', rule_id: 'Users.me.rules.js-html-from-user-text', path: '/tmp/asa-fixture/public/big.js', message: 'Timeout when running ...' },
    { code: 2, level: 'warn', type: 'Timeout', rule_id: 'Users.me.rules.sql-built-from-request', path: '/tmp/asa-fixture/public/big.js', message: 'Timeout when running ...' },
    { code: 2, level: 'error', type: 'Out of memory', path: '/tmp/asa-fixture/src/huge.ts', message: 'oom' },
    // A file with a syntax error is not read at all, even if a partial parse of it is reported too.
    { code: 3, level: 'warn', type: ['PartialParsing', []], path: '/tmp/asa-fixture/src/f.js', spans: [at('src/f.js', 9)], message: 'x' },
    // A real syntax error has no spans: the line is only in the message.
    { code: 3, level: 'warn', type: 'Syntax error', path: '/tmp/asa-fixture/src/snippet.ts', message: 'Syntax error at line /tmp/asa-fixture/src/snippet.ts:7:\n `x` was unexpected' },
    { code: 2, level: 'warn', type: 'Rule parse error', message: 'no path: about a rule, not a file' },
  ] };
  assert.deepEqual(opengrep.codeRead(json, ctx), {
    not_read: [{ file: 'src/f.js', line: 3 }, { file: 'src/huge.ts', line: null }, { file: 'src/snippet.ts', line: 7 }],
    read_in_part: [{ file: 'src/user.service.ts', lines: [14, 30] }],
    stopped: [{ file: 'public/big.js', rules: ['js-html-from-user-text', 'sql-built-from-request'] }],
  });
  assert.deepEqual(opengrep.codeRead({ results: [] }, ctx), { not_read: [], read_in_part: [], stopped: [] });
  assert.deepEqual(opengrep.codeRead(null, ctx), { not_read: [], read_in_part: [], stopped: [] });
});
