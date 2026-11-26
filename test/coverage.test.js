import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { coverageGaps, isComposeFile, NOT_LOOKED_FOR, projectCoverage, ruleLanguages, ruleSummaries } from '../src/coverage.js';

// The line that says how few code rules ran: other tests here are about something else, so they leave it out.
const FEW_RULES = /^Code rules: .* code was checked with only /;
const otherGaps = (cov) => coverageGaps(cov).filter((g) => !FEW_RULES.test(g));
import { BASIC_SCANNERS } from '../src/scan.js';

function project(files) {
  const root = mkdtempSync(join(tmpdir(), 'asa-coverage-'));
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(join(root, path, '..'), { recursive: true });
    writeFileSync(join(root, path), body);
  }
  return root;
}

test('coverage: the code rule languages come from the rule files', () => {
  const langs = ruleLanguages();
  assert.ok(langs.has('javascript') && langs.has('typescript'));
  assert.ok(!langs.has('php'));
});

test('coverage: a PHP project says its code was not checked', () => {
  const root = project({
    'app/Http/Controllers/AuthController.php': '<?php',
    'routes/web.php': '<?php',
    'composer.lock': '{}',
    'resources/js/app.js': '',
    'vendor/laravel/framework/src/Foo.php': '<?php',
    'node_modules/x/index.js': '',
  });
  try {
    const cov = projectCoverage(root);
    assert.deepEqual(cov.languages, [
      { language: 'php', files: 2, code_rules: false },
      { language: 'javascript', files: 1, code_rules: true },
    ]);
    assert.deepEqual(cov.lockfiles, [{ file: 'composer.lock', ecosystem: 'Packagist (PHP)', tested: true }]);
    const gaps = otherGaps(cov);
    assert.equal(gaps.length, 1);
    assert.match(gaps[0], /php \(2 files\)/);
    assert.match(gaps[0], /docs\/ai-review-prompt\.md/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('coverage: a JavaScript project with an npm lockfile has no gaps but the few-rules line', () => {
  const root = project({ 'server.js': '', 'public/app.js': '', 'package-lock.json': '{}' });
  try {
    const cov = projectCoverage(root);
    assert.deepEqual(otherGaps(cov), []);
    assert.equal(coverageGaps(cov).length, 1);
    assert.deepEqual(cov.lockfiles.map((l) => l.file), ['package-lock.json']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('coverage: Vue components are reported, since the JavaScript rules do not read them', () => {
  const root = project({ 'src/App.vue': '', 'src/main.ts': '' });
  try {
    const gaps = otherGaps(projectCoverage(root));
    assert.equal(gaps.length, 1);
    assert.match(gaps[0], /vue \(1 file\)/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('coverage: a lockfile from an ecosystem without a known-answer case is called untested', () => {
  const root = project({ 'lib/main.dart': '', 'pubspec.lock': '' });
  try {
    const gaps = coverageGaps(projectCoverage(root));
    assert.equal(gaps.length, 2);
    assert.match(gaps[0], /dart \(1 file\)/);
    assert.match(gaps[1], /pubspec\.lock \(Pub \(Dart\/Flutter\)\)/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('coverage: file names that count as Docker Compose', () => {
  for (const n of ['compose.yaml', 'compose.yml', 'docker-compose.yml', 'docker-compose.yaml', 'docker-compose.prod.yml', 'compose.override.yaml']) {
    assert.ok(isComposeFile(n), n);
  }
  for (const n of ['composer.json', 'composer.lock', 'compose.json', 'my-compose.yml', 'docker-compose.yml.bak', 'Dockerfile']) {
    assert.ok(!isComposeFile(n), n);
  }
});

test('coverage: Compose files are named as not checked, since trivy does not read them', () => {
  const root = project({ 'server.js': '', 'compose.yaml': 'services: {}\n', 'deploy/docker-compose.prod.yml': 'services: {}\n' });
  try {
    const cov = projectCoverage(root);
    assert.deepEqual(cov.compose, ['compose.yaml', 'deploy/docker-compose.prod.yml']);
    const gap = coverageGaps(cov).find((g) => g.startsWith('Docker Compose:'));
    assert.ok(gap, 'a Docker Compose gap');
    assert.match(gap, /compose\.yaml, deploy\/docker-compose\.prod\.yml were not checked/);
    assert.match(gap, /"0 findings" says nothing/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('coverage: a Dockerfile without Compose is not a gap', () => {
  const root = project({ 'server.js': '', 'Dockerfile': 'FROM node:22-alpine\n', 'package-lock.json': '{}' });
  try {
    const cov = projectCoverage(root);
    assert.deepEqual(cov.compose, []);
    assert.deepEqual(otherGaps(cov), []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('coverage: Compose files inside node_modules are not counted', () => {
  const root = project({ 'node_modules/x/docker-compose.yml': 'services: {}\n', 'server.js': '' });
  try {
    assert.deepEqual(projectCoverage(root).compose, []);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('scan: trivy runs with the basic check', () => {
  assert.deepEqual(BASIC_SCANNERS.map((s) => s.id), ['gitleaks', 'osv-scanner', 'opengrep', 'trivy']);
});

test('coverage: every rule a user can get a finding from has a summary for the report', () => {
  const rules = ruleSummaries();
  assert.ok(rules.length >= 4);
  for (const r of rules) {
    assert.ok(r.summary, `${r.id} has no metadata.summary`);
    assert.ok(r.languages.length, `${r.id} has no languages`);
  }
  assert.ok(!rules.some((r) => r.id === 'nestjs-global-throttler'), 'internal helper rules are left out');
});

test('coverage: a TypeScript project is told how few code rules ran and what was not looked for', () => {
  const root = project({ 'src/server.ts': '', 'src/db.ts': '', 'package-lock.json': '{}' });
  try {
    const cov = projectCoverage(root);
    const all = ruleSummaries().filter((r) => r.languages.includes('typescript'));
    assert.deepEqual(cov.code_rules.map((r) => r.id), all.map((r) => r.id));
    const gap = coverageGaps(cov).find((g) => FEW_RULES.test(g));
    assert.ok(gap, 'a few-rules gap');
    assert.match(gap, new RegExp(`^Code rules: typescript code was checked with only ${all.length} rules from this kit: `));
    for (const r of all) assert.ok(gap.includes(r.summary), r.id);
    for (const item of NOT_LOOKED_FOR) assert.ok(gap.includes(item), item);
    // Pinned: an item leaves this list only when a rule covers it, together with this test.
    for (const word of ['in another file', 'NoSQL', 'shell commands', 'XSS', 'redirects', 'file lists', 'MD5']) assert.ok(gap.includes(word), word);
    assert.match(gap, /SQL text built from request values/);
    assert.match(gap, /text run as code \(eval, new Function/);
    assert.match(gap, /"0 findings" says nothing about them/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('coverage: a JavaScript-only project is not told about TypeScript-only rules', () => {
  const root = project({ 'server.js': '', 'package-lock.json': '{}' });
  try {
    const cov = projectCoverage(root);
    assert.ok(cov.code_rules.length > 0);
    assert.ok(!cov.code_rules.some((r) => r.id === 'nestjs-route-no-throttle'));
    assert.match(coverageGaps(cov)[0], /^Code rules: javascript code was checked with only /);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('coverage: a project with no code in a ruled language gets no few-rules line', () => {
  const root = project({ 'app.py': '', 'requirements.txt': '' });
  try {
    const cov = projectCoverage(root);
    assert.deepEqual(cov.code_rules, []);
    assert.ok(!coverageGaps(cov).some((g) => FEW_RULES.test(g)));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('coverage: Solidity files are named as not checked instead of passing in silence', () => {
  const root = project({ 'contracts/Bank.sol': '', 'contracts/Token.sol': '', 'server.js': '', 'package-lock.json': '{}' });
  try {
    const cov = projectCoverage(root);
    assert.deepEqual(cov.languages.find((l) => l.language === 'solidity'), { language: 'solidity', files: 2, code_rules: false });
    assert.match(coverageGaps(cov)[0], /no rules yet for solidity \(2 files\)/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('coverage: code in test or tests folders and minified files is named as not checked by the code rules', () => {
  const root = project({
    'src/server.js': '', 'src/a.test.js': '', 'spec/b.js': '', '__tests__/c.js': '',
    'test/e2e.js': '', 'tests/unit.ts': '', 'packages/api/test/fixtures/x.js': '', 'public/lib/app.min.js': '', 'test/lib/jquery.min.js': '',
    'test/data.json': '{}', 'tests/helper.py': '', 'package-lock.json': '{}',
  });
  try {
    const cov = projectCoverage(root);
    assert.deepEqual(cov.code_skipped, {
      test_folders: ['packages/api/test/fixtures/x.js', 'test/e2e.js', 'test/lib/jquery.min.js', 'tests/unit.ts'],
      minified: ['public/lib/app.min.js'],
    });
    const gap = coverageGaps(cov).find((g) => g.startsWith('Code rules: 4 files in test or tests folders'));
    assert.ok(gap, 'a test-folder gap');
    assert.match(gap, /packages\/api\/test\/fixtures\/x\.js, test\/e2e\.js, test\/lib\/jquery\.min\.js, tests\/unit\.ts/);
    assert.match(gap, /1 minified file \(public\/lib\/app\.min\.js\)/);
    assert.match(gap, /review it by hand/);
    assert.match(gap, /A minified file does run/);
    assert.match(gap, /The secret check still read these files\./);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('coverage: no test folders and no minified files gives no such gap', () => {
  const root = project({ 'src/server.js': '', 'src/a.test.js': '', '__tests__/c.js': '', 'package-lock.json': '{}' });
  try {
    const cov = projectCoverage(root);
    assert.deepEqual(cov.code_skipped, { test_folders: [], minified: [] });
    assert.ok(!coverageGaps(cov).some((g) => /test or tests folders|minified/.test(g)));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('coverage: only test folders, or only minified files, says just that', () => {
  const a = project({ 'tests/a.js': '', 'package-lock.json': '{}' });
  const b = project({ 'app.min.js': '', 'server.js': '', 'package-lock.json': '{}' });
  try {
    const ga = coverageGaps(projectCoverage(a)).find((g) => g.includes('test or tests'));
    assert.match(ga, /^Code rules: 1 file in test or tests folders \(tests\/a\.js\) was not checked by the code rules/);
    assert.doesNotMatch(ga, /minified/);
    const gb = coverageGaps(projectCoverage(b)).find((g) => g.includes('minified'));
    assert.match(gb, /^Code rules: 1 minified file \(app\.min\.js\) was not checked by the code rules/);
    assert.doesNotMatch(gb, /Test code/);
  } finally {
    rmSync(a, { recursive: true, force: true });
    rmSync(b, { recursive: true, force: true });
  }
});

test('coverage: files the code checker could not read, read in part, or stopped on are named', () => {
  const cov = { languages: [], lockfiles: [], code_read: {
    not_read: [{ file: 'src/f.js', line: 3 }, { file: 'src/huge.ts', line: null }],
    read_in_part: [{ file: 'src/user.service.ts', lines: [14, 30] }],
    stopped: [{ file: 'public/big.js', rules: ['js-html-from-user-text'] }],
  } };
  const gaps = coverageGaps(cov);
  const notRead = gaps.find((g) => g.startsWith('Code rules: 2 files could not be read'));
  assert.ok(notRead, JSON.stringify(gaps));
  assert.match(notRead, /src\/f\.js \(syntax error at line 3\), src\/huge\.ts/);
  assert.match(notRead, /were not checked by the code rules at all/);
  const part = gaps.find((g) => g.startsWith('Code rules: 1 file was read only in part'));
  assert.match(part, /src\/user\.service\.ts \(lines 14, 30\)/);
  assert.match(part, /a finding there can be missing/);
  const stopped = gaps.find((g) => g.startsWith('Code rules: the check stopped on 1 file'));
  assert.match(stopped, /public\/big\.js \(js-html-from-user-text\)/);
  for (const g of [notRead, part, stopped]) assert.match(g, /full list in findings\.json under coverage\.code_read/);
  assert.deepEqual(coverageGaps({ languages: [], lockfiles: [], code_read: { not_read: [], read_in_part: [], stopped: [] } }), []);
  assert.deepEqual(coverageGaps({ languages: [], lockfiles: [] }), []);
});
