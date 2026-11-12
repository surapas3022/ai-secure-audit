import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { coverageGaps, projectCoverage, ruleLanguages } from '../src/coverage.js';

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
    const gaps = coverageGaps(cov);
    assert.equal(gaps.length, 1);
    assert.match(gaps[0], /php \(2 files\)/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('coverage: a JavaScript project with an npm lockfile has no gaps', () => {
  const root = project({ 'server.js': '', 'public/app.js': '', 'package-lock.json': '{}' });
  try {
    const cov = projectCoverage(root);
    assert.deepEqual(coverageGaps(cov), []);
    assert.deepEqual(cov.lockfiles.map((l) => l.file), ['package-lock.json']);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('coverage: Vue components are reported, since the JavaScript rules do not read them', () => {
  const root = project({ 'src/App.vue': '', 'src/main.ts': '' });
  try {
    const gaps = coverageGaps(projectCoverage(root));
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
