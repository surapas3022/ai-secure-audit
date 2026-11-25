import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { coverageGaps, NO_LIBRARY_CHECK, projectCoverage } from '../src/coverage.js';
import { reportMarkdown } from '../src/report.js';
import { reportSimple } from '../src/report-simple.js';
import osv from '../src/scanners/osv.js';

function coverageOf(files) {
  const root = mkdtempSync(join(tmpdir(), 'asa-libs-'));
  try {
    for (const [path, body] of Object.entries(files)) {
      mkdirSync(dirname(join(root, path)), { recursive: true });
      writeFileSync(join(root, path), body);
    }
    return projectCoverage(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
const pkg = (extra = { dependencies: { jsonwebtoken: '0.4.0' } }) => JSON.stringify({ name: 'x', ...extra });
const libraryGaps = (cov) => coverageGaps(cov).filter((g) => g.startsWith(NO_LIBRARY_CHECK));

test('libraries: a package.json with libraries and no lockfile is reported as not checked', () => {
  const cov = coverageOf({ 'package.json': pkg() });
  assert.deepEqual(cov.unlocked, ['package.json']);
  assert.equal(libraryGaps(cov).length, 1);
  assert.match(libraryGaps(cov)[0], /no lockfile .* for package\.json.*not looked at/);
});

test('libraries: devDependencies alone count, a package.json that asks for nothing does not', () => {
  assert.deepEqual(coverageOf({ 'package.json': pkg({ devDependencies: { vite: '1' } }) }).unlocked, ['package.json']);
  assert.deepEqual(coverageOf({ 'package.json': pkg({ type: 'module', dependencies: {} }) }).unlocked, []);
  assert.deepEqual(coverageOf({ 'composer.json': '{"require":{"php":"^8.2","ext-json":"*"}}' }).unlocked, []);
  assert.deepEqual(coverageOf({ 'package.json': '{ broken' }).unlocked, ['package.json']);
});

test('libraries: a lockfile beside the manifest covers it, in every ecosystem listed', () => {
  const cov = coverageOf({
    'a/package.json': pkg(), 'a/pnpm-lock.yaml': '',
    'b/composer.json': '{"require":{"monolog/monolog":"1"}}', 'b/composer.lock': '{}',
    'c/Gemfile': "gem 'rails'\n", 'c/Gemfile.lock': '',
    'd/Cargo.toml': '[dependencies]\nserde = "1"\n', 'd/Cargo.lock': '',
    'e/pyproject.toml': '[project]\ndependencies = [\n  "flask",\n]\n', 'e/uv.lock': '',
    'f/pubspec.yaml': 'dependencies:\n  http: any\n', 'f/pubspec.lock': '',
    'g/App.csproj': '<PackageReference Include="X" />', 'g/packages.lock.json': '{}',
  });
  assert.deepEqual(cov.unlocked, []);
});

test('libraries: the same manifests without a lockfile are all reported', () => {
  const cov = coverageOf({
    'b/composer.json': '{"require":{"monolog/monolog":"1"}}',
    'c/Gemfile': "source 'x'\ngem 'rails'\n",
    'd/Cargo.toml': '[package]\nname="x"\n[target.\'cfg(unix)\'.dependencies]\nlibc = "1"\n',
    'e/pyproject.toml': '[tool.poetry.dependencies]\nflask = "1"\n',
    'f/pubspec.yaml': 'name: x\ndependencies:\n  http: any\n',
    'g/App.csproj': '<PackageReference Include="X" />',
    'h/Pipfile': '[packages]\nflask = "*"\n',
    'i/build.gradle.kts': 'dependencies { implementation("a:b:1") }',
  });
  assert.deepEqual(cov.unlocked, ['b/composer.json', 'c/Gemfile', 'd/Cargo.toml', 'e/pyproject.toml', 'f/pubspec.yaml',
    'g/App.csproj', 'h/Pipfile', 'i/build.gradle.kts']);
  assert.match(libraryGaps(cov)[0], /and 3 more/);
});

test('libraries: a workspace lockfile at the top covers its members and nothing else', () => {
  const npm = coverageOf({
    'package.json': pkg({ workspaces: ['packages/*', '!packages/old'], dependencies: { a: '1' } }), 'package-lock.json': '{}',
    'packages/web/package.json': pkg(), 'packages/old/package.json': pkg(), 'tools/package.json': pkg(),
  });
  assert.deepEqual(npm.unlocked, ['packages/old/package.json', 'tools/package.json']);
  const pnpm = coverageOf({
    'pnpm-workspace.yaml': "packages:\n  - 'apps/**'  # all apps\n", 'pnpm-lock.yaml': '', 'apps/x/y/package.json': pkg(),
  });
  assert.deepEqual(pnpm.unlocked, []);
  const cargo = coverageOf({
    'Cargo.toml': '[workspace]\nmembers = ["crates/*"]\n', 'Cargo.lock': '', 'crates/a/Cargo.toml': '[dependencies]\nx="1"\n',
  });
  assert.deepEqual(cargo.unlocked, []);
  const plain = coverageOf({ 'package-lock.json': '{}', 'package.json': pkg(), 'admin/package.json': pkg() });
  assert.deepEqual(plain.unlocked, ['admin/package.json']);
});

test('libraries: installed and built folders are not asked for lockfiles', () => {
  assert.deepEqual(coverageOf({ 'node_modules/x/package.json': pkg(), 'dist/package.json': pkg() }).unlocked, []);
  assert.deepEqual(coverageOf({ '.vercel/output/functions/a.func/package.json': pkg() }).unlocked, []);
  assert.deepEqual(coverageOf({ 'my.vercel-app/package.json': pkg() }).unlocked, ['my.vercel-app/package.json']);
});

test('libraries: a lockfile the scanner read nothing from is reported, and not also called untested', () => {
  const cov = { ...coverageOf({ 'yarn.lock': '' }), unread: ['yarn.lock'] };
  assert.equal(coverageGaps(cov).length, 1);
  assert.match(libraryGaps(cov)[0], /read no libraries from yarn\.lock.*\.gitignore/);
});

test('libraries: the scanner lists the files it read, and listing clean libraries adds no findings', () => {
  const root = join(tmpdir(), 'p');
  const json = { results: [
    { source: { path: join(root, 'api', 'package-lock.json') }, packages: [{ package: { name: 'a', version: '1', ecosystem: 'npm' } }] },
    { source: { path: join(root, 'empty.lock') }, packages: [] },
  ] };
  assert.deepEqual(osv.filesRead(json, { root }), ['api/package-lock.json']);
  assert.deepEqual(osv.filesRead({ results: [] }, { root }), []);
  assert.deepEqual(osv.parse(json, { root }), []);
  assert.ok(osv.args({ root }, 'o.json').includes('--all-packages'));
});

test('libraries: both reports say it at the top and never say plain "Nothing found by these tools"', () => {
  const cov = coverageOf({ 'package.json': pkg() });
  const result = { generator: 'ai-secure-audit 0', target: { git: false }, tools: [], notices: [], notes: [], findings: [],
    coverage: { ...cov, gaps: coverageGaps(cov) } };
  const simple = reportSimple(result, '2026-01-01');
  const top = simple.slice(0, simple.indexOf('## What was not checked'));
  assert.match(top, /Some libraries were not checked/);
  assert.doesNotMatch(simple, /That is good/);
  const full = reportMarkdown(result, '2026-01-01');
  assert.match(full.slice(0, full.indexOf('## What this check could not see')), /Some libraries were not checked/);
  const ok = { ...result, coverage: { gaps: [] } };
  assert.doesNotMatch(reportSimple(ok, '2026-01-01') + reportMarkdown(ok, '2026-01-01'), /libraries were not checked/);
});
