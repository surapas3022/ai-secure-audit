import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { copiesWholeFolder, dockerignoreNotices, isExcluded, parseDockerignore } from '../src/dockerignore.js';

// Answer key: Docker 29.3.1 (BuildKit), FROM scratch + COPY . / exported with -o type=local, 18/11/2026.
// true = .audit/out/findings.json was NOT in the image.
const DOCKER = [
  ['.audit', true], ['.audit/', true], ['/.audit', true], ['.audit/**', true], ['**/.audit', true], ['.*', true],
  ['*\n!src', true], ['.audit/out', true], ['.audit\n!.audit/out/findings.json', false], ['audit', false],
  ['.audit*', true], ['# .audit', false], ['  .audit  ', true], ['./.audit', true], ['.audit/*', true],
];

test('matches what a real Docker build excluded for 15 .dockerignore files', () => {
  for (const [text, out] of DOCKER) {
    assert.equal(isExcluded(parseDockerignore(text), '.audit/out/findings.json'), out, JSON.stringify(text));
  }
});

test('finds COPY or ADD of the whole folder, not named files or other stages', () => {
  for (const df of ['COPY . .', 'COPY ./ /app/', 'ADD . /app', 'COPY --chown=1000:1000 . .', 'COPY ["." , "/app"]',
    'copy . .', 'COPY package.json \\\n  . ./', 'COPY * ./']) assert.equal(copiesWholeFolder(`FROM node\n${df}\n`), true, df);
  for (const df of ['COPY package.json ./', 'COPY src/ ./src/', 'COPY --from=build . /app', 'RUN cp . /x', '# COPY . .'])
    assert.equal(copiesWholeFolder(`FROM node\n${df}\n`), false, df);
});

function project(files) {
  const dir = mkdtempSync(join(tmpdir(), 'asa-dockerignore-'));
  for (const [f, text] of Object.entries(files)) { mkdirSync(join(dir, f, '..'), { recursive: true }); writeFileSync(join(dir, f), text); }
  return dir;
}

test('notices: no .dockerignore, one that misses .audit, one that has it, named copies only, Dockerfile.dockerignore', () => {
  const cases = [
    [{ Dockerfile: 'FROM node\nCOPY . .\n' }, /there is no \.dockerignore/],
    [{ Dockerfile: 'FROM node\nCOPY . .\n', '.dockerignore': 'node_modules\n.env\n' }, /\.dockerignore does not exclude \.audit/],
    [{ Dockerfile: 'FROM node\nCOPY . .\n', '.dockerignore': 'node_modules\n.audit\n' }, null],
    [{ Dockerfile: 'FROM node\nCOPY package.json server.js ./\n' }, null],
    [{ Dockerfile: 'FROM node\nCOPY . .\n', '.dockerignore': '.audit\n', 'Dockerfile.dockerignore': '.env\n' }, /Dockerfile\.dockerignore does not exclude/],
    [{ 'api.Dockerfile': 'FROM node\nCOPY . .\n', '.dockerignore': '.git\n' }, /^api\.Dockerfile copies/],
    [{ 'sub/Dockerfile': 'FROM node\nCOPY . .\n' }, null],
  ];
  for (const [files, expect] of cases) {
    const dir = project(files);
    const n = dockerignoreNotices(dir);
    if (expect) { assert.equal(n.length, 1, JSON.stringify(files)); assert.match(n[0].message, expect); }
    else assert.deepEqual(n, [], JSON.stringify(files));
    rmSync(dir, { recursive: true, force: true });
  }
});
