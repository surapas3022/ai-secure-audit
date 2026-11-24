import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { committedUnchanged } from '../src/scan.js';

// Real git, not a stub: this is the part that decides "committed" or "not committed yet".
function repo() {
  const dir = mkdtempSync(join(tmpdir(), 'asa-git-'));
  const git = (...a) => { const r = spawnSync('git', ['-C', dir, '-c', 'user.email=t@t.t', '-c', 'user.name=t', '-c', 'commit.gpgsign=false', ...a], { encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); };
  git('init', '-q', '-b', 'main');
  return { dir, git, write: (f, t) => { mkdirSync(join(dir, f, '..'), { recursive: true }); writeFileSync(join(dir, f), t); } };
}

test('tracked and unchanged is committed; edited, new and untracked files are not', () => {
  const { dir, git, write } = repo();
  write('a.js', 'one\n'); git('add', '.'); git('commit', '-qm', 'one');
  assert.equal(committedUnchanged(dir, 'a.js'), true);
  write('a.js', 'two\n');
  assert.equal(committedUnchanged(dir, 'a.js'), false, 'edited after the commit');
  write('b.js', 'x\n');
  assert.equal(committedUnchanged(dir, 'b.js'), false, 'untracked');
  git('add', 'b.js');
  assert.equal(committedUnchanged(dir, 'b.js'), false, 'staged but not committed');
});

test('a file moved with git mv and committed is committed at its new path', () => {
  const { dir, git, write } = repo();
  write('leak.js', 'k\n'); git('add', '.'); git('commit', '-qm', 'one');
  mkdirSync(join(dir, 'app')); git('mv', 'leak.js', 'app/leak.js'); git('commit', '-qm', 'move');
  assert.equal(committedUnchanged(dir, 'app/leak.js'), true);
  assert.equal(committedUnchanged(dir, 'leak.js'), false, 'the old path no longer exists');
});

test('works from a sub-folder of a repository (the scanned folder is not the repo root)', () => {
  const { dir, git, write } = repo();
  write('apps/one/c.js', 'k\n'); git('add', '.'); git('commit', '-qm', 'one');
  assert.equal(committedUnchanged(join(dir, 'apps', 'one'), 'c.js'), true);
});

test('a file name is never read as a pattern: "*.js" and ":(exclude)x" do not match other files', () => {
  const { dir, git, write } = repo();
  write('real.js', 'k\n'); git('add', '.'); git('commit', '-qm', 'one');
  write('untracked-star.txt', 'u\n');
  assert.equal(committedUnchanged(dir, '*.js'), false, 'a glob must not match real.js');
  assert.equal(committedUnchanged(dir, ':(top)real.js'), false, 'pathspec magic must not match real.js');
  assert.equal(committedUnchanged(dir, '*'), false);
});

test('outside a git repository nothing is "committed"', () => {
  const dir = mkdtempSync(join(tmpdir(), 'asa-nogit-'));
  writeFileSync(join(dir, 'a.js'), 'x');
  assert.equal(committedUnchanged(dir, 'a.js'), false);
});
