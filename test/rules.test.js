import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { ensureTool } from '../src/tools.js';
import opengrep from '../src/scanners/opengrep.js';

const RULES = fileURLToPath(new URL('../rules/', import.meta.url));

// Every rule's own test file (ruleid: / ok: comments) checked by the pinned opengrep, with the same taint flag the
// scanner passes, so a rule that only works with --taint-intrafile cannot pass here and fail in a real scan.
test('rules: every code rule passes its own test file with the pinned opengrep', async (t) => {
  let bin;
  try { bin = await ensureTool('opengrep'); } catch (e) { t.skip(`opengrep not available: ${e.message}`); return; }
  const flags = opengrep.args({ root: '.' }, 'o.json').filter((a) => a === '--taint-intrafile');
  assert.deepEqual(flags, ['--taint-intrafile'], 'the scanner passes --taint-intrafile');
  const r = spawnSync(bin, ['scan', '--test', '--disable-version-check', ...flags, RULES], { encoding: 'utf8', timeout: 300_000 });
  const out = `${r.stdout}\n${r.stderr}`;
  assert.equal(r.status, 0, out);
  assert.match(out, /All tests passed/, out);
});
