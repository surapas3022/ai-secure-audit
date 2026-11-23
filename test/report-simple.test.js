import { test } from 'node:test';
import assert from 'node:assert/strict';
import { reportSimple } from '../src/report-simple.js';

const base = { tools: [{ id: 'x', status: 'ok' }], coverage: { gaps: ['Gap one.'] } };
const f = (category, level, extra = {}) => ({
  id: 'AUD-001', category, title: `rule-${category}-id`, severity: { normalized: level },
  evidence: [{ location: 'a.js:1', commits: ['abc1234'], ...extra }], fix: 'Do the fix.', ...extra.top,
});

test('no findings: says nothing found and still lists what was not checked', () => {
  const r = reportSimple({ ...base, findings: [] }, '2026-01-01');
  assert.match(r, /Nothing found/);
  assert.match(r, /What was not checked/);
  assert.match(r, /Gap one\./);
});

test('plain words: no rule ids, commit hashes or CWE in the text', () => {
  const r = reportSimple({ ...base, findings: [f('secret', 'high', { history_only: true })] }, '2026-01-01');
  assert.doesNotMatch(r, /rule-secret-id|abc1234|CWE/);
  assert.match(r, /still in your git history/);
});

test('urgency groups come in order: today, this week, later', () => {
  const r = reportSimple({ ...base, findings: [f('code', 'low'), f('config', 'medium'), f('secret', 'critical')] }, '2026-01-01');
  assert.ok(r.indexOf('Do these today') < r.indexOf('Do these this week'));
  assert.ok(r.indexOf('Do these this week') < r.indexOf('When you have time'));
});

test('a failed tool is never reported as a clean pass', () => {
  const r = reportSimple({ ...base, tools: [{ id: 'x', status: 'failed' }], findings: [] }, '2026-01-01');
  assert.match(r, /check is incomplete/);
  assert.doesNotMatch(r, /Nothing found by these tools/);
});

test('code findings tell the reader to look first; only 10 get full detail', () => {
  const many = Array.from({ length: 12 }, () => f('code', 'high'));
  const r = reportSimple({ ...base, findings: many }, '2026-01-01');
  assert.match(r, /Look first/);
  assert.equal((r.match(/\*\*What to do:\*\*/g) ?? []).length, 10);
  assert.match(r, /### 12\./);
});

test('same library with several advisories becomes one item with the count and every fix', () => {
  const dep = (adv, fix) => ({
    id: 'AUD-00' + adv, category: 'dependency', title: `multer 1.4.5: advisory ${adv}`,
    severity: { normalized: adv === 2 ? 'high' : 'medium' }, evidence: [{ location: 'package-lock.json' }], fix,
  });
  const r = reportSimple({ ...base, findings: [dep(1, 'Upgrade multer to 2.0.0.'), dep(2, 'Upgrade multer to 2.0.0.'), dep(3, 'Upgrade multer to 2.1.0.')] }, '2026-01-01');
  assert.equal((r.match(/^### /gm) ?? []).length, 1);
  assert.match(r, /The library multer 1\.4\.5 has 3 known security holes/);
  assert.match(r, /Do these today/); // highest severity of the group wins
  assert.match(r, /2\.0\.0\. Also: Upgrade multer to 2\.1\.0\./);
  assert.match(r, /\*\*1 thing to fix/);
});
