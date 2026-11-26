import { countBySeverity } from './findings.js';
import { NO_LIBRARY_CHECK } from './coverage.js';

// Plain report for someone who does not know security words.
// Rules: no tool names, no commit hashes, no CWE ids, no severity jargon.
// Every item says what is wrong, where, and what to do, in that order.

const WHAT = {
  secret: 'A password or key is written in your code.',
  dependency: 'A library your app uses has a known security hole.',
  config: 'A setting in your Docker or server files is unsafe.',
  code: 'Your code has a pattern that apps built with AI often get wrong.',
};

const HEAD = {
  secret: 'A password or key is in your code',
  dependency: 'A library has a known security hole',
  config: 'An unsafe setting in your Docker or server files',
  code: 'A risky pattern in your code',
};

const GROUPS = [
  { title: 'Do these today', levels: ['critical', 'high'] },
  { title: 'Do these this week', levels: ['medium'] },
  { title: 'When you have time', levels: ['low'] },
];

const MAX_DETAILED = 10;

// One line per library, not one per advisory: a non-expert cannot act on 13 lines that all say "multer".
function mergeDependencies(findings) {
  const order = ['critical', 'high', 'medium', 'low'];
  const out = [];
  const byPkg = new Map();
  for (const f of findings) {
    const pkg = f.category === 'dependency' ? /^(\S+ \S+):/.exec(f.title)?.[1] : null;
    if (!pkg) { out.push(f); continue; }
    const key = `${pkg}|${f.evidence[0]?.location}`;
    const m = byPkg.get(key);
    if (!m) { const g = { ...f, pkg, count: 1, fixes: new Set(f.fix ? [f.fix] : []) }; byPkg.set(key, g); out.push(g); continue; }
    m.count++;
    if (f.fix) m.fixes.add(f.fix);
    if (order.indexOf(f.severity.normalized) < order.indexOf(m.severity.normalized)) m.severity = f.severity;
  }
  return out;
}

function place(f) {
  const e = f.evidence[0];
  if (!e) return '';
  const more = f.evidence.length > 1 ? ` (and ${f.evidence.length - 1} more place${f.evidence.length > 2 ? 's' : ''})` : '';
  let note = '';
  if (e.history_only) note = ' It is no longer in your files, but it is still in your git history, so anyone with a copy of the project can read it.';
  else if (e.not_committed) note = ' It is not in git yet, so you can still keep it out.';
  return `In \`${e.location}\`${more}.${note}`;
}

export function reportSimple(result, date) {
  const findings = mergeDependencies(result.findings);
  const c = countBySeverity(findings);
  const failed = result.tools.filter((t) => t.status !== 'ok');
  const lines = ['# Your security to-do list', ''];
  lines.push(`Checked on ${date}. This is a self-check with free tools. It is not a certification and does not prove your app is safe.`, '');

  if (failed.length) {
    lines.push('> **The check is incomplete:** some parts did not run. Do not treat "nothing found" as safe until they do.', '');
  }

  const noLibraries = result.coverage?.gaps?.some((g) => g.startsWith(NO_LIBRARY_CHECK));
  if (noLibraries) {
    lines.push('> **Some libraries were not checked.** See "What was not checked" below.', '');
  }

  const total = c.critical + c.high + c.medium + c.low;
  if (total === 0) {
    lines.push(failed.length || noLibraries ? 'Nothing found by the parts that ran.' : '**Nothing found by these tools.** That is good, but read "What was not checked" below.', '');
  } else {
    lines.push(`**${total} thing${total === 1 ? '' : 's'} to fix.** Start at number 1 and work down. After each fix, run \`npx ai-secure-audit retest\` to see it disappear from the list.`, '');
  }

  let n = 0;
  for (const g of GROUPS) {
    const items = findings.filter((f) => g.levels.includes(f.severity.normalized));
    if (!items.length) continue;
    lines.push(`## ${g.title}`, '');
    for (const f of items) {
      n++;
      lines.push(`### ${n}. ${f.pkg ? `The library ${f.pkg} has ${f.count} known security hole${f.count === 1 ? '' : 's'}` : (HEAD[f.category] ?? f.title)}`, '');
      if (n <= MAX_DETAILED) {
        lines.push(`**What is wrong:** ${WHAT[f.category] ?? f.title}`, '');
        lines.push(`**Where:** ${place(f)}`, '');
        const fix = f.fixes ? [...f.fixes].join(' Also: ') : f.fix;
        if (fix) lines.push(`**What to do:** ${fix}`, '');
        if (f.category === 'code') lines.push('**Look first:** this comes from a pattern rule and can be wrong. Read the code before you change it.', '');
      } else {
        lines.push(`**Where:** ${place(f)}`, '');
        lines.push('The full report (`report.md`) has the fix for this one.');
      }
      lines.push('');
    }
  }

  lines.push('## What was not checked', '');
  lines.push('These tools cannot see the following, so "nothing found" does not cover them:', '');
  lines.push('- Whether one user can open or change another user\'s data');
  lines.push('- Rules of your business: prices, coupons, payments, approvals');
  lines.push('- How signing in, signing up and resetting a password work, for example whether someone can make themselves an admin when signing up, or guess the answer to a reset question');
  lines.push('- Anything about your live website or server');
  for (const g of result.coverage?.gaps ?? []) lines.push(`- ${g}`);
  lines.push('');
  return lines.join('\n');
}
