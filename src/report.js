import { countBySeverity } from './findings.js';

// Plain-language explanations, by finding category.
const PLAIN = {
  secret: {
    what: 'A password, API key or token is written in your code.',
    why: 'Anyone who can see the code (or its git history) can use it: spend your money, read your data, or act as you.',
  },
  dependency: {
    what: 'A library your app uses has a known security hole.',
    why: 'Attackers look for apps running versions with published holes, because the method is already public.',
  },
  config: {
    what: 'A setting in your Docker or infrastructure files is unsafe.',
    why: 'Unsafe defaults make a break-in easier or do more damage once someone is in.',
  },
  code: {
    what: 'Your code has a pattern that apps built with AI often get wrong.',
    why: 'These mistakes are easy to find from the outside, and a short script is enough to use them.',
  },
};

function where(f) {
  return f.evidence.map((e) => `\`${e.location}\``).join(', ');
}

function whereSentence(f) {
  return f.evidence.map((e) => {
    const commits = e.commits?.length ? ` (commit ${e.commits.join(', ')})` : '';
    if (e.history_only) {
      return `\`${e.location}\`. This key is no longer in the files of your project, but it is still in git history${commits}, ` +
        'so anyone with a copy of the repository can still read it';
    }
    if (e.not_committed) return `\`${e.location}\`. This is not in git yet, so you can still keep it out of your history`;
    if (e.built) return `\`${e.location}\`${commits}. This file is build output, the code that gets deployed`;
    return `\`${e.location}\`${commits}`;
  }).join('; ');
}

function whereNote(f) {
  if (f.evidence.some((e) => e.history_only)) return ' (git history only)';
  if (f.evidence.some((e) => e.not_committed)) return ' (not committed yet)';
  return f.evidence.some((e) => e.built) ? ' (build output)' : '';
}

export function reportMarkdown(result, date) {
  const { findings, tools, target } = result;
  const c = countBySeverity(findings);
  const lines = [];
  lines.push('# Security check');
  lines.push('');
  lines.push(`${result.generator} · basic check · ${date}` + (target.commit ? ` · commit \`${target.commit}\`` : ' · not a git repository') +
    (target.uncommitted_changes ? ' (with uncommitted changes)' : ''));
  lines.push('');
  lines.push('This is a self-check with free open-source tools. It is not a certification and does not prove the app is secure.');
  lines.push('');
  lines.push(`**${c.critical} critical · ${c.high} high · ${c.medium} medium · ${c.low} low**`);
  lines.push('');

  const failed = tools.filter((t) => t.status !== 'ok');
  if (failed.length) {
    lines.push('> **Some checks did not run:** ' + failed.map((t) => `${t.id} (${t.error})`).join('; '));
    lines.push('');
  }

  const top = findings.filter((f) => ['critical', 'high'].includes(f.severity.normalized)).slice(0, 5);
  if (top.length) {
    lines.push('## Fix these first');
    lines.push('');
    for (const f of top) {
      const p = PLAIN[f.category] ?? {};
      lines.push(`### ${f.id}: ${f.title}`);
      lines.push('');
      if (p.what) lines.push(`**What is wrong:** ${p.what} Found at ${whereSentence(f)}.`);
      if (p.why) lines.push(`**Why it matters:** ${p.why}`);
      if (f.fix) lines.push(`**How to fix it:** ${f.fix}`);
      lines.push('');
    }
  } else if (findings.length === 0 && !failed.length) {
    lines.push('No problems found by these tools. That does not cover the items under "What this check could not see".');
    lines.push('');
  }

  // Medium and low findings still need a fix written out, not only a row in the table.
  const rest = findings.filter((f) => !top.includes(f) && f.fix).slice(0, 10);
  if (rest.length) {
    lines.push(top.length ? '## Then check these' : '## Check these');
    lines.push('');
    for (const f of rest) {
      const p = PLAIN[f.category] ?? {};
      lines.push(`### ${f.id}: ${f.title}`);
      lines.push('');
      if (p.what) lines.push(`**What is wrong:** ${p.what} Found at ${whereSentence(f)}.`);
      if (f.category === 'code') lines.push('**Check first:** this comes from a code rule, which can be wrong. Look at the code before changing it.');
      lines.push(`**How to fix it:** ${f.fix}`);
      lines.push('');
    }
  }

  if (findings.length) {
    lines.push('## All findings');
    lines.push('');
    lines.push('| ID | Severity | Type | Problem | Where |');
    lines.push('|---|---|---|---|---|');
    for (const f of findings) {
      lines.push(`| ${f.id} | ${f.severity.normalized} | ${f.category} | ${f.title.replace(/\|/g, '\\|')} | ${where(f)}${whereNote(f)} |`);
    }
    lines.push('');
  }

  lines.push('## What this check could not see');
  lines.push('');
  lines.push('- Whether one user can open or change another user\'s data (for example by changing an id in the URL)');
  lines.push('- Business rules: prices, coupons, approvals, payments');
  lines.push('- Database rules such as Supabase row-level security or Firebase security rules (planned)');
  lines.push('- Anything about the live server or website');
  lines.push('- Docker/config mistakes: not in this version yet (coming in v0.3)');
  for (const g of result.coverage?.gaps ?? []) lines.push(`- ${g}`);
  lines.push('');
  lines.push('## Tools');
  lines.push('');
  lines.push('| Tool | Version | License | Result |');
  lines.push('|---|---|---|---|');
  for (const t of tools) lines.push(`| ${t.id} | ${t.version} | ${t.license} | ${t.status === 'ok' ? `${t.findings} findings` : `failed: ${t.error}`} |`);
  lines.push('');
  return lines.join('\n');
}

export function consoleSummary(result, outRel) {
  const c = countBySeverity(result.findings);
  const failed = result.tools.filter((t) => t.status !== 'ok');
  return [
    `${result.generator} · basic check` + (result.target.commit ? ` · commit ${result.target.commit}` : ''),
    `${c.critical} critical · ${c.high} high · ${c.medium} medium · ${c.low} low     report: ${outRel}/report.md`,
    ...failed.map((t) => `NOT RUN: ${t.id}: ${t.error}`),
    '',
    'For the AI assistant reading this:',
    `- Findings are in ${outRel}/findings.json. Do not add, remove or re-rate findings.`,
    '- Explain them to the user in plain language, most serious first.',
    '- Ask before changing code. Fix one finding at a time; run `npx ai-secure-audit retest` after.',
    '- Use each finding\'s fix field. A key that is in git or was deployed must be rotated at the provider: deleting it from the code is not enough.',
    '- A finding marked not_committed can be moved out of the code without rotating, unless the key was shared or pasted somewhere else.',
    '- Findings of type code come from pattern rules and can be wrong. Read the code at that location and tell the user',
    '  if a limit or check exists somewhere the rule cannot see (another file, the proxy) before changing anything.',
    '- Not checked: whether one user can reach another user\'s data, business rules, and (in this version)',
    '  Docker/config files. Say so.',
    ...(result.coverage?.gaps ?? []).map((g) => `- ${g} Tell the user.`),
    ...(failed.length ? ['- Some tools did not run (see NOT RUN above). Tell the user the check is incomplete.'] : []),
  ].join('\n');
}
