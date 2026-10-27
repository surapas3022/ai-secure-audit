import { countBySeverity } from './findings.js';

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
};

function where(f) {
  return f.evidence.map((e) => `\`${e.location}\``).join(', ');
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
      if (p.what) lines.push(`**What is wrong:** ${p.what} Found at ${where(f)}.`);
      if (p.why) lines.push(`**Why it matters:** ${p.why}`);
      if (f.fix) lines.push(`**How to fix it:** ${f.fix}`);
      lines.push('');
    }
  } else if (findings.length === 0 && !failed.length) {
    lines.push('No problems found by these tools. That does not cover the items under "What this check could not see".');
    lines.push('');
  }

  if (findings.length) {
    lines.push('## All findings');
    lines.push('');
    lines.push('| ID | Severity | Type | Problem | Where |');
    lines.push('|---|---|---|---|---|');
    for (const f of findings) {
      lines.push(`| ${f.id} | ${f.severity.normalized} | ${f.category} | ${f.title.replace(/\|/g, '\\|')} | ${where(f)} |`);
    }
    lines.push('');
  }

  lines.push('## What this check could not see');
  lines.push('');
  lines.push('- Whether one user can open or change another user\'s data (for example by changing an id in the URL)');
  lines.push('- Business rules: prices, coupons, approvals, payments');
  lines.push('- Database rules such as Supabase row-level security or Firebase security rules (planned)');
  lines.push('- Anything about the live server or website');
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
    '- A leaked secret must be rotated at the provider. Deleting it from the code is not enough.',
    '- Not checked: whether one user can reach another user\'s data, and business rules. Say so.',
    ...(failed.length ? ['- Some tools did not run (see NOT RUN above). Tell the user the check is incomplete.'] : []),
    '- For deeper review, see the skills: npx ai-secure-audit init',
  ].join('\n');
}
