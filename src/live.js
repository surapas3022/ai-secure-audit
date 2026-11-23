import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { ensureFolderTool, liveTools } from './tools.js';
import { sortAndNumber, countBySeverity } from './findings.js';
import { loadTargets, resolveTarget } from './targets.js';
import { parseTestssl, testsslArgs } from './live/testssl.js';

// `live` checks one host from the targets file. It is a different kind of check from `scan`:
// it talks to a server, so it only runs against a host the owner listed, and production needs --allow-prod.

function need(cmd, args) {
  const r = spawnSync(cmd, args, { encoding: 'utf8' });
  return !r.error && r.status === 0;
}

export async function live(arg, { targetsFile, allowProd, log = () => {}, version, cwd = process.cwd() }) {
  const target = resolveTarget(arg, loadTargets(resolve(cwd, targetsFile)), { allowProd });
  const { host, port } = target;
  const lock = liveTools().testssl;

  const out = join(cwd, '.audit', 'out', 'live', `${host}-${port}`);
  mkdirSync(out, { recursive: true });
  writeFileSync(join(cwd, '.audit', 'out', '.gitignore'), '*\n');
  const rawFile = join(out, 'testssl.json');
  rmSync(rawFile, { force: true });

  const run = { id: 'testssl', version: lock.version, license: lock.license, status: 'ok' };
  let findings = [];
  let notices = [];
  try {
    if (process.platform === 'win32') throw new Error('not supported on Windows (it needs bash): use WSL or Docker');
    if (!need('bash', ['--version'])) throw new Error('bash was not found');
    if (!need('openssl', ['version'])) throw new Error('openssl was not found');
    const script = await ensureFolderTool('testssl', log);
    log(`checking TLS on ${host}:${port} with testssl ${lock.version} (takes about 2 minutes) ...`);
    const r = spawnSync('bash', [script, ...testsslArgs(host, port, rawFile)], {
      encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 15 * 60 * 1000,
    });
    if (r.error) throw r.error;
    if (!existsSync(rawFile)) throw new Error(`testssl wrote no result: ${(r.stdout || r.stderr || '').trim().split('\n').slice(-2).join(' ')}`);
    const parsed = parseTestssl(JSON.parse(readFileSync(rawFile, 'utf8') || 'null'), { host, port });
    findings = parsed.findings.map((f) => ({ ...f, source: { ...f.source, tool_version: lock.version } }));
    notices = parsed.notices;
    run.findings = findings.length;
  } catch (err) {
    run.status = 'failed';
    run.error = err.message;
  }

  const result = {
    generator: `ai-secure-audit ${version}`,
    check: 'live-tls',
    target: { host, port, env: target.env },
    tools: [run],
    notices,
    notes: [
      'This checked only the TLS of this one host and port: protocols, ciphers, the certificate, HSTS and known TLS weaknesses.',
      'Not checked: the app itself (login, access control, input handling), HTTP security headers other than HSTS, cookies, other hosts and ports.',
    ],
    findings: sortAndNumber(findings),
  };
  writeFileSync(join(out, 'findings.json'), JSON.stringify(result, null, 2) + '\n');
  writeFileSync(join(out, 'report.md'), liveReport(result, new Date().toISOString().slice(0, 10)));
  return { out, result };
}

export function liveReport(result, date) {
  const { findings, tools, target, notices } = result;
  const c = countBySeverity(findings);
  const L = [`# TLS check: ${target.host}:${target.port}`, ''];
  L.push(`${result.generator} · live TLS check · ${date} · ${target.env}`, '');
  L.push('This is a self-check with a free open-source tool. It is not a certification and does not prove the site is secure.', '');
  const failed = tools.filter((t) => t.status !== 'ok');
  if (failed.length) {
    L.push('> **The check did not run:** ' + failed.map((t) => `${t.id} (${t.error})`).join('; '), '');
    L.push('Do not read this as "no problems".', '');
  } else {
    L.push(`**${c.critical} critical · ${c.high} high · ${c.medium} medium · ${c.low} low**`, '');
    if (!findings.length) L.push('No TLS problems found by this tool. That does not cover what is listed under "What this check did not see".', '');
  }
  for (const f of findings) {
    L.push(`### ${f.id}: ${f.title} (${f.severity.normalized})`, '');
    L.push(`**What testssl saw:** ${f.evidence[0].detail}`, '');
    L.push(`**How to fix it:** ${f.fix}`, '');
  }
  if (notices?.length) {
    L.push('## Tests that could not run', '');
    for (const n of notices) L.push(`- ${n.message}`);
    L.push('');
  }
  L.push('## What this check did not see', '');
  for (const n of result.notes) L.push(`- ${n}`);
  L.push('', '## Tool', '', '| Tool | Version | License | Result |', '|---|---|---|---|');
  for (const t of tools) L.push(`| ${t.id} | ${t.version} | ${t.license} | ${t.status === 'ok' ? `${t.findings} findings` : `failed: ${t.error}`} |`);
  L.push('');
  return L.join('\n');
}

export function liveSummary(result, outRel) {
  const c = countBySeverity(result.findings);
  const failed = result.tools.filter((t) => t.status !== 'ok');
  return [
    `${result.generator} · live TLS check · ${result.target.host}:${result.target.port}`,
    `${c.critical} critical · ${c.high} high · ${c.medium} medium · ${c.low} low     report: ${outRel}/report.md`,
    ...failed.map((t) => `NOT RUN: ${t.id}: ${t.error}`),
    ...(result.notices ?? []).map((n) => `NOTE: ${n.message}`),
    '',
    'For the AI assistant reading this:',
    `- Findings are in ${outRel}/findings.json. Do not add, remove or re-rate findings.`,
    '- Explain them in plain language, most serious first. Ask before changing any server or proxy setting.',
    '- This checked only TLS on this host and port. Say so, and say what was not checked (the app, headers other than HSTS, cookies).',
    '- Never run this against a host the user did not list in targets.yml, and never against production without --allow-prod.',
    ...(failed.length ? ['- The check did not run. Tell the user it is incomplete; do not report it as clean.'] : []),
  ].join('\n');
}
