import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { ensureFolderTool, liveTools } from './tools.js';
import { sortAndNumber, countBySeverity } from './findings.js';
import { loadTargets, resolveTarget } from './targets.js';
import { parseTestssl, testsslArgs } from './live/testssl.js';
import { parseZap, zapDockerArgs, zapUrl, ZAP_NOT_CHECKED } from './live/zap.js';

// `live` checks one host from the targets file. It is a different kind of check from `scan`:
// it talks to a server, so it only runs against a host the owner listed, and production needs --allow-prod.
// Each step ends as ok, skipped (does not apply, said so) or failed (did not run: never read as a pass).

function ok(cmd, args) {
  const r = spawnSync(cmd, args, { encoding: 'utf8' });
  return !r.error && r.status === 0;
}

async function tlsStep({ target, out, log }) {
  const { host, port } = target;
  const lock = liveTools().testssl;
  if (process.platform === 'win32') throw new Error('not supported on Windows (it needs bash): use WSL or Docker');
  if (!ok('bash', ['--version'])) throw new Error('bash was not found');
  if (!ok('openssl', ['version'])) throw new Error('openssl was not found');
  const script = await ensureFolderTool('testssl', log);
  const rawFile = join(out, 'testssl.json');
  rmSync(rawFile, { force: true });
  log(`checking TLS on ${host}:${port} with testssl ${lock.version} (about 2 minutes) ...`);
  const r = spawnSync('bash', [script, ...testsslArgs(host, port, rawFile)], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 15 * 60 * 1000 });
  if (r.error) throw r.error;
  if (!existsSync(rawFile)) throw new Error(`testssl wrote no result: ${(r.stdout || r.stderr || '').trim().split('\n').slice(-2).join(' ')}`);
  return parseTestssl(JSON.parse(readFileSync(rawFile, 'utf8') || 'null'), { host, port });
}

function zapStep({ target, out, log }) {
  const lock = liveTools().zap;
  if (!ok('docker', ['version', '--format', '{{.Server.Version}}'])) throw new Error('Docker is not installed or not running');
  const url = zapUrl(target);
  // The container writes its report here as a different user, so the folder must be writable by anyone.
  const dir = join(out, 'zap');
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  chmodSync(dir, 0o777);
  log(`checking ${url} with ZAP ${lock.version} baseline in Docker (about 1 to 2 minutes; the first time it downloads the image) ...`);
  const r = spawnSync('docker', zapDockerArgs({ image: lock.image, dir, url }), { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 15 * 60 * 1000 });
  if (r.error) throw r.error;
  const rawFile = join(dir, 'report.json');
  if (!existsSync(rawFile)) throw new Error(`ZAP wrote no result: ${(r.stdout || r.stderr || '').trim().split('\n').slice(-2).join(' ')}`);
  return parseZap(JSON.parse(readFileSync(rawFile, 'utf8') || 'null'), { url });
}

export async function live(arg, { targetsFile, allowProd, zap = false, log = () => {}, version, cwd = process.cwd() }) {
  const target = resolveTarget(arg, loadTargets(resolve(cwd, targetsFile)), { allowProd });
  const { host, port } = target;
  if (target.scheme === 'http' && !zap) {
    throw new Error(`${host}:${port} is plain http, so there is no TLS to check. Add --zap to check the web site itself.`);
  }

  const out = join(cwd, '.audit', 'out', 'live', `${host}-${port}`);
  mkdirSync(out, { recursive: true });
  writeFileSync(join(cwd, '.audit', 'out', '.gitignore'), '*\n');

  const steps = [];
  if (target.scheme === 'https') steps.push({ id: 'testssl', run: tlsStep, tool: liveTools().testssl });
  else steps.push({ id: 'testssl', skip: 'plain http: there is no TLS to check', tool: liveTools().testssl });
  if (zap) steps.push({ id: 'zap-baseline', run: zapStep, tool: liveTools().zap });

  const runs = [];
  let findings = [];
  let notices = [];
  for (const s of steps) {
    const run = { id: s.id, version: s.tool.version, license: s.tool.license, status: 'ok' };
    runs.push(run);
    if (s.skip) { run.status = 'skipped'; run.note = s.skip; continue; }
    try {
      const parsed = await s.run({ target, out, log });
      const found = parsed.findings.map((f) => ({ ...f, source: { ...f.source, tool_version: s.tool.version } }));
      findings = findings.concat(found);
      notices = notices.concat(parsed.notices);
      run.findings = found.length;
    } catch (err) {
      run.status = 'failed';
      run.error = err.message;
    }
  }

  const notes = [];
  if (steps.some((s) => s.id === 'testssl' && !s.skip)) {
    notes.push('TLS check: only this one host and port: protocols, ciphers, the certificate, HSTS and known TLS weaknesses.');
  }
  if (zap) notes.push(`Web check: ${ZAP_NOT_CHECKED} It also trusts what the server says about itself (a made-up Server header is believed).`);
  notes.push('Not checked: the app\'s own logic (who may see or change what), other hosts and ports.');

  const result = {
    generator: `ai-secure-audit ${version}`,
    check: zap ? 'live-tls-web' : 'live-tls',
    target: { host, port, scheme: target.scheme, env: target.env },
    tools: runs,
    notices,
    notes,
    findings: sortAndNumber(findings),
  };
  writeFileSync(join(out, 'findings.json'), JSON.stringify(result, null, 2) + '\n');
  writeFileSync(join(out, 'report.md'), liveReport(result, new Date().toISOString().slice(0, 10)));
  return { out, result };
}

export function liveReport(result, date) {
  const { findings, tools, target, notices } = result;
  const c = countBySeverity(findings);
  const L = [`# Live check: ${target.host}:${target.port}`, ''];
  L.push(`${result.generator} · ${result.check} · ${date} · ${target.env}`, '');
  L.push('This is a self-check with free open-source tools. It is not a certification and does not prove the site is secure.', '');
  const failed = tools.filter((t) => t.status === 'failed');
  if (failed.length) {
    L.push('> **Some checks did not run:** ' + failed.map((t) => `${t.id} (${t.error})`).join('; '), '');
    L.push('Do not read this as "no problems" for the parts that did not run.', '');
  }
  L.push(`**${c.critical} critical · ${c.high} high · ${c.medium} medium · ${c.low} low**`, '');
  if (!findings.length && !failed.length) L.push('No problems found by these tools. That does not cover what is listed under "What this check did not see".', '');
  for (const f of findings) {
    L.push(`### ${f.id}: ${f.title} (${f.severity.normalized})`, '');
    L.push(`**Found by:** ${f.category === 'web' ? 'ZAP baseline (web)' : 'testssl (TLS)'}`, '');
    L.push(`**Where / what was seen:** ${f.evidence.map((e) => `\`${e.location}\`${e.detail ? ` (${e.detail})` : ''}`).join('; ')}`, '');
    L.push(`**How to fix it:** ${f.fix}`, '');
  }
  if (notices?.length) {
    L.push('## Tests that could not run', '');
    for (const n of notices) L.push(`- ${n.message}`);
    L.push('');
  }
  L.push('## What this check did not see', '');
  for (const n of result.notes) L.push(`- ${n}`);
  L.push('', '## Tools', '', '| Tool | Version | License | Result |', '|---|---|---|---|');
  for (const t of tools) {
    const res = t.status === 'ok' ? `${t.findings} findings` : t.status === 'skipped' ? `skipped: ${t.note}` : `did not run: ${t.error}`;
    L.push(`| ${t.id} | ${t.version} | ${t.license} | ${res} |`);
  }
  L.push('');
  return L.join('\n');
}

export function liveSummary(result, outRel) {
  const c = countBySeverity(result.findings);
  const failed = result.tools.filter((t) => t.status === 'failed');
  return [
    `${result.generator} · ${result.check} · ${result.target.host}:${result.target.port}`,
    `${c.critical} critical · ${c.high} high · ${c.medium} medium · ${c.low} low     report: ${outRel}/report.md`,
    ...result.tools.filter((t) => t.status === 'skipped').map((t) => `SKIPPED: ${t.id}: ${t.note}`),
    ...failed.map((t) => `NOT RUN: ${t.id}: ${t.error}`),
    ...(result.notices ?? []).map((n) => `NOTE: ${n.message}`),
    '',
    'For the AI assistant reading this:',
    `- Findings are in ${outRel}/findings.json. Do not add, remove or re-rate findings.`,
    '- Explain them in plain language, most serious first. Ask before changing any server, proxy or app setting.',
    ...result.notes.map((n) => `- ${n} Say so.`),
    '- Never run this against a host the user did not list in targets.yml, and never against production without --allow-prod.',
    '- Never run ZAP\'s active or full scan against anything: this tool does not, and you should not add it.',
    ...(failed.length ? ['- Some checks did not run. Tell the user the check is incomplete; do not report it as clean.'] : []),
  ].join('\n');
}
