import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { cacheDir, ensureTool, lockedTools } from './tools.js';
import { sortAndNumber } from './findings.js';
import gitleaks from './scanners/gitleaks.js';
import osv from './scanners/osv.js';
import trivy from './scanners/trivy.js';

export const BASIC_SCANNERS = [gitleaks, osv, trivy];

function git(root, args) {
  const r = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : null;
}

export function outDir(root) {
  return join(root, '.audit', 'out');
}

export async function scan(target, { log = () => {}, version }) {
  const root = resolve(target);
  if (!existsSync(root)) throw new Error(`folder not found: ${root}`);

  const out = outDir(root);
  const rawDir = join(out, 'raw');
  mkdirSync(rawDir, { recursive: true });
  // Results can describe real weaknesses: keep them out of git.
  writeFileSync(join(out, '.gitignore'), '*\n');

  const isGit = git(root, ['rev-parse', '--is-inside-work-tree']) === 'true';
  const ctx = {
    root,
    rawDir,
    cache: cacheDir(),
    isGit,
    commit: isGit ? git(root, ['rev-parse', '--short', 'HEAD']) : null,
    dirty: isGit ? git(root, ['status', '--porcelain']) !== '' : null,
  };

  const tools = lockedTools();
  const runs = [];
  let findings = [];
  for (const s of BASIC_SCANNERS) {
    const run = { id: s.id, version: tools[s.id].version, license: tools[s.id].license, status: 'ok' };
    runs.push(run);
    try {
      const bin = await ensureTool(s.id, log);
      const prep = s.prepare?.(ctx) ?? {};
      const rawFile = join(rawDir, `${s.id}.json`);
      log(`running ${s.id} ${run.version} ...`);
      const r = spawnSync(bin, s.args(ctx, rawFile, prep), {
        cwd: root,
        env: { ...process.env, ...(s.env?.(ctx) ?? {}) },
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
      });
      if (r.error) throw r.error;
      if (!s.okExit.includes(r.status)) {
        throw new Error(`exit code ${r.status}: ${(r.stderr || r.stdout || '').trim().split('\n').slice(-3).join(' ')}`);
      }
      const json = existsSync(rawFile) ? JSON.parse(readFileSync(rawFile, 'utf8') || 'null') : null;
      const found = s.parse(json, ctx).map((f) => ({ ...f, source: { ...f.source, tool_version: run.version } }));
      run.findings = found.length;
      findings = findings.concat(found);
    } catch (err) {
      run.status = 'failed';
      run.error = err.message;
    }
  }

  const result = {
    generator: `ai-secure-audit ${version}`,
    check: 'basic',
    target: { git: isGit, commit: ctx.commit, uncommitted_changes: ctx.dirty },
    tools: runs,
    notes: [
      'Vulnerability databases are updated daily, so dependency results can change without any code change.',
      'Not checked by this tool: whether one user can reach another user\'s data, business rules, and anything running on a server.',
    ],
    findings: sortAndNumber(findings),
  };
  writeFileSync(join(out, 'findings.json'), JSON.stringify(result, null, 2) + '\n');
  return { root, out, result };
}
