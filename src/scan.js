import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { cacheDir, ensureTool, lockedTools } from './tools.js';
import { sortAndNumber } from './findings.js';
import { coverageGaps, projectCoverage } from './coverage.js';
import { dockerignoreNotices } from './dockerignore.js';
import gitleaks from './scanners/gitleaks.js';
import osv from './scanners/osv.js';
import opengrep from './scanners/opengrep.js';
import trivy from './scanners/trivy.js';

// Scanners are released one at a time, each after passing its own tests (see CLAUDE.md).
// Scanners still in development are kept outside this repository until they pass.
export const BASIC_SCANNERS = [gitleaks, osv, opengrep, trivy];

function git(root, args) {
  const r = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : null;
}

// True when `file` is tracked and identical to HEAD. --literal-pathspecs: a file name from the scanned project is
// never read as a pattern (a file called "*.js" or ":(exclude)x" must not match other files).
export function committedUnchanged(root, file) {
  const g = (args) => spawnSync('git', ['--literal-pathspecs', '-C', root, ...args]).status === 0;
  return g(['ls-files', '--error-unmatch', '--', file]) && g(['diff', '--quiet', 'HEAD', '--', file]);
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
    prefix: isGit ? git(root, ['rev-parse', '--show-prefix']) ?? '' : '',
    // Tracked and identical to HEAD: the content is in git even when gitleaks saw no commit add it at this path
    // (a file moved with `git mv` shows up in history as a rename with no added lines).
    isCommitted: (file) => isGit && committedUnchanged(root, file),
    isIgnored: (file) => isGit && spawnSync('git', ['-C', root, 'check-ignore', '-q', '--', file]).status === 0,
  };

  const tools = lockedTools();
  const runs = [];
  let findings = [];
  let librariesRead = null; // stays null when the library scanner did not run: the report says that already
  for (const s of BASIC_SCANNERS) {
    const run = { id: s.id, version: tools[s.id].version, license: tools[s.id].license, status: 'ok' };
    runs.push(run);
    try {
      const bin = await ensureTool(s.id, log);
      const prep = s.prepare?.(ctx) ?? {};
      const defaultRaw = join(rawDir, `${s.id}.json`);
      const passes = s.passes ? s.passes(ctx, rawDir, prep) : [{ rawFile: defaultRaw, args: s.args(ctx, defaultRaw, prep) }];
      log(`running ${s.id} ${run.version} ...`);
      let json = null;
      for (const pass of passes) {
        const r = spawnSync(bin, pass.args, {
          cwd: root,
          env: { ...process.env, ...(s.env?.(ctx) ?? {}) },
          encoding: 'utf8',
          maxBuffer: 64 * 1024 * 1024,
        });
        if (r.error) throw r.error;
        if (!s.okExit.includes(r.status)) {
          throw new Error(`exit code ${r.status}: ${(r.stderr || r.stdout || '').trim().split('\n').slice(-3).join(' ')}`);
        }
        const data = existsSync(pass.rawFile) ? JSON.parse(readFileSync(pass.rawFile, 'utf8') || 'null') : null;
        json = pass.name ? [...(json ?? []), ...(data ?? []).map((item) => ({ ...item, pass: pass.name }))] : data;
      }
      if (s.filesRead) librariesRead = new Set(s.filesRead(json, ctx));
      const found = s.parse(json, ctx).map((f) => ({ ...f, source: { ...f.source, tool_version: run.version } }));
      run.findings = found.length;
      findings = findings.concat(found);
    } catch (err) {
      run.status = 'failed';
      run.error = err.message;
    }
  }

  const coverage = projectCoverage(root);
  coverage.unread = librariesRead ? coverage.lockfiles.map((l) => l.file).filter((f) => !librariesRead.has(f)) : [];
  const result = {
    generator: `ai-secure-audit ${version}`,
    check: 'basic',
    target: { git: isGit, commit: ctx.commit, uncommitted_changes: ctx.dirty },
    tools: runs,
    coverage: { ...coverage, gaps: coverageGaps(coverage) },
    // About this tool's own output, not a weakness of the app: kept apart from findings so it is never rated.
    notices: dockerignoreNotices(root),
    notes: [
      'Not checked by this tool: whether one user can reach another user\'s data, business rules, and anything running on a server.',
      'Code rules (category code) are this kit\'s own opengrep rules. They can be wrong: check the location before changing code.',
      'Config files are checked by trivy: Dockerfiles, Kubernetes, Helm, Terraform, CloudFormation, Azure ARM and Ansible files. ' +
        'trivy does not read Docker Compose files; coverage.gaps names any that were not checked.',
    ],
    findings: sortAndNumber(findings),
  };
  writeFileSync(join(out, 'findings.json'), JSON.stringify(result, null, 2) + '\n');
  return { root, out, result };
}
