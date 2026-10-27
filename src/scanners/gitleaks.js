import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { rel } from '../paths.js';

const SKIP_PATHS = [
  '(^|/)node_modules/',
  '(^|/)\\.git/',
  '(^|/)(dist|build|\\.next|\\.nuxt|\\.output|\\.svelte-kit|coverage|vendor)/',
  '(^|/)\\.audit/out/',
];
// A local .env that is not in git is where secrets belong, so folder mode skips it.
// Git mode keeps it: a committed .env is exactly what we want to find.
const LOCAL_ENV = '(^|/)\\.env(\\.[^/]+)?$';

export default {
  id: 'gitleaks',
  category: 'secret',

  prepare(ctx) {
    const paths = ctx.isGit ? SKIP_PATHS : [...SKIP_PATHS, LOCAL_ENV];
    const config = [
      'title = "ai-secure-audit"',
      '[extend]',
      'useDefault = true',
      '[allowlist]',
      'description = "dependency, build and output folders"',
      `paths = [${paths.map((p) => `'''${p}'''`).join(', ')}]`,
      '',
    ].join('\n');
    const file = join(ctx.rawDir, 'gitleaks.toml');
    writeFileSync(file, config);
    return { config: file };
  },

  args(ctx, out, prep) {
    return [ctx.isGit ? 'git' : 'dir', '--config', prep.config, '--redact', '--no-banner', '--log-level', 'error',
      '--exit-code', '0', '--report-format', 'json', '--report-path', out, ctx.root];
  },

  okExit: [0],

  parse(json, ctx) {
    const groups = new Map();
    for (const leak of json ?? []) {
      const file = rel(ctx.root, leak.File);
      const key = `gitleaks:${leak.RuleID}:${file}:${leak.StartLine}`;
      const g = groups.get(key) ?? { leak, file, commits: new Set() };
      if (leak.Commit) g.commits.add(leak.Commit.slice(0, 7));
      groups.set(key, g);
    }
    const fileExists = ctx.fileExists ?? ((f) => existsSync(join(ctx.root, f)));
    return [...groups].map(([key, { leak, file, commits }]) => {
      const commitList = [...commits].sort();
      // A secret in a file that no longer exists is only in git history. Say so: people look for the file and
      // cannot find it, then think the tool is wrong.
      const historyOnly = ctx.isGit !== false && !fileExists(file);
      return {
      fingerprint: key,
      category: 'secret',
      title: `Secret in code: ${leak.RuleID}`,
      severity: { tool: 'none (gitleaks does not rate)', normalized: 'high' },
      source: { kind: 'tool', tool: 'gitleaks', rule_id: leak.RuleID },
      evidence: [{
        location: `${file}:${leak.StartLine}`,
        // Never copy Match, Secret, Author or Email: they hold the secret or personal data.
        detail: leak.Description,
        ...(commitList.length ? { commits: commitList } : {}),
        ...(historyOnly ? { history_only: true } : {}),
      }],
      fix: 'Revoke or rotate this key at the provider first. Then remove it from the code and load it from an ' +
        'environment variable on the server. Deleting it from the code is not enough: it stays in git history.',
      references: { cwe: ['CWE-798'] },
      };
    });
  },
};
