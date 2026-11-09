import { existsSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { rel } from '../paths.js';

const SKIP_PATHS = [
  '(^|/)node_modules/',
  '(^|/)\\.git/',
  '(^|/)(coverage|vendor)/',
  '(^|/)\\.audit/out/',
];
// Outside git there is no .gitignore to ask, and a local .env is where secrets belong.
const LOCAL_ENV = '(^|/)\\.env(\\.[^/]+)?$';

// The parts of framework output that are served to visitors.
const DEPLOYED_OUTPUT = /(^|\/)(\.next\/static|\.output\/public|\.svelte-kit\/output\/client)\//;
// The rest of framework output is server code, caches and manifests. On real builds this was all false alarms.
const INTERNAL_OUTPUT = /(^|\/)(\.next|\.nuxt|\.output|\.svelte-kit)\//;
const PLAIN_OUTPUT = /(^|\/)(dist|build)\//;

function fileKind(file) {
  if (DEPLOYED_OUTPUT.test(file)) return 'built';
  if (INTERNAL_OUTPUT.test(file)) return 'internal';
  return PLAIN_OUTPUT.test(file) ? 'built' : 'source';
}

const FIX = {
  committed: 'Revoke or rotate this key at the provider first. Then remove it from the code and load it from an ' +
    'environment variable on the server. Deleting it from the code is not enough: it stays in git history.',
  notCommitted: 'Move this key out of the code before you commit: load it from an environment variable on the ' +
    'server, and keep the file that holds it in .gitignore. If the key was ever shared or pasted anywhere else, ' +
    'rotate it at the provider too.',
  built: 'This is build output, which is what gets deployed, and on a website it is sent to every visitor. Rotate ' +
    'this key at the provider, keep it on the server only (call the provider from your backend), then rebuild.',
};
const MAYBE_FALSE_ALARM = 'This may be a false alarm: minified code often looks like a key, so check the value first. If it is a real key: ';

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
      'description = "dependency and output folders"',
      `paths = [${paths.map((p) => `'''${p}'''`).join(', ')}]`,
      '',
    ].join('\n');
    const file = join(ctx.rawDir, 'gitleaks.toml');
    writeFileSync(file, config);
    return { config: file };
  },

  // gitleaks' git mode reads commits only, so a key that is not committed yet needs a second pass over the files.
  passes(ctx, rawDir, prep) {
    const pass = (name, mode, extra = []) => {
      const rawFile = join(rawDir, `gitleaks-${name}.json`);
      return {
        name,
        rawFile,
        args: [mode, '--config', prep.config, '--redact', '--no-banner', '--log-level', 'error', '--exit-code', '0',
          '--report-format', 'json', '--report-path', rawFile, ...extra, ctx.root],
      };
    };
    const files = pass('files', 'dir', ['--max-target-megabytes', '20']);
    return ctx.isGit && ctx.commit ? [pass('history', 'git'), files] : [files];
  },

  okExit: [0],

  parse(json, ctx) {
    const prefix = ctx.prefix ?? '';
    const groups = new Map();
    for (const leak of json ?? []) {
      const fromFiles = leak.pass === 'files';
      let file = rel(ctx.root, leak.File);
      if (!fromFiles && prefix) {
        // History is reported from the top of the repository, which may be above the scanned folder.
        if (!file.startsWith(prefix)) continue;
        file = file.slice(prefix.length);
      }
      const kind = fileKind(file);
      if (kind === 'internal') continue;
      // A file git ignores stays on this machine. Build output is the exception: it gets deployed.
      if (fromFiles && kind === 'source' && ctx.isIgnored?.(file)) continue;
      const key = `gitleaks:${leak.RuleID}:${file}:${leak.StartLine}`;
      const g = groups.get(key) ?? { leak, file, kind, commits: new Set(), inHistory: false };
      if (!fromFiles) g.inHistory = true;
      if (leak.Commit) g.commits.add(leak.Commit.slice(0, 7));
      groups.set(key, g);
    }
    const fileExists = ctx.fileExists ?? ((f) => existsSync(join(ctx.root, f)));
    return [...groups].map(([key, { leak, file, kind, commits, inHistory }]) => {
      const commitList = [...commits].sort();
      // A secret in a file that no longer exists is only in git history. Say so: people look for the file and
      // cannot find it, then think the tool is wrong.
      const historyOnly = ctx.isGit !== false && !fileExists(file);
      const built = kind === 'built';
      const notCommitted = Boolean(ctx.isGit) && !inHistory && !built;
      const guess = built && leak.RuleID === 'generic-api-key';
      const fix = built ? FIX.built : notCommitted ? FIX.notCommitted : FIX.committed;
      return {
      fingerprint: key,
      category: 'secret',
      title: `Secret in code: ${leak.RuleID}`,
      severity: { tool: 'none (gitleaks does not rate)', normalized: guess ? 'medium' : 'high' },
      source: { kind: 'tool', tool: 'gitleaks', rule_id: leak.RuleID },
      evidence: [{
        location: `${file}:${leak.StartLine}`,
        // Never copy Match, Secret, Author or Email: they hold the secret or personal data.
        detail: leak.Description,
        ...(commitList.length ? { commits: commitList } : {}),
        ...(historyOnly ? { history_only: true } : {}),
        ...(notCommitted ? { not_committed: true } : {}),
        ...(built ? { built: true } : {}),
      }],
      fix: guess ? MAYBE_FALSE_ALARM + fix : fix,
      references: { cwe: ['CWE-798'] },
      };
    });
  },
};
