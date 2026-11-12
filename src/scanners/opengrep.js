import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { rel } from '../paths.js';

// This kit's own rules, shipped in the package. Rules from the Semgrep Registry are not used: their license is not
// open source (see README).
const RULES = fileURLToPath(new URL('../../rules/', import.meta.url));

// Folders that hold installed or generated code, not code the project wrote.
const EXCLUDE = ['node_modules', '.git', '.audit', 'dist', 'build', '.next', '.nuxt', '.output', '.svelte-kit',
  'coverage', 'vendor'];

// Each rule has a test file beside it (same name, code extension) full of deliberate matches. Never scan those,
// or a project that contains this kit (this repository, a vendored copy) reports its own test cases.
const RULE_TESTS = readdirSync(RULES).filter((f) => !/\.ya?ml$/.test(f));

const SEVERITY = { ERROR: 'high', WARNING: 'medium', INFO: 'low' };

export default {
  id: 'opengrep',
  category: 'code',

  // Local rules only, no version check: nothing about the project leaves the machine.
  // --no-git-ignore: code that is not committed yet is still code that will run.
  args(ctx, out) {
    return ['scan', '--config', RULES, '--json', '--output', out, '--disable-version-check', '--quiet',
      '--no-git-ignore', ...[...EXCLUDE, ...RULE_TESTS].flatMap((d) => ['--exclude', d]), ctx.root];
  },

  okExit: [0],

  parse(json, ctx) {
    const findings = [];
    for (const r of json?.results ?? []) {
      // opengrep prefixes the rule id with the config path, joined by dots; our rule ids have no dots.
      const ruleId = r.check_id.split('.').at(-1);
      const location = `${rel(ctx.root, r.path)}:${r.start.line}`;
      const meta = r.extra?.metadata ?? {};
      const [title, ...rest] = (r.extra?.message ?? ruleId).split('. ');
      findings.push({
        fingerprint: `opengrep:${ruleId}:${location}`,
        category: 'code',
        title,
        severity: { tool: r.extra?.severity ?? 'WARNING', normalized: SEVERITY[r.extra?.severity] ?? 'medium' },
        source: { kind: 'tool', tool: 'opengrep', rule_id: ruleId },
        // Only the first line of the match: enough to find it, without copying the handler body.
        evidence: [{ location, detail: (r.extra?.lines ?? '').split('\n')[0].trim().slice(0, 160) }],
        fix: rest.join('. '),
        references: { cwe: meta.cwe ?? null, asvs: meta.asvs ?? null, confidence: meta.confidence ?? null },
      });
    }
    return findings;
  },
};
