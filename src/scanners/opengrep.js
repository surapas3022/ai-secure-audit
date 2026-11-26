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
  // --taint-intrafile: follow a request value into a helper function in the same file (sql-built-from-request).
  args(ctx, out) {
    return ['scan', '--config', RULES, '--json', '--output', out, '--disable-version-check', '--quiet',
      '--no-git-ignore', '--taint-intrafile', ...[...EXCLUDE, ...RULE_TESTS].flatMap((d) => ['--exclude', d]), ctx.root];
  },

  okExit: [0],

  // Files opengrep could not check fully, from its errors list: a syntax error means the whole file was skipped, a
  // partial parse means some lines were skipped (a finding there can be missing), a timeout means a rule gave up on
  // the file. Errors with no file (about a rule) are left out: those make the run fail instead.
  codeRead(json, ctx) {
    const notRead = new Map();
    const inPart = new Map();
    const stopped = new Map();
    for (const e of json?.errors ?? []) {
      if (!e?.path) continue;
      const file = rel(ctx.root, e.path);
      const kind = Array.isArray(e.type) ? e.type[0] : e.type;
      const lines = (e.spans ?? []).map((s) => s?.start?.line).filter((n) => Number.isInteger(n));
      // A syntax error that stops the whole file has no spans; its message names the line: "...at line <path>:7:".
      const inMessage = Number(String(e.message ?? '').split(`${e.path}:`)[1]?.match(/^(\d+):/)?.[1]);
      if (!lines.length && Number.isInteger(inMessage) && inMessage > 0) lines.push(inMessage);
      if (kind === 'PartialParsing') {
        inPart.set(file, [...new Set([...(inPart.get(file) ?? []), ...lines])].sort((a, b) => a - b));
      } else if (kind === 'Timeout') {
        const rule = String(e.rule_id ?? '').split('.').at(-1);
        stopped.set(file, [...new Set([...(stopped.get(file) ?? []), ...(rule ? [rule] : [])])].sort());
      } else if (!notRead.has(file)) {
        notRead.set(file, lines[0] ?? null);
      }
    }
    const sorted = (m) => [...m].sort((a, b) => (a[0] < b[0] ? -1 : 1));
    return {
      not_read: sorted(notRead).map(([file, line]) => ({ file, line })),
      read_in_part: sorted(inPart).filter(([file]) => !notRead.has(file)).map(([file, lines]) => ({ file, lines })),
      stopped: sorted(stopped).map(([file, rules]) => ({ file, rules })),
    };
  },

  parse(json, ctx) {
    // opengrep prefixes the rule id with the config path, joined by dots; our rule ids have no dots.
    const results = (json?.results ?? []).map((r) => ({ ...r, ruleId: r.check_id.split('.').at(-1) }));
    // Internal rules are never shown: they only record that something exists anywhere in the project (for example a
    // throttle registered for the whole app), and a rule with suppressed-by: <id> is dropped when that rule matched.
    const seen = new Set(results.filter((r) => r.extra?.metadata?.internal).map((r) => r.ruleId));
    // A rule with suppressed-on-same-line-by: <id> is dropped where that rule reported the same file and line (a
    // medium "check the callers" finding is not needed next to the high one that already sees the request).
    const lineOf = (r) => `${rel(ctx.root, r.path)}:${r.start.line}`;
    const reported = new Set(results.map((r) => `${r.ruleId}@${lineOf(r)}`));
    const findings = [];
    // A taint rule reports one result per path from a source to the same line (three request values in one query
    // give three results): one line is one finding.
    const done = new Set();
    for (const r of results) {
      const meta = r.extra?.metadata ?? {};
      if (meta.internal || (meta['suppressed-by'] && seen.has(meta['suppressed-by']))) continue;
      if (meta['suppressed-on-same-line-by'] && reported.has(`${meta['suppressed-on-same-line-by']}@${lineOf(r)}`)) continue;
      const ruleId = r.ruleId;
      const location = `${rel(ctx.root, r.path)}:${r.start.line}`;
      if (done.has(`${ruleId}:${location}`)) continue;
      done.add(`${ruleId}:${location}`);
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
