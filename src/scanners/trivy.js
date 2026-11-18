import { join } from 'node:path';
import { rel } from '../paths.js';

export default {
  id: 'trivy',
  category: 'config',

  // --skip-check-update keeps the checks built into the pinned trivy version, so results do not drift.
  args(ctx, out) {
    return ['config', '--format', 'json', '--output', out, '--skip-check-update', '--quiet',
      '--cache-dir', join(ctx.cache, 'trivy'),
      '--skip-dirs', '**/node_modules', '--skip-dirs', '**/.git', ctx.root];
  },

  okExit: [0],

  parse(json, ctx) {
    const findings = [];
    for (const result of json?.Results ?? []) {
      const file = rel(ctx.root, result.Target);
      for (const m of result.Misconfigurations ?? []) {
        if (m.Status !== 'FAIL') continue;
        const line = m.CauseMetadata?.StartLine;
        const location = line ? `${file}:${line}` : file;
        const sev = (m.Severity ?? 'UNKNOWN').toLowerCase();
        findings.push({
          fingerprint: `trivy:${m.ID}:${location}`,
          category: 'config',
          title: m.Title,
          severity: { tool: m.Severity, normalized: ['critical', 'high', 'medium', 'low'].includes(sev) ? sev : 'medium' },
          source: { kind: 'tool', tool: 'trivy', rule_id: m.ID },
          evidence: [{ location, detail: m.Message }],
          fix: m.Resolution,
          references: { urls: m.PrimaryURL ? [m.PrimaryURL] : [] },
        });
      }
    }
    return findings;
  },
};
