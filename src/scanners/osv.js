import { join } from 'node:path';
import { rel } from '../paths.js';

function cvssBand(score) {
  const s = Number.parseFloat(score);
  if (Number.isNaN(s)) return null;
  if (s >= 9) return 'critical';
  if (s >= 7) return 'high';
  if (s >= 4) return 'medium';
  if (s > 0) return 'low';
  return 'info';
}

function compareVersions(a, b) {
  const pa = a.split(/[.\-+]/).map((x) => (/^\d+$/.test(x) ? Number(x) : x));
  const pb = b.split(/[.\-+]/).map((x) => (/^\d+$/.test(x) ? Number(x) : x));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0, y = pb[i] ?? 0;
    if (x === y) continue;
    if (typeof x === 'number' && typeof y === 'number') return x - y;
    return String(x).localeCompare(String(y));
  }
  return 0;
}

function fixedVersion(vulns, pkgName) {
  const fixed = [];
  for (const v of vulns) {
    for (const a of v.affected ?? []) {
      if (a.package?.name !== pkgName) continue;
      for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) fixed.push(e.fixed);
    }
  }
  return fixed.sort(compareVersions).at(-1) ?? null;
}

export default {
  id: 'osv-scanner',
  category: 'dependency',

  // Offline databases: the dependency list never leaves the machine. Only the public databases are downloaded.
  env(ctx) {
    return { OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY: join(ctx.cache, 'osv-db') };
  },

  args(ctx, out) {
    return ['scan', 'source', '-r', '--offline-vulnerabilities', '--download-offline-databases', '--allow-no-lockfiles',
      '--format', 'json', '--output-file', out, '--verbosity', 'error', ctx.root];
  },

  okExit: [0, 1],

  parse(json, ctx) {
    const findings = [];
    for (const result of json?.results ?? []) {
      const file = rel(ctx.root, result.source?.path);
      for (const pkg of result.packages ?? []) {
        const { name, version, ecosystem } = pkg.package;
        const vulns = pkg.vulnerabilities ?? [];
        for (const group of pkg.groups ?? []) {
          const ids = [...group.ids].sort();
          const main = vulns.find((v) => ids.includes(v.id)) ?? {};
          const groupVulns = vulns.filter((v) => ids.includes(v.id));
          const fixed = fixedVersion(groupVulns, name);
          const band = cvssBand(group.max_severity);
          const aliases = [...new Set([...(group.aliases ?? []), ...ids])].sort();
          findings.push({
            fingerprint: `osv:${ecosystem}:${name}@${version}:${ids[0]}`,
            category: 'dependency',
            title: `${name} ${version}: ${main.summary ?? ids[0]}`,
            severity: {
              tool: group.max_severity ? `CVSS ${group.max_severity}` : 'unrated',
              normalized: band ?? 'medium',
            },
            source: { kind: 'tool', tool: 'osv-scanner', rule_id: ids[0] },
            evidence: [{ location: file, detail: `${ecosystem} package ${name}@${version}. Advisories: ${aliases.join(', ')}` }],
            fix: fixed
              ? `Upgrade ${name} to ${fixed} or later, then reinstall so the lockfile updates.`
              : `No fixed version is published yet. Check whether the affected feature is used; consider a replacement.`,
            references: { advisories: aliases },
          });
        }
      }
    }
    return findings;
  },
};
