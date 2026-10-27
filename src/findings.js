export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const CATEGORY_ORDER = ['secret', 'dependency', 'config', 'code'];

// Stable order: same inputs give byte-identical findings.json.
export function sortAndNumber(findings) {
  const rank = (list, v) => { const i = list.indexOf(v); return i < 0 ? list.length : i; };
  const sorted = [...findings].sort((a, b) =>
    rank(SEVERITY_ORDER, a.severity.normalized) - rank(SEVERITY_ORDER, b.severity.normalized) ||
    rank(CATEGORY_ORDER, a.category) - rank(CATEGORY_ORDER, b.category) ||
    (a.fingerprint < b.fingerprint ? -1 : a.fingerprint > b.fingerprint ? 1 : 0));
  return sorted.map((f, i) => ({
    id: `AUD-${String(i + 1).padStart(3, '0')}`,
    status: 'Open',
    verification: 'unverified',
    ...f,
  }));
}

export function countBySeverity(findings) {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0]));
  for (const f of findings) counts[f.severity.normalized] = (counts[f.severity.normalized] ?? 0) + 1;
  return counts;
}

export function atOrAbove(findings, level) {
  const limit = SEVERITY_ORDER.indexOf(level);
  return findings.filter((f) => SEVERITY_ORDER.indexOf(f.severity.normalized) <= limit);
}
