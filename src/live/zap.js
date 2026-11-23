// OWASP ZAP baseline: a passive check of one live web site, run in Docker.
// "Baseline" = spider for about a minute, then read every response with ZAP's passive rules. It sends ordinary GET
// requests and nothing that attacks. This tool never runs ZAP's active or full scan.
//
// What it finds: header, cookie and information-leak mistakes. What it cannot find (say so in every report):
// XSS, injection, broken login, access control. Those need an active scan or a person.

export const ZAP_NOT_CHECKED =
  'ZAP baseline only reads responses. It does not find XSS, injection, broken login or access control: ' +
  'a clean result here says nothing about them.';

const RISK = { 3: 'high', 2: 'medium', 1: 'low' };

// pluginid -> true when the alert is only as good as a banner the server sends about itself.
// Everything not listed here is left out (ids 10019, 10049, 10027, 10109, 10063, 90004 ... are advice or noise).
const CURATED = {
  10003: false, // vulnerable JavaScript library
  10010: false, // cookie without HttpOnly
  10011: false, // cookie without Secure
  10020: false, // missing anti-clickjacking header
  10021: false, // X-Content-Type-Options missing
  10023: false, // debug error messages
  10024: false, // sensitive information in URL
  10035: false, // HSTS missing (https)
  10036: true,  // Server header leaks version
  10037: true,  // X-Powered-By leaks
  10038: false, // CSP not set
  10054: false, // cookie without SameSite
  10061: true,  // X-AspNet-Version leaks
  10062: false, // PII disclosure
  10098: false, // cross-domain misconfiguration (CORS)
  10105: false, // weak authentication method
  10202: false, // absence of anti-CSRF tokens
  20020: true,  // server version with known vulnerabilities (from the banner)
  90003: false, // subresource integrity missing
  90022: false, // application error disclosure
};

function plain(html) {
  return String(html ?? '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 400);
}

export function parseZap(json, { url }) {
  const site = json?.site?.[0];
  if (!site) throw new Error(`ZAP found no site at ${url} (not reachable from Docker, or nothing answered)`);
  const findings = [];
  for (const a of site.alerts ?? []) {
    const id = Number(a.pluginid);
    if (!(id in CURATED)) continue;
    let sev = RISK[Number(a.riskcode)];
    if (!sev) continue;
    const banner = CURATED[id];
    // ZAP trusts what the server says about itself: it can rate "Apache 2.2 with known holes" high for a lie.
    if (banner && sev === 'high') sev = 'medium';
    const inst = a.instances ?? [];
    const total = Number(a.count) || inst.length;
    findings.push({
      fingerprint: `zap:${a.alertRef ?? id}:${url}`,
      category: 'web',
      title: a.name,
      severity: { tool: `ZAP risk ${a.riskcode}`, normalized: sev },
      source: { kind: 'tool', tool: 'zap-baseline', rule_id: String(a.alertRef ?? id) },
      evidence: inst.slice(0, 3).map((i, n) => ({
        location: `${i.method ?? 'GET'} ${i.uri}`,
        detail: [
          n === 0 && total > 3 ? `${total} places in total, first 3 shown.` : '',
          i.evidence ? `Seen: ${String(i.evidence).slice(0, 80)}` : '',
          banner ? 'Based on what the server says about itself; it may not be true.' : '',
        ].filter(Boolean).join(' ') || a.name,
      })),
      fix: plain(a.solution) || 'See the ZAP alert for this check.',
      references: a.cweid && Number(a.cweid) > 0 ? { cwe: [`CWE-${a.cweid}`] } : {},
    });
  }
  return { findings, notices: [] };
}

// docker arguments. The URL is the only thing taken from the target; the scan type is fixed.
// -m 1: spider for one minute. -I: do not make the exit code depend on warnings (we read the JSON).
export function zapDockerArgs({ image, dir, url }) {
  return ['run', '--rm', '--security-opt', 'no-new-privileges', '--add-host', 'host.docker.internal:host-gateway',
    '-v', `${dir}:/zap/wrk:rw`, image, 'zap-baseline.py', '-t', url, '-J', 'report.json', '-m', '1', '-I'];
}

// A server on this machine is reached from the container through host.docker.internal.
export function zapUrl({ scheme, host, port }) {
  const local = ['localhost', '127.0.0.1', '::1'].includes(host);
  const h = local ? 'host.docker.internal' : host;
  const dflt = scheme === 'http' ? 80 : 443;
  return `${scheme}://${h}${port === dflt ? '' : `:${port}`}`;
}
