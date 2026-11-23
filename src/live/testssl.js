// testssl.sh: TLS check of one live host. Turns its flat list into a few findings.
// testssl reports ~170 lines for one host (one per cipher, grades, hints). Only the ids below can become a finding;
// the rest stays in the raw file. A line about testssl itself (engine, deprecated flags) is never a finding.

const SEVERITY = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };

const FIX = {
  protocol: 'Turn off this old TLS/SSL version on the server or proxy. Keep TLS 1.2 and TLS 1.3 only. Browsers that need less are gone.',
  cipher: 'Remove this group of weak ciphers from the server or proxy cipher list. Use the "modern" or "intermediate" list from the Mozilla SSL Configuration Generator.',
  cert_trust: 'Install a certificate from a trusted authority (Let\'s Encrypt is free) that includes this exact host name, with the full chain.',
  cert_expiry: 'Renew the certificate now and set up automatic renewal (certbot, Caddy and most hosting panels do this).',
  cert_key: 'Issue a new certificate with a modern key (RSA 2048 or more, or ECDSA P-256) and a SHA-256 signature.',
  hsts: 'Send the header `Strict-Transport-Security: max-age=31536000` from the HTTPS site, after you are sure every sub-page works on HTTPS.',
  vuln: 'Update the server software (OpenSSL, nginx, Apache or the proxy in front) and its TLS settings, then run the check again.',
};

// id -> [title, fix, category of the problem]. cert_* are capped at high: a self-signed cert on a dev host is not critical.
const CURATED = {
  SSLv2: ['SSLv2 is offered', FIX.protocol],
  SSLv3: ['SSLv3 is offered', FIX.protocol],
  TLS1: ['TLS 1.0 is offered', FIX.protocol],
  TLS1_1: ['TLS 1.1 is offered', FIX.protocol],
  cipherlist_NULL: ['Ciphers with no encryption are offered', FIX.cipher],
  cipherlist_aNULL: ['Ciphers with no authentication are offered', FIX.cipher],
  cipherlist_EXPORT: ['Export-grade (deliberately weak) ciphers are offered', FIX.cipher],
  cipherlist_LOW: ['Weak ciphers (64-bit, DES, RC2, RC4, MD5) are offered', FIX.cipher],
  cipherlist_3DES_IDEA: ['Triple-DES / IDEA ciphers are offered', FIX.cipher],
  cert_chain_of_trust: ['The certificate is not trusted', FIX.cert_trust],
  cert_trust: ['The certificate does not match the host name', FIX.cert_trust],
  cert_subjectAltName: ['The certificate has no Subject Alternative Name', FIX.cert_trust],
  cert_expirationStatus: ['The certificate is expired or about to expire', FIX.cert_expiry],
  cert_signatureAlgorithm: ['The certificate uses a weak signature', FIX.cert_key],
  cert_keySize: ['The certificate key is weak', FIX.cert_key],
  HSTS: ['HSTS is not sent', FIX.hsts],
  heartbleed: ['Heartbleed', FIX.vuln], CCS: ['CCS injection', FIX.vuln], ticketbleed: ['Ticketbleed', FIX.vuln],
  ROBOT: ['ROBOT', FIX.vuln], secure_renego: ['Insecure renegotiation', FIX.vuln],
  secure_client_renego: ['Client-initiated renegotiation (denial of service)', FIX.vuln],
  CRIME_TLS: ['CRIME', FIX.vuln], POODLE_SSL: ['POODLE', FIX.vuln], SWEET32: ['SWEET32', FIX.vuln],
  FREAK: ['FREAK', FIX.vuln], DROWN: ['DROWN', FIX.vuln], LOGJAM: ['LOGJAM', FIX.vuln], BEAST: ['BEAST', FIX.vuln],
  RC4: ['RC4 ciphers are offered', FIX.cipher], winshock: ['Winshock', FIX.vuln],
};

// The result is only trusted if testssl reached the host and spoke TLS to it.
const PROOF_OF_TLS = ['SSLv3', 'TLS1', 'TLS1_1', 'TLS1_2', 'TLS1_3'];

export function parseTestssl(json, { host, port }) {
  const rows = Array.isArray(json) ? json : [];
  if (!rows.some((r) => PROOF_OF_TLS.includes(r.id))) {
    throw new Error(`testssl could not talk TLS to ${host}:${port} (no TLS answer: wrong port, no HTTPS, or blocked)`);
  }
  const findings = [];
  const notices = [];
  for (const r of rows) {
    const c = CURATED[r.id];
    if (!c) continue;
    if (r.severity === 'WARN') {
      // The test did not run (e.g. the local OpenSSL has no RC4): "no finding" would read as a pass. Say so.
      notices.push({ id: r.id, message: `testssl could not check "${c[0]}": ${r.finding}` });
      continue;
    }
    let sev = SEVERITY[r.severity];
    if (!sev) continue; // OK and INFO are not problems
    if (r.id.startsWith('cert_') && (sev === 'critical')) sev = 'high';
    findings.push({
      fingerprint: `testssl:${r.id}:${host}:${port}`,
      category: 'tls',
      title: c[0],
      severity: { tool: r.severity, normalized: sev },
      source: { kind: 'tool', tool: 'testssl', rule_id: r.id },
      evidence: [{ location: `${host}:${port}`, detail: String(r.finding).slice(0, 300) }],
      fix: c[1],
      references: r.cwe ? { cwe: [r.cwe] } : {},
    });
  }
  return { findings, notices };
}

export function testsslArgs(host, port, rawFile) {
  // --ip one: test a single address, so a host behind many addresses is not hit many times.
  // No --connect-timeout: testssl needs a `timeout` command for it and macOS has none. `live` stops the run after 15 minutes.
  // No --fast (not recommended by testssl) and nothing that sends attack traffic beyond testssl's own TLS probes.
  return ['--quiet', '--warnings', 'off', '--color', '0', '--ip', 'one',
    '--jsonfile', rawFile, `${host}:${port}`];
}
