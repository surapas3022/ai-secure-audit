import { existsSync, readFileSync } from 'node:fs';

// The allowlist for `live`. A line this reader does not understand is an error, never skipped:
// a typo must not turn into "no limits".

const HOST = /^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$/;

export function parseTargets(text) {
  const targets = [];
  let seenHeader = false;
  let cur = null;
  const bad = (n, why) => { throw new Error(`targets file, line ${n}: ${why}`); };
  const finish = (n) => { if (cur && !cur.host) bad(n, 'an entry has no host'); };

  text.split(/\r?\n/).forEach((raw, i) => {
    const n = i + 1;
    const line = raw.replace(/(^|\s)#.*$/, '').trimEnd();
    if (!line.trim()) return;
    if (!seenHeader) {
      if (line.trim() !== 'targets:') bad(n, 'expected "targets:" first');
      seenHeader = true;
      return;
    }
    const m = /^(\s+)(- )?([a-z]+):\s*(\S+)\s*$/.exec(line);
    if (!m) bad(n, `cannot read "${raw.trim()}"`);
    const [, , dash, key, value] = m;
    if (dash) {
      finish(n);
      cur = { host: null, port: 443, env: 'dev' };
      targets.push(cur);
    } else if (!cur) bad(n, 'a setting before any "- host:" entry');
    if (key === 'host') {
      if (!HOST.test(value) || value.includes('..')) bad(n, `"${value}" is not a plain host name (no scheme, path, port or wildcard)`);
      if (cur.host) bad(n, 'two hosts in one entry');
      cur.host = value.toLowerCase();
    } else if (key === 'port') {
      if (!/^\d{1,5}$/.test(value) || +value < 1 || +value > 65535) bad(n, `"${value}" is not a port`);
      cur.port = +value;
    } else if (key === 'env') {
      if (!['dev', 'prod'].includes(value)) bad(n, 'env must be dev or prod');
      cur.env = value;
    } else bad(n, `unknown setting "${key}"`);
    if (dash && key !== 'host') bad(n, 'an entry must start with "- host:"');
  });
  finish(text.split('\n').length);
  if (!seenHeader || !targets.length) throw new Error('targets file has no targets');
  return targets;
}

export function loadTargets(file) {
  if (!existsSync(file)) {
    throw new Error(`no targets file at ${file}. \`live\` only checks hosts you list there. ` +
      'Copy config/targets.example.yml to targets.yml, list your own hosts, and keep it out of git.');
  }
  return parseTargets(readFileSync(file, 'utf8'));
}

// "host" or "host:port" only. Anything that looks like a URL, a path, a wildcard or an address range is refused.
export function resolveTarget(arg, targets, { allowProd = false } = {}) {
  const m = /^([A-Za-z0-9.-]+)(?::(\d{1,5}))?$/.exec(arg ?? '');
  if (!m || !HOST.test(m[1])) throw new Error(`"${arg}" is not host or host:port (no scheme, path, wildcard or range)`);
  const host = m[1].toLowerCase();
  const port = m[2] ? +m[2] : 443;
  const hit = targets.find((t) => t.host === host && t.port === port);
  if (!hit) throw new Error(`${host}:${port} is not in the targets file: refusing to check it`);
  if (hit.env === 'prod' && !allowProd) {
    throw new Error(`${host}:${port} is marked prod: add --allow-prod only when the owner has told you to check production`);
  }
  return hit;
}
