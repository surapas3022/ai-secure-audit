import { BlockList, connect } from 'node:net';
import { lookup } from 'node:dns/promises';

// Port check: which well-known risky ports accept a connection from here.
// It connects and closes at once. It sends no data, reads no banner, and tries only the list below, never a range.
// "Not open" means closed, filtered by a firewall, or not reachable from where this ran: it cannot tell which.

// Where an address sits decides what an open port proves. The check only ever connects from the computer that ran it,
// so a port that is open on a public address proves it is reachable from here, and on a loopback or private address
// it proves only that something is listening there, not that anyone on the internet can reach it.
const SCOPES = new BlockList();
for (const [net, prefix] of [['127.0.0.0', 8], ['0.0.0.0', 8]]) SCOPES.addSubnet(net, prefix, 'ipv4');
SCOPES.addAddress('::1', 'ipv6'); SCOPES.addAddress('::', 'ipv6');
const PRIVATE = new BlockList();
for (const [net, prefix] of [['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16], ['169.254.0.0', 16], ['100.64.0.0', 10]]) PRIVATE.addSubnet(net, prefix, 'ipv4');
PRIVATE.addSubnet('fc00::', 7, 'ipv6'); PRIVATE.addSubnet('fe80::', 10, 'ipv6');

export function addressScope(ip) {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);   // an IPv4 address written in IPv6 form
  const addr = mapped ? mapped[1] : ip;
  const family = addr.includes(':') ? 'ipv6' : 'ipv4';
  if (SCOPES.check(addr, family)) return 'loopback';
  if (PRIVATE.check(addr, family)) return 'private';
  return 'public';
}

const SEEN = {
  public: 'If you ran this from outside your own network, anyone on the internet can do the same.',
  loopback: 'This address is this computer itself, so it shows the service is listening here, not that it can be reached from outside.',
  private: 'This is a private network address, so it shows the service can be reached from inside that network, not from the internet.',
};

const DB = 'Do not expose a database to the internet. Make it listen only on 127.0.0.1 or a private network, and block the port in the firewall. Reach it through an SSH tunnel or VPN. If it was open for a while, assume the data could have been read: change its passwords and check its logs.';
const ADMIN = 'Block this port in the firewall and reach the machine through a VPN or SSH instead. Remote-control services on the open internet are attacked all day.';
const DEV = 'This is a common development-server port. If it is a dev server, stop it or make it listen only on 127.0.0.1 (for example `--host 127.0.0.1`), and put the real site behind a proxy on ports 80 and 443. If it is meant to be public, ignore this.';

// port -> [name, severity, fix]. No SSH here: an open SSH port is normal; it is listed as information only.
export const RISKY_PORTS = {
  2375: ['Docker remote API (no login)', 'critical', 'Anyone who can reach this can start containers as root on the machine. Close it now: remove `-H tcp://0.0.0.0:2375` from the Docker settings, or bind it to 127.0.0.1, and treat the machine as possibly compromised.'],
  4243: ['Docker remote API (no login)', 'critical', 'Anyone who can reach this can start containers as root on the machine. Close it now and treat the machine as possibly compromised.'],
  10250: ['Kubernetes kubelet', 'high', 'Block this port from the internet; the kubelet API can run commands in pods.'],
  2379: ['etcd', 'high', 'etcd holds cluster secrets. Block it from the internet and require client certificates.'],
  6379: ['Redis', 'high', DB], 27017: ['MongoDB', 'high', DB], 5432: ['PostgreSQL', 'high', DB], 3306: ['MySQL / MariaDB', 'high', DB],
  1433: ['Microsoft SQL Server', 'high', DB], 9200: ['Elasticsearch', 'high', DB], 11211: ['Memcached', 'high', DB], 5984: ['CouchDB', 'high', DB],
  3389: ['Remote Desktop (RDP)', 'high', ADMIN], 5900: ['VNC', 'high', ADMIN], 445: ['Windows file sharing (SMB)', 'high', ADMIN], 23: ['Telnet', 'high', ADMIN],
  21: ['FTP', 'medium', 'FTP sends passwords in plain text. Use SFTP (over SSH) instead and close this port.'],
  111: ['rpcbind', 'medium', ADMIN], 6443: ['Kubernetes API', 'medium', 'Limit the Kubernetes API to your own addresses (firewall or private network).'],
  5601: ['Kibana', 'medium', 'Put it behind a login and a VPN, or block the port.'], 15672: ['RabbitMQ management', 'medium', 'Put it behind a VPN or block the port, and change the default guest login.'],
  5672: ['RabbitMQ', 'medium', DB], 9090: ['Prometheus', 'medium', 'Put it behind a login and a VPN, or block the port. Metrics often reveal internals.'],
  3000: ['Development server (port 3000)', 'low', DEV], 5173: ['Vite dev server', 'low', DEV], 4200: ['Angular dev server', 'low', DEV],
  5000: ['Development server (port 5000)', 'low', DEV], 8000: ['Development server (port 8000)', 'low', DEV],
  8080: ['Alternate web port (8080)', 'low', DEV], 8888: ['Development server (port 8888)', 'low', DEV],
};
export const INFO_PORTS = { 22: 'SSH', 25: 'SMTP (mail)', 80: 'HTTP', 443: 'HTTPS' };

export const PORT_LIST = [...Object.keys(RISKY_PORTS), ...Object.keys(INFO_PORTS)].map(Number).sort((a, b) => a - b);

// 'open' | 'closed' | 'filtered' (no answer in time) | `error:<code>`. Never writes to the socket.
export function probe(ip, port, timeoutMs = 3000) {
  return new Promise((done) => {
    const s = connect({ host: ip, port });
    let settled = false;
    const end = (v) => { if (!settled) { settled = true; s.destroy(); done(v); } };
    s.setTimeout(timeoutMs, () => end('filtered'));
    s.once('connect', () => end('open'));
    s.once('error', (e) => end(e.code === 'ECONNREFUSED' ? 'closed' : `error:${e.code ?? 'unknown'}`));
  });
}

// Both address families are tried (the first IPv4 and the first IPv6 address): a firewall rule is often set for
// one and forgotten for the other. A family that cannot be reached at all (no IPv6 route here) is reported as such;
// the check fails only if no address could be tried.
export async function scanPorts(host, { probeFn = probe, resolve = (h) => lookup(h, { all: true }), concurrency = 10, ports = PORT_LIST } = {}) {
  let all;
  try { all = await resolve(host); } catch (e) { throw new Error(`could not resolve ${host} (${e.code ?? e.message})`); }
  const list = Array.isArray(all) ? all : [all];
  const picked = [4, 6].map((f) => list.find((a) => a.family === f)).filter(Boolean);
  if (!picked.length) throw new Error(`could not resolve ${host} (no address)`);
  const addrs = [];
  for (const { address: ip, family } of picked) {
    const results = {};
    const queue = [...ports];
    await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, async () => {
      for (let p = queue.shift(); p !== undefined; p = queue.shift()) results[p] = await probeFn(ip, p);
    }));
    const states = Object.values(results);
    // Every probe failed in a way that is not "closed" or "no answer": the network is the problem, not the host.
    const unreachable = states.every((st) => st.startsWith('error:')) ? [...new Set(states)].join(', ') : null;
    addrs.push({ ip, family, results, unreachable });
  }
  if (addrs.every((a) => a.unreachable)) {
    throw new Error(`no connection could be tried from this computer (${addrs.map((a) => a.unreachable).join('; ')}): the result would say nothing about ${host}`);
  }
  return { addrs };
}

export function parsePorts({ addrs }, { host }) {
  const byPort = new Map();
  const info = new Set();
  const notices = [];
  for (const a of addrs) {
    if (a.unreachable) {
      notices.push({ id: `ports-ipv${a.family}`, message: `IPv${a.family} address ${a.ip} could not be tried from this computer (${a.unreachable}), so its ports are not counted as closed.` });
      continue;
    }
    const unclear = Object.values(a.results).filter((st) => st.startsWith('error:')).length;
    if (unclear) notices.push({ id: `ports-ipv${a.family}`, message: `${unclear} of ${Object.keys(a.results).length} ports on ${a.ip} could not be tried (network error), so they are not counted as closed.` });
    for (const [port, state] of Object.entries(a.results)) {
      if (state !== 'open') continue;
      if (!RISKY_PORTS[port]) { info.add(`${port} (${INFO_PORTS[port] ?? 'open'}) on IPv${a.family}`); continue; }
      byPort.set(port, [...(byPort.get(port) ?? []), a]);
    }
  }
  const findings = [...byPort].map(([port, hits]) => {
    const risky = RISKY_PORTS[port];
    return {
      fingerprint: `ports:${port}:${host}`,
      category: 'network',
      title: `${risky[0]} accepts connections`,
      severity: { tool: 'port-check', normalized: risky[1] },
      source: { kind: 'tool', tool: 'port-check', rule_id: String(port) },
      evidence: hits.map((a) => ({
        location: a.family === 6 ? `[${a.ip}]:${port}` : `${a.ip}:${port}`,
        detail: `A connection over IPv${a.family} was accepted from the computer that ran this check. Nothing was sent. ${SEEN[addressScope(a.ip)]}`,
      })),
      fix: risky[2],
      references: {},
    };
  });
  return {
    findings,
    notices,
    info: [...info].sort((x, y) => parseInt(x) - parseInt(y)),
    addresses: addrs.map((a) => `${a.ip} (IPv${a.family}${a.unreachable ? ', not reachable from here' : ''})`),
  };
}
