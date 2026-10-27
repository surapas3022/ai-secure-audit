// Maintainer script: rebuilds tools.lock.json from each tool's published checksums.
// Run after changing a version below. Users never run this.
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { get } from '../src/http.js';

const PLATFORMS = ['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64', 'win32-arm64', 'win32-x64'];

const TOOLS = {
  gitleaks: {
    repo: 'gitleaks/gitleaks',
    version: '8.30.1',
    license: 'MIT',
    checksums: (v) => `gitleaks_${v}_checksums.txt`,
    asset(v, os, arch) {
      const o = { darwin: 'darwin', linux: 'linux', win32: 'windows' }[os];
      return { name: `gitleaks_${v}_${o}_${arch}.${os === 'win32' ? 'zip' : 'tar.gz'}`, binary: os === 'win32' ? 'gitleaks.exe' : 'gitleaks' };
    },
  },
  'osv-scanner': {
    repo: 'google/osv-scanner',
    version: '2.7.0',
    license: 'Apache-2.0',
    checksums: () => 'osv-scanner_SHA256SUMS',
    asset(v, os, arch) {
      const a = { x64: 'amd64', arm64: 'arm64' }[arch];
      const o = { darwin: 'darwin', linux: 'linux', win32: 'windows' }[os];
      const name = `osv-scanner_${o}_${a}${os === 'win32' ? '.exe' : ''}`;
      return { name, binary: name };
    },
  },
  trivy: {
    repo: 'aquasecurity/trivy',
    version: '0.76.1',
    license: 'Apache-2.0',
    checksums: (v) => `trivy_${v}_checksums.txt`,
    asset(v, os, arch) {
      // No Windows arm64 build; Windows on Arm runs the x64 binary.
      if (os === 'win32') return { name: `trivy_${v}_windows-64bit.zip`, binary: 'trivy.exe' };
      const o = { darwin: 'macOS', linux: 'Linux' }[os];
      const a = { x64: '64bit', arm64: 'ARM64' }[arch];
      return { name: `trivy_${v}_${o}-${a}.tar.gz`, binary: 'trivy' };
    },
  },
};

function archiveKind(name) {
  if (name.endsWith('.tar.gz')) return 'tar.gz';
  if (name.endsWith('.zip')) return 'zip';
  return 'raw';
}

const lock = { lockfileVersion: 1, tools: {} };
for (const [id, t] of Object.entries(TOOLS)) {
  const base = `https://github.com/${t.repo}/releases/download/v${t.version}`;
  const sums = new Map();
  for (const line of (await get(`${base}/${t.checksums(t.version)}`)).toString('utf8').split('\n')) {
    const m = line.trim().match(/^([0-9a-f]{64})\s+\*?(\S+)$/);
    if (m) sums.set(m[2], m[1]);
  }
  const platforms = {};
  for (const p of PLATFORMS) {
    const [os, arch] = p.split('-');
    const { name, binary } = t.asset(t.version, os, arch);
    const sha256 = sums.get(name);
    if (!sha256) throw new Error(`${id}: no checksum for ${name}`);
    platforms[p] = { url: `${base}/${name}`, sha256, archive: archiveKind(name), binary };
  }
  lock.tools[id] = { version: t.version, license: t.license, repo: `https://github.com/${t.repo}`, platforms };
}

const out = fileURLToPath(new URL('../tools.lock.json', import.meta.url));
writeFileSync(out, JSON.stringify(lock, null, 2) + '\n');
console.log(`wrote ${out}`);
