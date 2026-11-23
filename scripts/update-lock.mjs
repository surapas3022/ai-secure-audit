// Maintainer script: rebuilds tools.lock.json from each tool's published checksums.
// Run after changing a version below. Users never run this.
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { get } from '../src/http.js';
import { treeFromTarGz } from '../src/extract.js';
import { treeHash } from '../src/tools.js';

// *-musl = Linux without glibc (Alpine). Static Go tools use the same file as glibc Linux.
const PLATFORMS = ['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64', 'linux-arm64-musl', 'linux-x64-musl', 'win32-arm64', 'win32-x64'];

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
  opengrep: {
    repo: 'opengrep/opengrep',
    version: '1.33.1',
    license: 'LGPL-2.1',
    // No checksums file is published; GitHub records a sha256 for every release asset (the release is also
    // signed with cosign: *.sig / *.cert beside each binary).
    checksums: null,
    asset(v, os, arch, libc) {
      // No Windows arm64 build; Windows on Arm runs the x64 binary. manylinux needs glibc; musllinux is for Alpine.
      if (os === 'win32') return { name: 'opengrep_windows_x86.exe', binary: 'opengrep_windows_x86.exe' };
      const o = { darwin: 'osx', linux: libc === 'musl' ? 'musllinux' : 'manylinux' }[os];
      const a = { x64: 'x86', arm64: os === 'darwin' ? 'arm64' : 'aarch64' }[arch];
      const name = `opengrep_${o}_${a}`;
      return { name, binary: name };
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
  if (t.checksums) {
    for (const line of (await get(`${base}/${t.checksums(t.version)}`)).toString('utf8').split('\n')) {
      const m = line.trim().match(/^([0-9a-f]{64})\s+\*?(\S+)$/);
      if (m) sums.set(m[2], m[1]);
    }
  } else {
    const release = JSON.parse((await get(`https://api.github.com/repos/${t.repo}/releases/tags/v${t.version}`)).toString('utf8'));
    for (const a of release.assets) {
      const m = (a.digest ?? '').match(/^sha256:([0-9a-f]{64})$/);
      if (m) sums.set(a.name, m[1]);
    }
  }
  const platforms = {};
  for (const p of PLATFORMS) {
    const [os, arch, libc] = p.split('-');
    const { name, binary } = t.asset(t.version, os, arch, libc);
    const sha256 = sums.get(name);
    if (!sha256) throw new Error(`${id}: no checksum for ${name}`);
    platforms[p] = { url: `${base}/${name}`, sha256, archive: archiveKind(name), binary };
  }
  lock.tools[id] = { version: t.version, license: t.license, repo: `https://github.com/${t.repo}`, platforms };
}

// Tools for checking a live host. They ship as a source folder, so the pin is a hash of the folder content.
// No Windows build (needs bash) and no Alpine build (no bash by default): the report says so instead of passing.
const LIVE_TOOLS = {
  testssl: { repo: 'testssl/testssl.sh', version: '3.2.5', license: 'GPL-2.0', entry: 'testssl.sh', platforms: ['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64'] },
};
lock.live_tools = {};
for (const [id, t] of Object.entries(LIVE_TOOLS)) {
  const url = `https://github.com/${t.repo}/archive/refs/tags/v${t.version}.tar.gz`;
  const tree_sha256 = treeHash(treeFromTarGz(await get(url), 1));
  lock.live_tools[id] = { version: t.version, license: t.license, repo: `https://github.com/${t.repo}`, entry: t.entry, url, tree_sha256, platforms: t.platforms };
}

const out = fileURLToPath(new URL('../tools.lock.json', import.meta.url));
writeFileSync(out, JSON.stringify(lock, null, 2) + '\n');
console.log(`wrote ${out}`);
