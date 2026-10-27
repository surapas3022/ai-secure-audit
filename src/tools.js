import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync, chmodSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { get } from './http.js';
import { fromTarGz, fromZip } from './extract.js';

const lock = JSON.parse(readFileSync(new URL('../tools.lock.json', import.meta.url), 'utf8'));

export function lockedTools() {
  return lock.tools;
}

export function platformKey() {
  return `${process.platform}-${process.arch}`;
}

export function cacheDir() {
  if (process.env.AI_SECURE_AUDIT_CACHE) return process.env.AI_SECURE_AUDIT_CACHE;
  if (process.platform === 'win32') return join(process.env.LOCALAPPDATA ?? join(homedir(), 'AppData', 'Local'), 'ai-secure-audit');
  return join(process.env.XDG_CACHE_HOME ?? join(homedir(), '.cache'), 'ai-secure-audit');
}

// Returns the path to the pinned binary, downloading and verifying it on first use.
// A checksum mismatch is fatal: we never run a binary that is not the pinned one.
export async function ensureTool(id, log = () => {}) {
  const tool = lock.tools[id];
  if (!tool) throw new Error(`unknown tool: ${id}`);
  const p = tool.platforms[platformKey()];
  if (!p) throw new Error(`${id} has no build for ${platformKey()}`);

  const dir = join(cacheDir(), 'bin', id, tool.version);
  const target = join(dir, p.binary);
  if (existsSync(target)) return target;

  log(`downloading ${id} ${tool.version} ...`);
  const archive = await get(p.url);
  const sha256 = createHash('sha256').update(archive).digest('hex');
  if (sha256 !== p.sha256) {
    throw new Error(`${id}: checksum mismatch for ${p.url}\n  expected ${p.sha256}\n  got      ${sha256}`);
  }
  const bytes = p.archive === 'tar.gz' ? fromTarGz(archive, p.binary) : p.archive === 'zip' ? fromZip(archive, p.binary) : archive;

  mkdirSync(dir, { recursive: true });
  const tmp = `${target}.${process.pid}.tmp`;
  writeFileSync(tmp, bytes);
  if (process.platform !== 'win32') chmodSync(tmp, 0o755);
  renameSync(tmp, target);
  return target;
}
