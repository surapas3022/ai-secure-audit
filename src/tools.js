import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync, chmodSync, rmSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { get } from './http.js';
import { fromTarGz, fromZip, treeFromTarGz } from './extract.js';

const lock = JSON.parse(readFileSync(new URL('../tools.lock.json', import.meta.url), 'utf8'));

export function lockedTools() {
  return lock.tools;
}

// Linux without glibc (Alpine and other musl systems) needs builds of its own for tools that are not static.
export function isMusl() {
  if (process.platform !== 'linux') return false;
  return !process.report?.getReport?.().header?.glibcVersionRuntime;
}

export function platformKey() {
  return `${process.platform}-${process.arch}${isMusl() ? '-musl' : ''}`;
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

// Hash of a folder's content that does not depend on how the archive was compressed (GitHub does not promise that
// a source archive keeps the same bytes): path, mode and content of every file, in path order.
export function treeHash(files) {
  const h = createHash('sha256');
  for (const f of [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))) {
    h.update(`${f.path}\0${f.mode & 0o111 ? 'x' : '-'}\0${f.data.length}\0`);
    h.update(f.data);
  }
  return h.digest('hex');
}

export function liveTools() {
  return lock.live_tools ?? {};
}

// Tools for checking a live host. They ship as a folder, so the pin is a content hash of the whole folder.
// Returns the path to the entry script, downloading and verifying it on first use.
export async function ensureFolderTool(id, log = () => {}) {
  const tool = liveTools()[id];
  if (!tool) throw new Error(`unknown tool: ${id}`);
  if (!tool.platforms.includes(platformKey())) throw new Error(`${id} has no build for ${platformKey()}`);

  const dir = join(cacheDir(), 'live', id, tool.version);
  const entry = join(dir, tool.entry);
  if (existsSync(join(dir, '.verified'))) return entry;

  log(`downloading ${id} ${tool.version} ...`);
  const files = treeFromTarGz(await get(tool.url), 1);
  const got = treeHash(files);
  if (got !== tool.tree_sha256) {
    throw new Error(`${id}: content hash mismatch for ${tool.url}\n  expected ${tool.tree_sha256}\n  got      ${got}`);
  }
  const tmp = `${dir}.${process.pid}.tmp`;
  rmSync(tmp, { recursive: true, force: true });
  for (const f of files) {
    const dest = join(tmp, f.path);
    mkdirSync(dirname(dest), { recursive: true });
    writeFileSync(dest, f.data);
    chmodSync(dest, f.mode);
  }
  writeFileSync(join(tmp, '.verified'), `${got}\n`);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dirname(dir), { recursive: true });
  renameSync(tmp, dir);
  return entry;
}
