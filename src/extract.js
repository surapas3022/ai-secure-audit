import { gunzipSync, inflateRawSync } from 'node:zlib';
import { basename } from 'node:path';

// Minimal readers for the two archive formats the pinned tools ship in.
// Each returns the bytes of the first entry whose file name equals `name`.

export function fromTarGz(buf, name) {
  const tar = gunzipSync(buf);
  let longName = null;
  for (let off = 0; off + 512 <= tar.length; ) {
    const header = tar.subarray(off, off + 512);
    if (header.every((b) => b === 0)) break;
    const field = (start, len) => header.subarray(start, start + len).toString('utf8').replace(/\0.*$/s, '');
    const size = parseInt(field(124, 12).trim() || '0', 8);
    const type = field(156, 1);
    const data = tar.subarray(off + 512, off + 512 + size);
    let path = longName ?? (field(345, 155) ? `${field(345, 155)}/${field(0, 100)}` : field(0, 100));
    longName = null;
    if (type === 'L') longName = data.toString('utf8').replace(/\0.*$/s, '');
    else if ((type === '0' || type === '') && basename(path) === name) return Buffer.from(data);
    off += 512 + Math.ceil(size / 512) * 512;
  }
  throw new Error(`${name} not found in archive`);
}

export function fromZip(buf, name) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65_557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('not a zip file');
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) throw new Error('bad zip central directory');
    const method = buf.readUInt16LE(off + 10);
    const compSize = buf.readUInt32LE(off + 20);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const local = buf.readUInt32LE(off + 42);
    const path = buf.subarray(off + 46, off + 46 + nameLen).toString('utf8');
    if (basename(path) === name) {
      const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
      const data = buf.subarray(start, start + compSize);
      if (method === 0) return Buffer.from(data);
      if (method === 8) return inflateRawSync(data);
      throw new Error(`unsupported zip compression method ${method}`);
    }
    off += 46 + nameLen + extraLen + commentLen;
  }
  throw new Error(`${name} not found in archive`);
}
