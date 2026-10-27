import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync, deflateRawSync } from 'node:zlib';
import { fromTarGz, fromZip } from '../src/extract.js';

function tarEntry(name, data) {
  const h = Buffer.alloc(512);
  h.write(name, 0);
  h.write('0000755\0', 100);
  h.write(data.length.toString(8).padStart(11, '0') + '\0', 124);
  h.write('0', 156);
  h.write('ustar\0', 257);
  const pad = Buffer.alloc((512 - (data.length % 512)) % 512);
  return Buffer.concat([h, data, pad]);
}

function zip(entries) {
  const locals = [], centrals = [];
  let offset = 0;
  for (const { name, data, method } of entries) {
    const body = method === 8 ? deflateRawSync(data) : data;
    const n = Buffer.from(name);
    const crc = 0; // the reader does not check CRC; checksums are verified on the whole download
    const l = Buffer.alloc(30);
    l.writeUInt32LE(0x04034b50, 0); l.writeUInt16LE(method, 8); l.writeUInt32LE(crc, 14);
    l.writeUInt32LE(body.length, 18); l.writeUInt32LE(data.length, 22); l.writeUInt16LE(n.length, 26);
    const c = Buffer.alloc(46);
    c.writeUInt32LE(0x02014b50, 0); c.writeUInt16LE(method, 10); c.writeUInt32LE(crc, 16);
    c.writeUInt32LE(body.length, 20); c.writeUInt32LE(data.length, 24); c.writeUInt16LE(n.length, 28);
    c.writeUInt32LE(offset, 42);
    locals.push(l, n, body); centrals.push(c, n);
    offset += 30 + n.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const e = Buffer.alloc(22);
  e.writeUInt32LE(0x06054b50, 0); e.writeUInt16LE(entries.length, 8); e.writeUInt16LE(entries.length, 10);
  e.writeUInt32LE(cd.length, 12); e.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, e]);
}

test('tar.gz: finds the binary by file name, in any folder', () => {
  const tar = Buffer.concat([tarEntry('README.md', Buffer.from('readme')), tarEntry('pkg/tool', Buffer.from('BINARY')), Buffer.alloc(1024)]);
  assert.equal(fromTarGz(gzipSync(tar), 'tool').toString(), 'BINARY');
  assert.throws(() => fromTarGz(gzipSync(tar), 'missing'), /not found/);
});

test('zip: reads stored and deflated entries', () => {
  const z = zip([
    { name: 'LICENSE', data: Buffer.from('license'), method: 0 },
    { name: 'tool.exe', data: Buffer.from('EXE'.repeat(100)), method: 8 },
  ]);
  assert.equal(fromZip(z, 'LICENSE').toString(), 'license');
  assert.equal(fromZip(z, 'tool.exe').toString(), 'EXE'.repeat(100));
});
