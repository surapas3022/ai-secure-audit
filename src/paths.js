import { isAbsolute, relative, sep } from 'node:path';

// Paths in findings are relative to the scanned folder and use "/", so output is the same on every OS.
export function rel(root, p) {
  if (!p) return '';
  const r = isAbsolute(p) ? relative(root, p) : p;
  return r.split(sep).join('/');
}
