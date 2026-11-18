// Does a Docker build of the scanned folder take this tool's own results (.audit/) into the image?
// trivy only reads Dockerfile instructions, so nothing else notices: .audit/ appears on the first scan, and a
// Dockerfile with COPY . . then ships the list of the app's weak points in every image.
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, posix } from 'node:path';

// The files a scan writes; if any of them gets into the build context, the results do.
const AUDIT_FILES = ['.audit/out/findings.json', '.audit/out/report.md', '.audit/out/raw/x.json'];

const DOCKERFILE = /^(Dockerfile|Containerfile)(\.[\w.-]+)?$|^[\w.-]+\.(Dockerfile|dockerfile)$/;

function patternToRegex(p) {
  let re = '';
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === '*') {
      if (p[i + 1] === '*') {
        i++;
        if (p[i + 1] === '/') { i++; re += '(?:.*/)?'; } else re += '.*';
      } else re += '[^/]*';
    } else if (c === '?') re += '[^/]';
    else if (c === '[') {
      const end = p.indexOf(']', i + 1);
      if (end < 0) { re += '\\['; continue; }
      re += '[' + p.slice(i + 1, end).replace(/^!/, '^').replace(/\\/g, '\\\\') + ']';
      i = end;
    } else if (c === '\\' && i + 1 < p.length) re += '\\' + p[++i];
    else re += c.replace(/[.+^${}()|]/g, '\\$&');
  }
  return new RegExp(`^${re}$`);
}

// .dockerignore rules as Docker reads them: one pattern per line, # comments, surrounding space trimmed, a leading
// ! re-includes, paths cleaned (leading /, ./ and trailing / dropped). The last matching line wins.
export function parseDockerignore(text) {
  const rules = [];
  for (let line of text.split(/\r?\n/)) {
    line = line.trim();
    if (!line || line.startsWith('#')) continue;
    const negate = line.startsWith('!');
    if (negate) line = line.slice(1).trim();
    let p = posix.normalize(line).replace(/^\/+/, '').replace(/\/+$/, '');
    if (!p || p === '.') continue;
    rules.push({ negate, re: patternToRegex(p) });
  }
  return rules;
}

// A path is excluded when a pattern matches it or one of its parent folders.
export function isExcluded(rules, file) {
  const parts = file.split('/');
  const paths = parts.map((_, i) => parts.slice(0, i + 1).join('/'));
  let excluded = false;
  for (const r of rules) if (paths.some((p) => r.re.test(p))) excluded = !r.negate;
  return excluded;
}

// COPY or ADD whose sources include the whole context: ".", "./", "*" or "./*" (shell or JSON form).
export function copiesWholeFolder(dockerfile) {
  const text = dockerfile.replace(/\\\r?\n/g, ' ');
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*(?:COPY|ADD)\s+(.*)$/i.exec(line);
    if (!m) continue;
    let rest = m[1].trim();
    while (/^--\S+/.test(rest)) rest = rest.replace(/^--\S+\s*/, '');
    if (/--from=/i.test(m[1])) continue; // copies from another stage, not from the folder
    let args;
    if (rest.startsWith('[')) {
      try { args = JSON.parse(rest); } catch { continue; }
    } else args = rest.split(/\s+/);
    if (args.slice(0, -1).some((a) => ['.', './', '*', './*'].includes(a))) return true;
  }
  return false;
}

// One notice per Dockerfile at the top of the scanned folder (the usual build context) that would ship .audit/.
// Not checked: Dockerfiles in subfolders built with a context above them (compose build.context: ..).
export function dockerignoreNotices(root) {
  let names;
  try { names = readdirSync(root); } catch { return []; }
  const notices = [];
  for (const name of names.filter((n) => DOCKERFILE.test(n)).sort()) {
    let text;
    try { text = readFileSync(join(root, name), 'utf8'); } catch { continue; }
    if (!copiesWholeFolder(text)) continue;
    // BuildKit reads <Dockerfile>.dockerignore next to the Dockerfile first, then .dockerignore.
    const own = `${name}.dockerignore`;
    const ignoreFile = existsSync(join(root, own)) ? own : existsSync(join(root, '.dockerignore')) ? '.dockerignore' : null;
    if (!ignoreFile) {
      notices.push({
        id: 'dockerignore-audit', file: name,
        message: `${name} copies the whole folder and there is no .dockerignore, so this check's results in .audit/ ` +
          '(a list of the app\'s weak points) go into the image, together with .env, .git and anything else in the ' +
          'folder. Add a .dockerignore with at least these lines: .audit, .env, .git',
      });
      continue;
    }
    const rules = parseDockerignore(readFileSync(join(root, ignoreFile), 'utf8'));
    if (AUDIT_FILES.every((f) => isExcluded(rules, f))) continue;
    notices.push({
      id: 'dockerignore-audit', file: name,
      message: `${name} copies the whole folder and ${ignoreFile} does not exclude .audit/, so this check's results ` +
        `(a list of the app's weak points) go into the image. Add the line .audit to ${ignoreFile}.`,
    });
  }
  return notices;
}
