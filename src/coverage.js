import { readdirSync, readFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// What the check can and cannot read in this project, so a "0 findings" result is never mistaken for "checked".

// Installed or generated code: not code the project wrote (same list as the code scanner).
export const SKIP_DIRS = new Set(['node_modules', '.git', '.audit', 'dist', 'build', '.next', '.nuxt', '.output',
  '.svelte-kit', 'coverage', 'vendor', 'target', '.venv', 'venv', '__pycache__', 'Pods', '.dart_tool']);

const LANGUAGES = {
  javascript: ['.js', '.jsx', '.mjs', '.cjs'],
  typescript: ['.ts', '.tsx', '.mts', '.cts'],
  php: ['.php'],
  python: ['.py'],
  go: ['.go'],
  rust: ['.rs'],
  ruby: ['.rb'],
  java: ['.java'],
  kotlin: ['.kt', '.kts'],
  csharp: ['.cs'],
  c: ['.c', '.h'],
  cpp: ['.cpp', '.cc', '.cxx', '.hpp', '.hh'],
  dart: ['.dart'],
  swift: ['.swift'],
  scala: ['.scala'],
  elixir: ['.ex', '.exs'],
  lua: ['.lua'],
  // Smart contracts: a language this kit does not read must still be named, or its files look checked.
  solidity: ['.sol'],
  // Single-file components: the JavaScript rules do not read the <script> block inside them.
  vue: ['.vue'],
  svelte: ['.svelte'],
};
// Docker Compose files: trivy (the config checker) does not read them, so the report must say they were not checked.
// compose.yaml, compose.yml, docker-compose.yml, docker-compose.prod.yaml and the like.
export const isComposeFile = (name) => /^(docker-)?compose(\.[\w-]+)?\.ya?ml$/i.test(name);

const BY_EXT = new Map(Object.entries(LANGUAGES).flatMap(([lang, exts]) => exts.map((e) => [e, lang])));

// Lockfiles osv-scanner reads, and whether this kit has tested that ecosystem with known-answer cases.
// Update `tested` only after a probe case for that ecosystem passes (lab/probes/osv-probe.mjs in the private repo).
export const LOCKFILES = {
  'package-lock.json': { ecosystem: 'npm', tested: true },
  'npm-shrinkwrap.json': { ecosystem: 'npm', tested: false },
  'yarn.lock': { ecosystem: 'npm', tested: false },
  'pnpm-lock.yaml': { ecosystem: 'npm', tested: false },
  'bun.lock': { ecosystem: 'npm', tested: false },
  'composer.lock': { ecosystem: 'Packagist (PHP)', tested: true },
  'go.mod': { ecosystem: 'Go', tested: true },
  'Cargo.lock': { ecosystem: 'crates.io (Rust)', tested: true },
  'Gemfile.lock': { ecosystem: 'RubyGems', tested: true },
  'packages.lock.json': { ecosystem: 'NuGet (C#)', tested: true },
  'requirements.txt': { ecosystem: 'PyPI (Python)', tested: true },
  'poetry.lock': { ecosystem: 'PyPI (Python)', tested: false },
  'Pipfile.lock': { ecosystem: 'PyPI (Python)', tested: false },
  'uv.lock': { ecosystem: 'PyPI (Python)', tested: false },
  'pubspec.lock': { ecosystem: 'Pub (Dart/Flutter)', tested: false },
  'pom.xml': { ecosystem: 'Maven (Java)', tested: false },
  'gradle.lockfile': { ecosystem: 'Maven (Java)', tested: false },
  'conan.lock': { ecosystem: 'ConanCenter (C/C++)', tested: false },
  'mix.lock': { ecosystem: 'Hex (Elixir)', tested: false },
};

// Files that list libraries without fixing their versions, and the lockfiles that do. A project with one of these and no
// lockfile gets no library check at all, so the report has to say it. `uses` is true when the file really asks for a library.
const matches = (re) => (text) => re.test(text);
const json = (read) => (text) => { try { return read(JSON.parse(text)); } catch { return true; } };
const anyKey = (...objects) => objects.some((o) => o && Object.keys(o).length > 0);
const MANIFESTS = [
  { is: (n) => n === 'package.json', locks: ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock'],
    uses: json((p) => anyKey(p.dependencies, p.devDependencies, p.optionalDependencies, p.peerDependencies)) },
  // "php" and "ext-*" are the platform, not libraries: library names contain a slash.
  { is: (n) => n === 'composer.json', locks: ['composer.lock'],
    uses: json((p) => Object.keys({ ...p.require, ...p['require-dev'] }).some((k) => k.includes('/'))) },
  { is: (n) => n === 'Gemfile', locks: ['Gemfile.lock'], uses: matches(/^\s*gem\s/m) },
  { is: (n) => n === 'Cargo.toml', locks: ['Cargo.lock'], uses: matches(/^\[(?:[^\]\n]*\.)?(?:dev-|build-)?dependencies(?:\.[^\]\n]*)?\]/m) },
  { is: (n) => n === 'pyproject.toml', locks: ['poetry.lock', 'uv.lock', 'Pipfile.lock', 'requirements.txt'],
    uses: matches(/^\s*dependencies\s*=\s*\[\s*[^\]\s]|^\[(?:tool\.poetry\.(?:[\w.-]+\.)?dependencies|project\.optional-dependencies|dependency-groups)\]/m) },
  { is: (n) => n === 'Pipfile', locks: ['Pipfile.lock'], uses: matches(/^\[(?:dev-)?packages\][ \t]*\r?\n(?:[ \t]*(?:#.*)?\r?\n)*[ \t]*[^\[\s#]/m) },
  { is: (n) => n === 'pubspec.yaml', locks: ['pubspec.lock'], uses: matches(/^(?:dev_)?dependencies:/m) },
  { is: (n) => n.endsWith('.csproj'), locks: ['packages.lock.json'], uses: matches(/<PackageReference\b/) },
  { is: (n) => n === 'build.gradle' || n === 'build.gradle.kts', locks: ['gradle.lockfile'],
    uses: matches(/\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\b/) },
  { is: (n) => n === 'mix.exs', locks: ['mix.lock'], uses: matches(/\bdefp?\s+deps\b/) },
];

// Output written by a deploy tool: its package.json files are copies, not something a person keeps a lockfile for.
const GENERATED = /(?:^|\/)\.(?:vercel|netlify|serverless|wrangler)\//;

const parent = (dir) => (dir.includes('/') ? dir.slice(0, dir.lastIndexOf('/')) : '');
const at = (dir, name) => (dir ? `${dir}/${name}` : name);
const globRe = (glob) => new RegExp(`^${glob.replace(/^\.\//, '').replace(/\/$/, '')
  .replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*|\*|\?/g, (m) => (m === '**' ? '.*' : m === '*' ? '[^/]*' : '[^/]'))}$`);

// The folders a workspace at `dir` says belong to it (npm, yarn, pnpm and Cargo keep one lockfile at the top).
function workspaceMembers(root, dir, files) {
  const read = (name) => { try { return files.has(at(dir, name)) ? readFileSync(join(root, dir, name), 'utf8') : ''; } catch { return ''; } };
  const globs = [];
  try {
    const w = JSON.parse(read('package.json') || '{}').workspaces;
    globs.push(...(Array.isArray(w) ? w : w?.packages ?? []));
  } catch { /* an unreadable package.json declares no workspace */ }
  for (const m of read('pnpm-workspace.yaml').matchAll(/^\s*-\s*['"]?([^'"#\r\n]+?)['"]?\s*(?:#.*)?$/gm)) globs.push(m[1]);
  const cargo = /^\[workspace\][^[]*?members\s*=\s*\[([^\]]*)\]/m.exec(read('Cargo.toml'));
  if (cargo) globs.push(...[...cargo[1].matchAll(/['"]([^'"]+)['"]/g)].map((m) => m[1]));
  const include = globs.filter((g) => typeof g === 'string' && !g.startsWith('!')).map(globRe);
  const exclude = globs.filter((g) => typeof g === 'string' && g.startsWith('!')).map((g) => globRe(g.slice(1)));
  return (sub) => include.some((re) => re.test(sub)) && !exclude.some((re) => re.test(sub));
}

function manifestsWithoutLockfile(root, list) {
  const files = new Set(list);
  const missing = [];
  for (const f of list) {
    const name = basename(f);
    const kind = MANIFESTS.find((m) => m.is(name));
    if (!kind || GENERATED.test(f)) continue;
    const dir = f === name ? '' : f.slice(0, -name.length - 1);
    if (kind.locks.some((l) => files.has(at(dir, l)))) continue;
    let covered = false;
    for (let up = dir; up && !covered;) {
      up = parent(up);
      if (kind.locks.some((l) => files.has(at(up, l)))) covered = workspaceMembers(root, up, files)(up ? dir.slice(up.length + 1) : dir);
    }
    if (covered) continue;
    let text = '';
    try { text = readFileSync(join(root, f), 'utf8'); } catch { missing.push(f); continue; }
    if (kind.uses(text)) missing.push(f);
  }
  return missing;
}

const named = (files) => `${files.slice(0, 5).join(', ')}${files.length > 5 ? ` and ${files.length - 5} more` : ''}`;
// Gaps that start like this mean some libraries got no check; the reports repeat it at the top.
export const NO_LIBRARY_CHECK = 'Libraries not checked:';

// Languages the kit's own code rules read, taken from the rule files so the list cannot fall behind them.
const RULES_DIR = fileURLToPath(new URL('../rules/', import.meta.url));

export function ruleLanguages(rulesDir = RULES_DIR) {
  const langs = new Set();
  for (const f of readdirSync(rulesDir).filter((n) => /\.ya?ml$/.test(n)).sort()) {
    for (const m of readFileSync(join(rulesDir, f), 'utf8').matchAll(/languages:\s*\[([^\]]*)\]/g)) {
      for (const l of m[1].split(',')) langs.add(l.trim());
    }
  }
  return langs;
}

// The rules a user sees findings from, with the one-line summary the report lists. Helper rules marked
// `internal: true` only filter other findings, so they are left out.
export function ruleSummaries(rulesDir = RULES_DIR) {
  const rules = [];
  for (const f of readdirSync(rulesDir).filter((n) => /\.ya?ml$/.test(n)).sort()) {
    for (const block of readFileSync(join(rulesDir, f), 'utf8').split(/^ {2}- id:/m).slice(1)) {
      if (/^\s+internal:\s*true\b/m.test(block)) continue;
      const id = block.slice(0, block.indexOf('\n')).trim();
      const languages = (/languages:\s*\[([^\]]*)\]/.exec(block)?.[1] ?? '').split(',').map((l) => l.trim()).filter(Boolean);
      const summary = /^\s+summary:\s*'([^']*)'/m.exec(block)?.[1] ?? /^\s+summary:\s*"([^"]*)"/m.exec(block)?.[1] ?? null;
      rules.push({ id, languages, summary });
    }
  }
  return rules;
}

// Common mistakes that no code rule of this kit looks for yet. Keep this list true: drop an item once a rule covers it.
export const NOT_LOOKED_FOR = [
  'NoSQL queries or shell commands built from user input',
  'HTML put on the page from values whose names do not look like text people type, or through other variables (XSS)',
  'redirects or server-side requests to a URL the user chose',
  'folders served as file lists',
  'passwords stored with a fast hash such as MD5 or SHA-1',
];

const extOf = (name) => (name.includes('.') ? name.slice(name.lastIndexOf('.')).toLowerCase() : '');

function walk(dir, rel, out, limit) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries.sort((a, b) => (a.name < b.name ? -1 : 1))) {
    if (out.length >= limit) return;
    const path = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(join(dir, e.name), path, out, limit); }
    else if (e.isFile()) out.push(path);
  }
}

export function projectCoverage(root, { rulesDir = RULES_DIR, limit = 200_000 } = {}) {
  const files = [];
  walk(root, '', files, limit);
  const covered = ruleLanguages(rulesDir);
  const rules = ruleSummaries(rulesDir);
  const counts = new Map();
  const lockfiles = [];
  const compose = [];
  for (const f of files) {
    const name = basename(f);
    const lang = BY_EXT.get(extOf(name));
    if (lang) counts.set(lang, (counts.get(lang) ?? 0) + 1);
    if (LOCKFILES[name]) lockfiles.push({ file: f, ...LOCKFILES[name] });
    if (isComposeFile(name)) compose.push(f);
  }
  const languages = [...counts].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
    .map(([language, n]) => ({ language, files: n, code_rules: covered.has(language) }));
  // Only the rules that can match a language found here: a NestJS rule says nothing about a PHP project.
  const present = new Set(languages.filter((l) => l.code_rules).map((l) => l.language));
  // opengrep's built-in ignore list leaves out folders named test or tests at any depth, and *.min.js files, so the
  // code rules never read them. Files in a language with no rules are already named above.
  const ruled = (f) => present.has(BY_EXT.get(extOf(basename(f))));
  const code_skipped = {
    test_folders: files.filter((f) => ruled(f) && /(?:^|\/)tests?\//.test(f)),
    minified: files.filter((f) => ruled(f) && /\.min\.js$/i.test(f) && !/(?:^|\/)tests?\//.test(f)),
  };
  const code_rules = rules.filter((r) => r.languages.some((l) => present.has(l))).map(({ id, summary }) => ({ id, summary }));
  return { languages, code_rules, code_skipped, lockfiles, compose, unlocked: manifestsWithoutLockfile(root, files), truncated: files.length >= limit };
}

const list = (items) => (items.length < 2 ? items.join('') : `${items.slice(0, -1).join(', ')} and ${items.at(-1)}`);

// Plain sentences for the report and for the AI assistant. Empty when everything found is covered.
export function coverageGaps(cov) {
  const gaps = [];
  const noRules = cov.languages.filter((l) => !l.code_rules);
  if (noRules.length) {
    gaps.push(`Code rules: this kit has no rules yet for ${noRules.map((l) => `${l.language} (${l.files} file${l.files === 1 ? "" : "s"})`).join(', ')}. ` +
      'Code in these languages was not checked for mistakes; "0 findings" says nothing about it. To review it, ask an ' +
      'AI assistant with the prompt in https://github.com/surapas3022/ai-secure-audit/blob/main/docs/ai-review-prompt.md ' +
      '(its results are leads to check, not findings).');
  }
  // Languages that do have rules: say how few, so "code rules: yes" is not read as "the code was checked".
  const withRules = cov.languages.filter((l) => l.code_rules).map((l) => l.language);
  if (withRules.length && cov.code_rules) {
    const n = cov.code_rules.length;
    gaps.push(`Code rules: ${list(withRules)} code was checked with only ${n} rule${n === 1 ? '' : 's'} from this kit` +
      (n ? `: ${cov.code_rules.map((r) => r.summary ?? r.id).join('; ')}` : '') + '. ' +
      `Other mistakes were not looked for, such as ${list(NOT_LOOKED_FOR)}; "0 findings" says nothing about them. ` +
      'To review them, ask an AI assistant with the prompt in ' +
      'https://github.com/surapas3022/ai-secure-audit/blob/main/docs/ai-review-prompt.md (its results are leads to check, not findings).');
  }
  const skipped = cov.code_skipped ?? { test_folders: [], minified: [] };
  const parts = [];
  const files = (n) => `${n} ${n === 1 ? 'file' : 'files'}`;
  if (skipped.test_folders.length) parts.push(`${files(skipped.test_folders.length)} in test or tests folders (${named(skipped.test_folders)})`);
  if (skipped.minified.length) {
    const n = skipped.minified.length;
    parts.push(`${n} minified ${n === 1 ? 'file' : 'files'} (${named(skipped.minified)})`);
  }
  if (parts.length) {
    const total = skipped.test_folders.length + skipped.minified.length;
    const what = [skipped.test_folders.length && 'folders named test or tests', skipped.minified.length && '*.min.js files'].filter(Boolean);
    const why = [
      skipped.test_folders.length && 'Test code usually does not run as the app; if a folder named test or tests holds code that does, review it by hand.',
      skipped.minified.length && 'A minified file does run, but it is usually a library copied in or build output whose source is elsewhere; if it is code you wrote, check the source instead.',
    ].filter(Boolean);
    gaps.push(`Code rules: ${parts.join(' and ')} ${total === 1 ? 'was' : 'were'} not checked by the code rules: opengrep ` +
      `leaves ${what.join(' and ')} out on its own. ${why.join(' ')} The secret check still read these files.`);
  }
  const read = cov.code_read ?? { not_read: [], read_in_part: [], stopped: [] };
  const n = (k, one, many) => `${k} ${k === 1 ? one : many}`;
  if (read.not_read.length) {
    const list = named(read.not_read.map((x) => (x.line ? `${x.file} (syntax error at line ${x.line})` : x.file)));
    gaps.push(`Code rules: ${n(read.not_read.length, 'file', 'files')} could not be read by the code checker (${list}), so ` +
      `${read.not_read.length === 1 ? 'it was' : 'they were'} not checked by the code rules at all. This happens with syntax ` +
      'the checker does not know, or a file that is only part of a program. If one of them is app code, review it by hand ' +
      '(full list in findings.json under coverage.code_read).');
  }
  if (read.read_in_part.length) {
    const list = named(read.read_in_part.map((x) => (x.lines.length ? `${x.file} (${x.lines.length === 1 ? 'line' : 'lines'} ${x.lines.join(', ')})` : x.file)));
    gaps.push(`Code rules: ${n(read.read_in_part.length, 'file was', 'files were')} read only in part (${list}): the code ` +
      'checker skipped the code around those lines, so a finding there can be missing. Review those parts by hand ' +
      '(full list in findings.json under coverage.code_read).');
  }
  if (read.stopped.length) {
    const list = named(read.stopped.map((x) => (x.rules.length ? `${x.file} (${x.rules.join(', ')})` : x.file)));
    gaps.push(`Code rules: the check stopped on ${n(read.stopped.length, 'file', 'files')} before it finished (${list}), ` +
      'because a rule took too long; those rules did not finish on that file. Large or generated files cause this ' +
      '(full list in findings.json under coverage.code_read).');
  }
  if (cov.unlocked?.length) {
    gaps.push(`${NO_LIBRARY_CHECK} no lockfile (the file that records exact library versions) was found for ${named(cov.unlocked)}, ` +
      'so the libraries listed there were not looked at; "0 findings" says nothing about them. Create the lockfile with your ' +
      'package manager (for npm: npm install --package-lock-only), keep it in git, and run the check again.');
  }
  const unread = new Set(cov.unread ?? []);
  if (unread.size) {
    gaps.push(`${NO_LIBRARY_CHECK} osv-scanner read no libraries from ${named([...unread])}. It skips files that a .gitignore ` +
      'names, even committed ones; the other usual reason is a file that lists no libraries. "0 findings" says nothing about ' +
      'them. If .gitignore names the lockfile or its folder, remove that line and run the check again.');
  }
  const untested = cov.lockfiles.filter((l) => !l.tested && !unread.has(l.file));
  if (untested.length) {
    gaps.push(`Libraries: ${untested.map((l) => `${l.file} (${l.ecosystem})`).join(', ')} ` +
      'were read by osv-scanner, but this kit has not tested that ecosystem with known answers yet.');
  }
  if (cov.compose?.length) {
    gaps.push(`Docker Compose: ${cov.compose.join(', ')} ${cov.compose.length === 1 ? 'was' : 'were'} not checked. trivy reads ` +
      'Dockerfiles but not Compose files, so settings such as privileged: true, network_mode: host, a mounted ' +
      'docker.sock or a database port open to every network were not looked at; "0 findings" says nothing about them.');
  }
  if (cov.truncated) gaps.push('The project has more files than this check counts; the lists above may be incomplete.');
  return gaps;
}
