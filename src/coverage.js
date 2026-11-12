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
  // Single-file components: the JavaScript rules do not read the <script> block inside them.
  vue: ['.vue'],
  svelte: ['.svelte'],
};
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

// Languages the kit's own code rules read, taken from the rule files so the list cannot fall behind them.
export function ruleLanguages(rulesDir = fileURLToPath(new URL('../rules/', import.meta.url))) {
  const langs = new Set();
  for (const f of readdirSync(rulesDir).filter((n) => /\.ya?ml$/.test(n)).sort()) {
    for (const m of readFileSync(join(rulesDir, f), 'utf8').matchAll(/languages:\s*\[([^\]]*)\]/g)) {
      for (const l of m[1].split(',')) langs.add(l.trim());
    }
  }
  return langs;
}

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

export function projectCoverage(root, { rulesDir, limit = 200_000 } = {}) {
  const files = [];
  walk(root, '', files, limit);
  const covered = ruleLanguages(rulesDir);
  const counts = new Map();
  const lockfiles = [];
  for (const f of files) {
    const name = basename(f);
    const ext = name.includes('.') ? name.slice(name.lastIndexOf('.')).toLowerCase() : '';
    const lang = BY_EXT.get(ext);
    if (lang) counts.set(lang, (counts.get(lang) ?? 0) + 1);
    if (LOCKFILES[name]) lockfiles.push({ file: f, ...LOCKFILES[name] });
  }
  const languages = [...counts].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1))
    .map(([language, n]) => ({ language, files: n, code_rules: covered.has(language) }));
  return { languages, lockfiles, truncated: files.length >= limit };
}

// Plain sentences for the report and for the AI assistant. Empty when everything found is covered.
export function coverageGaps(cov) {
  const gaps = [];
  const noRules = cov.languages.filter((l) => !l.code_rules);
  if (noRules.length) {
    gaps.push(`Code rules: this kit has no rules yet for ${noRules.map((l) => `${l.language} (${l.files} file${l.files === 1 ? "" : "s"})`).join(', ')}. ` +
      'Code in these languages was not checked for mistakes; "0 findings" says nothing about it.');
  }
  const untested = cov.lockfiles.filter((l) => !l.tested);
  if (untested.length) {
    gaps.push(`Libraries: ${untested.map((l) => `${l.file} (${l.ecosystem})`).join(', ')} ` +
      'were read by osv-scanner, but this kit has not tested that ecosystem with known answers yet.');
  }
  if (cov.truncated) gaps.push('The project has more files than this check counts; the lists above may be incomplete.');
  return gaps;
}
