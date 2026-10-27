import { copyFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { scan, outDir } from './scan.js';
import { reportMarkdown, consoleSummary } from './report.js';
import { atOrAbove, SEVERITY_ORDER } from './findings.js';
import { cacheDir, lockedTools, platformKey } from './tools.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

const HELP = `ai-secure-audit ${pkg.version}: free security check for apps built with AI

Usage: npx ai-secure-audit [command] [path] [options]

Commands
  scan [path]     basic check of a project folder (default command, default path ".")
  retest [path]   run the check again and compare with the last result
  tools           list pinned tool versions, licenses and the cache folder
  init            install the AI skills into this project (not available yet)
  mcp             run as an MCP server (not available yet)

Options
  --json               print findings.json to stdout instead of the summary
  --fail-on <level>    exit 1 if a finding is at or above: ${SEVERITY_ORDER.slice(0, 4).join(', ')}
  --advanced           add the Docker-based advanced tools (not available yet)
  -h, --help           show this help
  -v, --version        show the version

Results are written to <path>/.audit/out/ (git-ignored automatically).`;

function parseArgs(argv) {
  const opts = { command: 'scan', path: '.', json: false, failOn: null, advanced: false };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--advanced') opts.advanced = true;
    else if (a === '--fail-on') opts.failOn = argv[++i];
    else if (a.startsWith('--fail-on=')) opts.failOn = a.slice(10);
    else if (a === '-h' || a === '--help') opts.command = 'help';
    else if (a === '-v' || a === '--version') opts.command = 'version';
    else if (a.startsWith('-')) throw new Error(`unknown option: ${a}`);
    else rest.push(a);
  }
  if (opts.command === 'scan' && ['scan', 'retest', 'tools', 'init', 'mcp', 'help'].includes(rest[0])) opts.command = rest.shift();
  if (rest[0]) opts.path = rest[0];
  if (opts.failOn && !SEVERITY_ORDER.slice(0, 4).includes(opts.failOn)) throw new Error(`--fail-on must be one of ${SEVERITY_ORDER.slice(0, 4).join(', ')}`);
  return opts;
}

function compare(prev, curr) {
  const before = new Map(prev.findings.map((f) => [f.fingerprint, f]));
  const after = new Map(curr.findings.map((f) => [f.fingerprint, f]));
  return {
    fixed: [...before.values()].filter((f) => !after.has(f.fingerprint)),
    still: [...after.values()].filter((f) => before.has(f.fingerprint)),
    added: [...after.values()].filter((f) => !before.has(f.fingerprint)),
  };
}

async function runScan(opts, { retest }) {
  const log = opts.json ? () => {} : (m) => process.stderr.write(`${m}\n`);
  let prev = null;
  const prevFile = join(outDir(opts.path), 'findings.json');
  if (retest) {
    if (!existsSync(prevFile)) throw new Error('no previous result to compare with: run `npx ai-secure-audit` first');
    prev = JSON.parse(readFileSync(prevFile, 'utf8'));
    copyFileSync(prevFile, join(outDir(opts.path), 'findings.prev.json'));
  }

  const { root, out, result } = await scan(opts.path, { log, version: pkg.version });
  writeFileSync(join(out, 'report.md'), reportMarkdown(result, new Date().toISOString().slice(0, 10)));
  const r = relative(process.cwd(), out);
  const outRel = (r && !r.startsWith('..') ? r : out).split('\\').join('/');

  if (opts.json) process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  else {
    process.stdout.write(consoleSummary(result, outRel) + '\n');
    if (prev) {
      const d = compare(prev, result);
      writeFileSync(join(out, 'retest.json'), JSON.stringify({
        fixed: d.fixed.map((f) => f.fingerprint), still_open: d.still.map((f) => f.fingerprint), new: d.added.map((f) => f.fingerprint),
      }, null, 2) + '\n');
      process.stdout.write(`\nRetest: ${d.fixed.length} fixed · ${d.still.length} still open · ${d.added.length} new\n`);
      for (const f of d.fixed) process.stdout.write(`  fixed: ${f.title} (${f.evidence[0].location})\n`);
      for (const f of d.added) process.stdout.write(`  new:   ${f.title} (${f.evidence[0].location})\n`);
    }
  }

  if (result.tools.some((t) => t.status !== 'ok')) return 2;
  if (opts.failOn && atOrAbove(result.findings, opts.failOn).length) return 1;
  return 0;
}

export async function main(argv) {
  let opts;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    process.stderr.write(`${err.message}\n\n${HELP}\n`);
    return 2;
  }
  try {
    switch (opts.command) {
      case 'help': process.stdout.write(HELP + '\n'); return 0;
      case 'version': process.stdout.write(pkg.version + '\n'); return 0;
      case 'tools': {
        for (const [id, t] of Object.entries(lockedTools())) process.stdout.write(`${id.padEnd(12)} ${t.version.padEnd(8)} ${t.license.padEnd(11)} ${t.repo}\n`);
        process.stdout.write(`\nplatform: ${platformKey()}\ncache:    ${cacheDir()}\n`);
        return 0;
      }
      case 'init':
      case 'mcp':
        process.stderr.write(`\`${opts.command}\` is not available yet. See docs/cli.md.\n`);
        return 2;
      default:
        if (opts.advanced) {
          process.stderr.write('`--advanced` is not available yet. Running the basic check only is the default.\n');
          return 2;
        }
        return await runScan(opts, { retest: opts.command === 'retest' });
    }
  } catch (err) {
    process.stderr.write(`error: ${err.message}\n`);
    return 2;
  }
}
