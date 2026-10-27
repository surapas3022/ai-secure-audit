#!/usr/bin/env node
// Builds a small fake app with security mistakes, as its own git repository, for demos and tests.
//
//   node examples/vulnerable-app/setup.mjs [folder]     (default: ./vulnerable-app-demo)
//
// Every key is random and fake, generated when this script runs. No real or real-looking key is stored
// in this repository, so nothing here can leak, and GitHub push protection is not triggered.
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const target = resolve(process.argv[2] ?? 'vulnerable-app-demo');
if (existsSync(target) && readdirSync(target).length) {
  console.error(`${target} is not empty. Choose another folder or delete it first.`);
  process.exit(2);
}

const ALNUM = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const random = (n) => [...randomBytes(n)].map((b) => ALNUM[b % ALNUM.length]).join('');
// Built from parts so the repository itself never contains a key-shaped string.
const fakeStripeKey = () => ['sk', 'test', random(32)].join('_');
const fakeSecret = () => random(40);

const git = (...args) => execFileSync('git', ['-C', target, ...args], { stdio: 'pipe' });
const write = (file, text) => {
  mkdirSync(join(target, file, '..'), { recursive: true });
  writeFileSync(join(target, file), text);
};
const commit = (message) => {
  git('add', '-A');
  git('-c', 'user.name=Demo', '-c', 'user.email=demo@example.invalid', 'commit', '-q', '-m', message);
};

mkdirSync(target, { recursive: true });
git('init', '-q');

// Commit 1: a normal start.
write('package.json', JSON.stringify({ name: 'vulnerable-app-demo', private: true, version: '1.0.0' }, null, 2) + '\n');
write('README.md', '# Demo shop\n\nA fake app made by ai-secure-audit for demos. Every key in it is fake.\n');
write('.gitignore', 'node_modules/\n');
commit('Start project');

// Commit 2: mistake 1, a .env file committed with a payment key.
write('.env', `STRIPE_SECRET_KEY=${fakeStripeKey()}\n`);
write('src/server/payment.js', "export const stripeKey = process.env.STRIPE_SECRET_KEY;\n");
commit('Add payments');

// Commit 3: someone notices and deletes .env. The key is gone from the files, but not from git history.
rmSync(join(target, '.env'));
write('.gitignore', 'node_modules/\n.env\n');
commit('Remove .env');

// Commit 4: mistake 2, a secret in a variable that the frontend build makes public.
write('src/web/config.js', [
  '// NEXT_PUBLIC_* values are bundled into the JavaScript every visitor downloads.',
  `export const NEXT_PUBLIC_API_SECRET = "${fakeSecret()}";`,
  '',
].join('\n'));
commit('Add web config');

console.log(`Fake app created at ${target}`);
console.log('It has 2 mistakes, one of them only in git history. Check it with:');
console.log(`  node bin/ai-secure-audit.js ${target}`);
