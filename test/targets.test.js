import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseTargets, resolveTarget } from '../src/targets.js';

const ok = `# comment
targets:
  - host: Dev.Example.com   # trailing comment
    env: dev
  - host: www.example.com
    port: 8443
    env: prod
`;

test('reads hosts, ports, env and defaults; host names are lower-cased', () => {
  assert.deepEqual(parseTargets(ok), [
    { host: 'dev.example.com', port: 443, env: 'dev' },
    { host: 'www.example.com', port: 8443, env: 'prod' },
  ]);
});

test('anything the reader does not understand is an error, never skipped', () => {
  const cases = [
    '',
    'targets:\n',
    'hosts:\n  - host: a.com\n',
    'targets:\n  - host: https://a.com\n',
    'targets:\n  - host: *.a.com\n',
    'targets:\n  - host: a.com/path\n',
    'targets:\n  - host: a.com\n    port: 99999\n',
    'targets:\n  - host: a.com\n    env: staging\n',
    'targets:\n  - host: a.com\n    nope: 1\n',
    'targets:\n    env: dev\n',
    'targets:\n  - env: dev\n',
    'targets:\n  - host: a..com\n',
    'targets:\n  - host: 10.0.0.0/8\n',
  ];
  for (const c of cases) assert.throws(() => parseTargets(c), Error, JSON.stringify(c));
});

test('only a listed host and port is allowed; case does not matter', () => {
  const t = parseTargets(ok);
  assert.equal(resolveTarget('DEV.example.com', t).host, 'dev.example.com');
  assert.throws(() => resolveTarget('other.example.com', t), /not in the targets file/);
  assert.throws(() => resolveTarget('dev.example.com:8443', t), /not in the targets file/);
});

test('a host in the list does not open its neighbours (sub-domains, parents, similar names)', () => {
  const t = parseTargets(ok);
  for (const h of ['a.dev.example.com', 'example.com', 'dev.example.com.evil.com', 'xdev.example.com']) {
    assert.throws(() => resolveTarget(h, t), /not in the targets file/, h);
  }
});

test('URLs, paths, wildcards and ranges are refused before the list is read', () => {
  const t = parseTargets(ok);
  for (const a of ['https://dev.example.com', 'dev.example.com/x', '*.example.com', '10.0.0.0/24', '', undefined, 'dev.example.com:99999x']) {
    assert.throws(() => resolveTarget(a, t), /host or host:port/, String(a));
  }
});

test('prod needs --allow-prod every time', () => {
  const t = parseTargets(ok);
  assert.throws(() => resolveTarget('www.example.com:8443', t), /--allow-prod/);
  assert.equal(resolveTarget('www.example.com:8443', t, { allowProd: true }).env, 'prod');
});
