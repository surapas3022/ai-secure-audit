import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const lock = JSON.parse(readFileSync(new URL('../tools.lock.json', import.meta.url), 'utf8'));
const PLATFORMS = ['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64', 'win32-arm64', 'win32-x64'];

test('every basic tool is pinned for every platform with a sha256 and a GitHub release URL', () => {
  for (const id of ['gitleaks', 'osv-scanner', 'trivy']) {
    const t = lock.tools[id];
    assert.ok(t, id);
    assert.match(t.version, /^\d+\.\d+\.\d+$/);
    for (const p of PLATFORMS) {
      const e = t.platforms[p];
      assert.ok(e, `${id} ${p}`);
      assert.match(e.sha256, /^[0-9a-f]{64}$/);
      assert.ok(e.url.startsWith(`https://github.com/`) && e.url.includes(`/releases/download/v${t.version}/`), e.url);
      assert.ok(['tar.gz', 'zip', 'raw'].includes(e.archive));
    }
  }
});
