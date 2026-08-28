import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

function command(bin, args, cwd = root) {
  return execFileSync(bin, args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

function packOnce() {
  const result = JSON.parse(command('npm', ['pack', '--json', '--ignore-scripts']));
  assert.equal(result.length, 1);
  const meta = result[0];
  const path = resolve(root, meta.filename);
  const bytes = readFileSync(path);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  rmSync(path, { force: true });
  return { meta, bytes, sha256 };
}

test('npm pack is byte-for-byte reproducible from the same built tree', () => {
  const first = packOnce();
  const second = packOnce();
  assert.equal(first.sha256, second.sha256);
  assert.equal(first.meta.shasum, second.meta.shasum);
  assert.equal(first.meta.integrity, second.meta.integrity);
  assert.deepEqual(
    first.meta.files.map(({ path, size, mode }) => ({ path, size, mode })),
    second.meta.files.map(({ path, size, mode }) => ({ path, size, mode })),
  );
});

test('packed artifact installs and both declared CLI bins execute', () => {
  const packed = packOnce();
  const tarball = resolve(root, packed.meta.filename);
  // packOnce removes the file after hashing, so recreate the exact deterministic tarball once.
  const recreated = JSON.parse(command('npm', ['pack', '--json', '--ignore-scripts']))[0];
  const recreatedPath = resolve(root, recreated.filename);
  assert.equal(
    createHash('sha256').update(readFileSync(recreatedPath)).digest('hex'),
    packed.sha256,
  );

  const sandbox = mkdtempSync(join(tmpdir(), 'sovereign-guard-pack-'));
  try {
    command('npm', ['init', '-y'], sandbox);
    command(
      'npm',
      ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', recreatedPath],
      sandbox,
    );

    const suffix = process.platform === 'win32' ? '.cmd' : '';
    const sovereignBin = join(sandbox, 'node_modules', '.bin', `sovereign-guard${suffix}`);
    const guardBin = join(sandbox, 'node_modules', '.bin', `guard${suffix}`);
    assert.equal(command(sovereignBin, ['--version'], sandbox), pkg.version);
    assert.equal(command(guardBin, ['--version'], sandbox), pkg.version);
  } finally {
    rmSync(recreatedPath, { force: true });
    rmSync(sandbox, { recursive: true, force: true });
  }
});
