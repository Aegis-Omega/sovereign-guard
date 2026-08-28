import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { existsSync, readFileSync } from 'node:fs';

const require = createRequire(import.meta.url);
const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));

test('package identity is sovereign-guard', () => {
  assert.equal(pkg.name, 'sovereign-guard');
  assert.match(pkg.version, /^\d+\.\d+\.\d+(?:[-+].*)?$/);
});

test('build outputs declared package entrypoints', () => {
  assert.ok(existsSync(new URL('../dist/src/index.js', import.meta.url)), 'missing dist/src/index.js');
  assert.ok(existsSync(new URL('../dist/src/index.d.ts', import.meta.url)), 'missing dist/src/index.d.ts');
  assert.ok(existsSync(new URL('../dist/bin/guard.js', import.meta.url)), 'missing dist/bin/guard.js');
});

test('compiled public API loads and exposes core entrypoints', () => {
  const api = require('../dist/src/index.js');
  assert.equal(typeof api.runScan, 'function');
  assert.equal(typeof api.generatePatch, 'function');
  assert.equal(typeof api.generateSeal, 'function');
  assert.equal(typeof api.loadConfig, 'function');
  assert.ok(Array.isArray(api.ALL_RULES));
});

test('package exposes no lifecycle install hooks', () => {
  for (const hook of ['preinstall', 'install', 'postinstall']) {
    assert.equal(pkg.scripts?.[hook], undefined, `unexpected lifecycle hook: ${hook}`);
  }
});
