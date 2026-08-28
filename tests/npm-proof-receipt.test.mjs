import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';

test('proof-carrying npm receipt generator is present', () => {
  assert.ok(existsSync(new URL('../scripts/npm-proof-receipt.mjs', import.meta.url)));
});
