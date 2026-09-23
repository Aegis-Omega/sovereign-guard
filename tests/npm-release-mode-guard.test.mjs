import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateReleaseMode } from '../scripts/npm-release-mode-guard.mjs';

test('trusted-stage requires an existing registry package', () => {
  assert.deepEqual(
    evaluateReleaseMode('trusted-stage', 'PACKAGE_PRESENT'),
    { mode: 'trusted-stage', registry_state: 'PACKAGE_PRESENT' },
  );
  assert.throws(
    () => evaluateReleaseMode('trusted-stage', 'PACKAGE_ABSENT'),
    /TRUSTED_STAGE_REQUIRES_EXISTING_PACKAGE/,
  );
});

test('bootstrap-token is restricted to first publication', () => {
  assert.deepEqual(
    evaluateReleaseMode('bootstrap-token', 'PACKAGE_ABSENT'),
    { mode: 'bootstrap-token', registry_state: 'PACKAGE_ABSENT' },
  );
  assert.throws(
    () => evaluateReleaseMode('bootstrap-token', 'PACKAGE_PRESENT'),
    /BOOTSTRAP_TOKEN_REQUIRES_ABSENT_PACKAGE/,
  );
});

test('unknown mode or registry state fails closed', () => {
  assert.throws(
    () => evaluateReleaseMode('anything-else', 'PACKAGE_PRESENT'),
    /RELEASE_MODE_INVALID/,
  );
  assert.throws(
    () => evaluateReleaseMode('trusted-stage', 'UNKNOWN'),
    /REGISTRY_STATE_INVALID/,
  );
});
