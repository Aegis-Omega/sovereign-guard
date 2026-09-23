import test from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluateRegistryMetadata,
  evaluateReleaseMode,
} from '../scripts/npm-release-mode-guard.mjs';

test('trusted-stage requires an existing registry package', () => {
  assert.deepEqual(
    evaluateReleaseMode('trusted-stage', 'PACKAGE_PRESENT', 'VERSION_ABSENT'),
    {
      mode: 'trusted-stage',
      registry_state: 'PACKAGE_PRESENT',
      version_state: 'VERSION_ABSENT',
    },
  );
  assert.throws(
    () => evaluateReleaseMode('trusted-stage', 'PACKAGE_ABSENT', 'VERSION_ABSENT'),
    /TRUSTED_STAGE_REQUIRES_EXISTING_PACKAGE/,
  );
});

test('bootstrap-token is restricted to first publication', () => {
  assert.deepEqual(
    evaluateReleaseMode('bootstrap-token', 'PACKAGE_ABSENT', 'VERSION_ABSENT'),
    {
      mode: 'bootstrap-token',
      registry_state: 'PACKAGE_ABSENT',
      version_state: 'VERSION_ABSENT',
    },
  );
  assert.throws(
    () => evaluateReleaseMode('bootstrap-token', 'PACKAGE_PRESENT', 'VERSION_ABSENT'),
    /BOOTSTRAP_TOKEN_REQUIRES_ABSENT_PACKAGE/,
  );
});

test('unknown mode or registry state fails closed', () => {
  assert.throws(
    () => evaluateReleaseMode('anything-else', 'PACKAGE_PRESENT', 'VERSION_ABSENT'),
    /RELEASE_MODE_INVALID/,
  );
  assert.throws(
    () => evaluateReleaseMode('trusted-stage', 'UNKNOWN', 'VERSION_ABSENT'),
    /REGISTRY_STATE_INVALID/,
  );
});


test('already-published package version fails closed in every release mode', () => {
  assert.throws(
    () => evaluateReleaseMode('trusted-stage', 'PACKAGE_PRESENT', 'VERSION_PRESENT'),
    /RELEASE_VERSION_ALREADY_PUBLISHED/,
  );
  assert.throws(
    () => evaluateReleaseMode('bootstrap-token', 'PACKAGE_ABSENT', 'VERSION_PRESENT'),
    /RELEASE_VERSION_ALREADY_PUBLISHED/,
  );
});

test('unknown version state fails closed', () => {
  assert.throws(
    () => evaluateReleaseMode('trusted-stage', 'PACKAGE_PRESENT', 'UNKNOWN'),
    /VERSION_STATE_INVALID/,
  );
});


test('registry metadata must expose a valid versions map', () => {
  assert.throws(
    () => evaluateRegistryMetadata('sovereign-guard', '1.0.0', {
      name: 'sovereign-guard',
    }),
    /NPM_REGISTRY_VERSIONS_INVALID/,
  );
  assert.throws(
    () => evaluateRegistryMetadata('sovereign-guard', '1.0.0', {
      name: 'sovereign-guard',
      versions: [],
    }),
    /NPM_REGISTRY_VERSIONS_INVALID/,
  );
});

test('registry metadata binds exact package identity and target version state', () => {
  assert.deepEqual(
    evaluateRegistryMetadata('sovereign-guard', '1.0.0', {
      name: 'sovereign-guard',
      versions: { '0.9.0': {} },
    }),
    { registryState: 'PACKAGE_PRESENT', versionState: 'VERSION_ABSENT' },
  );
  assert.deepEqual(
    evaluateRegistryMetadata('sovereign-guard', '1.0.0', {
      name: 'sovereign-guard',
      versions: { '1.0.0': {} },
    }),
    { registryState: 'PACKAGE_PRESENT', versionState: 'VERSION_PRESENT' },
  );
  assert.throws(
    () => evaluateRegistryMetadata('sovereign-guard', '1.0.0', {
      name: 'different-package',
      versions: {},
    }),
    /NPM_REGISTRY_PACKAGE_IDENTITY_MISMATCH/,
  );
});
