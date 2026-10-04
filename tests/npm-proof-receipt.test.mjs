import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const SCRIPT = new URL('../scripts/npm-proof-receipt.mjs', import.meta.url);

test('proof-carrying npm receipt generator is present', () => {
  assert.ok(existsSync(SCRIPT));
});

test('package receipt independently binds npm metadata census to actual tar contents', () => {
  const git = spawnSync('git', ['rev-parse', 'HEAD'], {
    cwd: new URL('..', import.meta.url),
    encoding: 'utf8',
  });
  assert.equal(git.status, 0, git.stderr || git.stdout);
  const sourceSha = git.stdout.trim();

  const result = spawnSync(process.execPath, [SCRIPT.pathname], {
    cwd: new URL('..', import.meta.url),
    env: { ...process.env, AEGIS_SOURCE_SHA: sourceSha },
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);

  const receipt = JSON.parse(
    readFileSync(new URL('../artifacts/NpmPackageReceiptV1.json', import.meta.url), 'utf8'),
  );
  assert.equal(receipt.package.filename, `sovereign-guard-${receipt.package.version}.tgz`);
  assert.equal(receipt.package.tar_file_count, receipt.package.file_count);
  assert.equal(receipt.package.tar_census_matches_npm_metadata, true);
  assert.equal(receipt.package.tar_paths_safe, true);
  assert.equal(receipt.package.tar_regular_files_only, true);
  assert.equal(receipt.package.tar_permissions_safe, true);
  assert.equal(receipt.package.publish_path_allowlist_verified, true);
  assert.equal(receipt.package.packed_manifest_canonical_equal, true);
  assert.equal(receipt.package.public_entrypoints_verified, true);
  assert.equal(receipt.package.publish_config_verified, true);
  assert.equal(receipt.package.required_entrypoints_present_in_tar, true);
  assert.equal(receipt.verification.canonical_filename_verified, true);
  assert.equal(receipt.verification.tar_census_independently_verified, true);
  assert.equal(receipt.verification.tar_paths_safe, true);
  assert.equal(receipt.verification.tar_regular_files_only, true);
  assert.equal(receipt.verification.tar_permissions_safe, true);
  assert.equal(receipt.verification.publish_path_allowlist_verified, true);
  assert.equal(receipt.verification.packed_manifest_canonical_equal, true);
  assert.equal(receipt.verification.public_entrypoints_verified, true);
  assert.equal(receipt.verification.publish_config_verified, true);
  assert.equal(receipt.verification.required_entrypoints_present_in_tar, true);
  assert.equal(receipt.reproducibility.tar_file_census_equal, true);
  assert.match(receipt.package.tar_file_census_sha256, /^[0-9a-f]{64}$/);
});
