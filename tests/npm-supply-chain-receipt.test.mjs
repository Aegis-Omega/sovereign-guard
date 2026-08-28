import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const SCRIPT = new URL('../scripts/npm-supply-chain-receipt.mjs', import.meta.url);
const SOURCE_SHA = 'a'.repeat(40);

function fixture({ low = 0, missing = [], invalid = [], timestamp = '2026-08-28T00:00:00Z', serialNumber = 'urn:uuid:first' } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'guard-supply-chain-'));
  const artifacts = join(root, 'artifacts');
  mkdirSync(artifacts, { recursive: true });

  writeFileSync(join(root, 'package-lock.json'), JSON.stringify({ name: 'sovereign-guard', version: '1.0.0', lockfileVersion: 3 }) + '\n');
  writeFileSync(join(artifacts, 'NpmPackageReceiptV1.json'), JSON.stringify({
    receipt_version: 'NpmPackageReceiptV1',
    source: { repository: 'Aegis-Omega/sovereign-guard', git_sha: SOURCE_SHA },
    package: { name: 'sovereign-guard', version: '1.0.0', sha256: 'b'.repeat(64) },
    verification: {
      authority: 'REMOTE_EXACT_SOURCE_PACK_VERIFIED',
      exact_source_sha_verified: true,
      reproducible_pack_verified: true,
      local_64_suite_bound: false,
    },
    receipt_sha256: 'c'.repeat(64),
  }, null, 2) + '\n');

  const total = low;
  writeFileSync(join(artifacts, 'npm-audit.json'), JSON.stringify({
    vulnerabilities: {},
    metadata: {
      vulnerabilities: { info: 0, low, moderate: 0, high: 0, critical: 0, total },
      dependencies: { prod: 12, dev: 32, optional: 27, peer: 1, peerOptional: 0, total: 44 },
    },
  }, null, 2) + '\n');

  writeFileSync(join(artifacts, 'npm-signatures.json'), JSON.stringify({
    invalid,
    missing,
    verified: [
      { name: 'tsx', version: '4.23.12', attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } },
      { name: 'esbuild', version: '0.28.2', attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } },
    ],
  }, null, 2) + '\n');

  writeFileSync(join(artifacts, 'sbom.cdx.json'), JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber,
    version: 1,
    metadata: {
      timestamp,
      component: {
        type: 'library',
        name: 'sovereign-guard',
        version: '1.0.0',
        'bom-ref': 'sovereign-guard@1.0.0',
      },
    },
    components: [
      { type: 'library', name: 'tsx', version: '4.23.12', 'bom-ref': 'tsx@4.23.12' },
      { type: 'library', name: 'esbuild', version: '0.28.2', 'bom-ref': 'esbuild@0.28.2' },
    ],
    dependencies: [],
  }, null, 2) + '\n');

  return root;
}

function run(root) {
  return spawnSync(process.execPath, [SCRIPT.pathname], {
    cwd: root,
    env: { ...process.env, AEGIS_SOURCE_SHA: SOURCE_SHA },
    encoding: 'utf8',
  });
}

test('supply-chain receipt generator is committed', () => {
  assert.ok(existsSync(SCRIPT), 'missing scripts/npm-supply-chain-receipt.mjs');
});

test('supply-chain receipt binds exact source, package receipt, lock, audit, signatures and normalized SBOM', () => {
  const root = fixture();
  const result = run(root);
  assert.equal(result.status, 0, result.stderr || result.stdout);

  const receipt = JSON.parse(readFileSync(join(root, 'artifacts', 'NpmSupplyChainReceiptV1.json'), 'utf8'));
  assert.equal(receipt.receipt_version, 'NpmSupplyChainReceiptV1');
  assert.equal(receipt.source.git_sha, SOURCE_SHA);
  assert.equal(receipt.package_receipt.receipt_root, 'c'.repeat(64));
  assert.equal(receipt.package_receipt.tarball_sha256, 'b'.repeat(64));
  assert.equal(receipt.audit.policy_threshold, 'low');
  assert.equal(receipt.audit.vulnerabilities.total, 0);
  assert.equal(receipt.signatures.missing_count, 0);
  assert.equal(receipt.signatures.invalid_count, 0);
  assert.equal(receipt.signatures.verified_count, 2);
  assert.equal(receipt.signatures.provenance_attestation_count, 2);
  assert.equal(receipt.sbom.normalization.removed_serial_number, true);
  assert.equal(receipt.sbom.normalization.removed_metadata_timestamp, true);
  assert.match(receipt.sbom.normalized_sha256, /^[0-9a-f]{64}$/);
  assert.match(receipt.lockfile.sha256, /^[0-9a-f]{64}$/);
  assert.equal(receipt.verification.authority, 'REMOTE_EXACT_SOURCE_SUPPLY_CHAIN_VERIFIED');
  assert.equal(receipt.verification.local_64_suite_bound, false);
  assert.match(receipt.receipt_sha256, /^[0-9a-f]{64}$/);
});

test('CycloneDX timestamp and serial number cannot perturb normalized supply-chain identity', () => {
  const first = fixture({ timestamp: '2026-08-28T00:00:00Z', serialNumber: 'urn:uuid:first' });
  const second = fixture({ timestamp: '2099-01-01T12:34:56Z', serialNumber: 'urn:uuid:second' });
  assert.equal(run(first).status, 0);
  assert.equal(run(second).status, 0);

  const a = JSON.parse(readFileSync(join(first, 'artifacts', 'NpmSupplyChainReceiptV1.json'), 'utf8'));
  const b = JSON.parse(readFileSync(join(second, 'artifacts', 'NpmSupplyChainReceiptV1.json'), 'utf8'));
  assert.equal(a.sbom.normalized_sha256, b.sbom.normalized_sha256);
  assert.equal(a.receipt_sha256, b.receipt_sha256);
});

test('one LOW vulnerability fails closed', () => {
  const result = run(fixture({ low: 1 }));
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /AUDIT_VULNERABILITY_DEBT/);
});

test('missing or invalid registry signature fails closed', () => {
  const missing = run(fixture({ missing: [{ name: 'dependency-x', version: '1.0.0' }] }));
  assert.notEqual(missing.status, 0);
  assert.match(`${missing.stderr}\n${missing.stdout}`, /REGISTRY_SIGNATURE_DEBT/);

  const invalid = run(fixture({ invalid: [{ name: 'dependency-y', version: '2.0.0' }] }));
  assert.notEqual(invalid.status, 0);
  assert.match(`${invalid.stderr}\n${invalid.stdout}`, /REGISTRY_SIGNATURE_DEBT/);
});
