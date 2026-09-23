import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const SCRIPT = new URL('../scripts/npm-supply-chain-receipt.mjs', import.meta.url);
const SOURCE_SHA = 'a'.repeat(40);

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, stable(value[key])]),
    );
  }
  return value;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function fixture({
  low = 0,
  totalOverride = null,
  missing = [],
  invalid = [],
  timestamp = '2026-08-28T00:00:00Z',
  serialNumber = 'urn:uuid:first',
} = {}) {
  const root = mkdtempSync(join(tmpdir(), 'guard-supply-chain-'));
  const artifacts = join(root, 'artifacts');
  mkdirSync(artifacts, { recursive: true });

  writeFileSync(
    join(root, 'package-lock.json'),
    JSON.stringify({
      name: 'sovereign-guard',
      version: '1.0.0',
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'sovereign-guard',
          version: '1.0.0',
        },
        'node_modules/tsx': {
          version: '4.23.12',
          resolved: 'https://registry.npmjs.org/tsx/-/tsx-4.23.12.tgz',
        },
        'node_modules/esbuild': {
          version: '0.28.2',
          resolved: 'https://registry.npmjs.org/esbuild/-/esbuild-0.28.2.tgz',
        },
      },
    }) + '\n',
  );
  const packageCore = stable({
    receipt_version: 'NpmPackageReceiptV1',
    source: { repository: 'Aegis-Omega/sovereign-guard', git_sha: SOURCE_SHA },
    package: { name: 'sovereign-guard', version: '1.0.0', sha256: 'b'.repeat(64) },
    verification: {
      authority: 'REMOTE_EXACT_SOURCE_PACK_VERIFIED',
      exact_source_sha_verified: true,
      reproducible_pack_verified: true,
      local_64_suite_bound: false,
    },
  });
  const packageReceipt = stable({
    ...packageCore,
    receipt_sha256: sha256(Buffer.from(`${JSON.stringify(packageCore, null, 2)}\n`)),
  });
  writeFileSync(
    join(artifacts, 'NpmPackageReceiptV1.json'),
    `${JSON.stringify(packageReceipt, null, 2)}\n`,
  );

  const total = totalOverride ?? low;
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
      {
        name: 'tsx',
        version: '4.23.12',
        location: 'node_modules/tsx',
        registry: 'https://registry.npmjs.org/',
        attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } },
      },
      {
        name: 'esbuild',
        version: '0.28.2',
        location: 'node_modules/esbuild',
        registry: 'https://registry.npmjs.org/',
        attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } },
      },
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
        purl: 'pkg:npm/sovereign-guard@1.0.0',
      },
    },
    components: [
      {
        type: 'library',
        name: 'tsx',
        version: '4.23.12',
        'bom-ref': 'tsx@4.23.12',
        purl: 'pkg:npm/tsx@4.23.12',
      },
      {
        type: 'library',
        name: 'esbuild',
        version: '0.28.2',
        'bom-ref': 'esbuild@0.28.2',
        purl: 'pkg:npm/esbuild@0.28.2',
      },
    ],
    dependencies: [
      { ref: 'sovereign-guard@1.0.0', dependsOn: ['tsx@4.23.12'] },
      { ref: 'tsx@4.23.12', dependsOn: ['esbuild@0.28.2'] },
      { ref: 'esbuild@0.28.2', dependsOn: [] },
    ],
  }, null, 2) + '\n');

  return root;
}

function run(root, envOverrides = {}) {
  return spawnSync(process.execPath, [SCRIPT.pathname], {
    cwd: root,
    env: {
      ...process.env,
      AEGIS_SOURCE_SHA: SOURCE_SHA,
      AEGIS_GITHUB_RUN_ID: '33130879805',
      AEGIS_GITHUB_RUN_ATTEMPT: '1',
      AEGIS_GITHUB_RUN_NUMBER: '48',
      AEGIS_GITHUB_WORKFLOW: 'NPM Proof-Carrying Release',
      AEGIS_GITHUB_EVENT_NAME: 'pull_request',
      ...envOverrides,
    },
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
  assert.equal(receipt.observation.provider, 'github-actions');
  assert.equal(receipt.observation.run_id, 33130879805);
  assert.equal(receipt.observation.run_attempt, 1);
  assert.equal(receipt.observation.run_number, 48);
  assert.equal(receipt.observation.workflow, 'NPM Proof-Carrying Release');
  assert.equal(receipt.observation.event_name, 'pull_request');
  assert.match(receipt.package_receipt.receipt_root, /^[0-9a-f]{64}$/);
  assert.equal(receipt.package_receipt.tarball_sha256, 'b'.repeat(64));
  assert.equal(receipt.audit.policy_threshold, 'low');
  assert.equal(receipt.audit.vulnerabilities.total, 0);
  assert.equal(receipt.signatures.missing_count, 0);
  assert.equal(receipt.signatures.invalid_count, 0);
  assert.equal(receipt.signatures.verified_count, 2);
  assert.equal(receipt.signatures.provenance_attestation_count, 2);
  assert.equal(receipt.signatures.lock_bound_verified_count, 2);
  assert.equal(receipt.verification.registry_signatures_lock_bound, true);
  assert.equal(receipt.sbom.normalization.removed_serial_number, true);
  assert.equal(receipt.sbom.normalization.removed_metadata_timestamp, true);
  assert.equal(receipt.sbom.lock_bound_component_count, 2);
  assert.equal(receipt.sbom.dependency_node_count, 3);
  assert.equal(receipt.verification.sbom_lock_bound, true);
  assert.equal(receipt.verification.sbom_graph_closed, true);
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

test('lockfile root package identity mismatch fails closed', () => {
  const root = fixture();
  const path = join(root, 'package-lock.json');
  const lock = JSON.parse(readFileSync(path, 'utf8'));
  lock.packages[''].version = '9.9.9';
  writeFileSync(path, `${JSON.stringify(lock)}\n`);
  const result = run(root);
  assert.notEqual(result.status, 0);
  assert.match(
    `${result.stderr}\n${result.stdout}`,
    /LOCK_ROOT_PACKAGE_IDENTITY_MISMATCH/,
  );
});

test('unexpected lockfile version fails closed', () => {
  const root = fixture();
  const path = join(root, 'package-lock.json');
  const lock = JSON.parse(readFileSync(path, 'utf8'));
  lock.lockfileVersion = 2;
  writeFileSync(path, `${JSON.stringify(lock)}\n`);
  const result = run(root);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /LOCKFILE_VERSION_MISMATCH/);
});

test('tampered package receipt root fails closed before supply authority is emitted', () => {
  const root = fixture();
  const path = join(root, 'artifacts', 'NpmPackageReceiptV1.json');
  const receipt = JSON.parse(readFileSync(path, 'utf8'));
  receipt.receipt_sha256 = '0'.repeat(64);
  writeFileSync(path, `${JSON.stringify(receipt, null, 2)}\n`);
  const result = run(root);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /PACKAGE_RECEIPT_ROOT_INVALID/);
});

test('foreign SBOM component fails closed even when structurally valid', () => {
  const root = fixture();
  const path = join(root, 'artifacts', 'sbom.cdx.json');
  const sbom = JSON.parse(readFileSync(path, 'utf8'));
  sbom.components.push({
    type: 'library',
    name: 'not-locked',
    version: '1.0.0',
    'bom-ref': 'not-locked@1.0.0',
    purl: 'pkg:npm/not-locked@1.0.0',
  });
  sbom.dependencies.push({ ref: 'not-locked@1.0.0', dependsOn: [] });
  writeFileSync(path, `${JSON.stringify(sbom, null, 2)}\n`);
  const result = run(root);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /SBOM_COMPONENT_NOT_LOCKED/);
});

test('dangling SBOM dependency target fails closed', () => {
  const root = fixture();
  const path = join(root, 'artifacts', 'sbom.cdx.json');
  const sbom = JSON.parse(readFileSync(path, 'utf8'));
  sbom.dependencies[0].dependsOn.push('ghost@1.0.0');
  writeFileSync(path, `${JSON.stringify(sbom, null, 2)}\n`);
  const result = run(root);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /SBOM_DEPENDENCY_TARGET_UNKNOWN/);
});

test('one LOW vulnerability fails closed', () => {
  const result = run(fixture({ low: 1 }));
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /AUDIT_VULNERABILITY_DEBT/);
});

test('inconsistent npm audit total fails closed', () => {
  const result = run(fixture({ low: 1, totalOverride: 0 }));
  assert.notEqual(result.status, 0);
  assert.match(
    `${result.stderr}\n${result.stdout}`,
    /AUDIT_VULNERABILITY_TOTAL_MISMATCH/,
  );
});

test('verified registry signature must bind to an exact lockfile location and version', () => {
  const root = fixture();
  const path = join(root, 'artifacts', 'npm-signatures.json');
  const signatures = JSON.parse(readFileSync(path, 'utf8'));
  signatures.verified[0].version = '9.9.9';
  writeFileSync(path, `${JSON.stringify(signatures, null, 2)}\n`);
  const result = run(root);
  assert.notEqual(result.status, 0);
  assert.match(
    `${result.stderr}\n${result.stdout}`,
    /REGISTRY_SIGNATURE_PACKAGE_VERSION_MISMATCH/,
  );
});

test('verified registry signature for an unlocked location fails closed', () => {
  const root = fixture();
  const path = join(root, 'artifacts', 'npm-signatures.json');
  const signatures = JSON.parse(readFileSync(path, 'utf8'));
  signatures.verified[0].location = 'node_modules/not-locked';
  signatures.verified[0].name = 'not-locked';
  writeFileSync(path, `${JSON.stringify(signatures, null, 2)}\n`);
  const result = run(root);
  assert.notEqual(result.status, 0);
  assert.match(
    `${result.stderr}\n${result.stdout}`,
    /REGISTRY_SIGNATURE_LOCK_ENTRY_MISSING/,
  );
});

test('missing or invalid registry signature fails closed', () => {
  const missing = run(fixture({ missing: [{ name: 'dependency-x', version: '1.0.0' }] }));
  assert.notEqual(missing.status, 0);
  assert.match(`${missing.stderr}\n${missing.stdout}`, /REGISTRY_SIGNATURE_DEBT/);

  const invalid = run(fixture({ invalid: [{ name: 'dependency-y', version: '2.0.0' }] }));
  assert.notEqual(invalid.status, 0);
  assert.match(`${invalid.stderr}\n${invalid.stdout}`, /REGISTRY_SIGNATURE_DEBT/);
});


test('missing hosted-run identity fails closed', () => {
  const result = run(fixture(), { AEGIS_GITHUB_RUN_ID: '' });
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /OBSERVATION_ENV_MISSING/);
});
