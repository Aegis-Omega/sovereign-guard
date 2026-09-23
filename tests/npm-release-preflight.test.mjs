import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const SCRIPT = new URL('../scripts/npm-release-preflight.mjs', import.meta.url);
const SOURCE_SHA = 'a'.repeat(40);
const RUN_ID = '35911711346';
const RUN_ATTEMPT = '2';

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

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

function canonicalSha256(value) {
  return sha256(Buffer.from(JSON.stringify(stable(value))));
}

function normalizeSbom(input) {
  const sbom = structuredClone(input);
  delete sbom.serialNumber;
  if (sbom.metadata) delete sbom.metadata.timestamp;
  return sbom;
}

function writeManifest(f) {
  const names = [
    'NpmPackageReceiptV1.json',
    'NpmSupplyChainReceiptV1.json',
    'npm-audit.json',
    'npm-signatures.json',
    'sbom.cdx.json',
  ];
  const lines = names.map((name) => {
    const path = join(f.artifacts, name);
    return `${sha256(readFileSync(path))}  artifacts/${name}`;
  });
  writeFileSync(f.manifestPath, `${lines.join('\n')}\n`);
}

function refreshSupply(f, mutate = () => {}) {
  const supply = JSON.parse(readFileSync(f.supplyPath, 'utf8'));
  mutate(supply);
  const core = structuredClone(supply);
  delete core.receipt_sha256;
  supply.receipt_sha256 = canonicalSha256(core);
  writeFileSync(f.supplyPath, `${JSON.stringify(supply, null, 2)}\n`);
  writeManifest(f);
}

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'guard-release-preflight-'));
  const evidenceRoot = join(root, 'verified-package');
  const artifacts = join(evidenceRoot, 'artifacts');
  mkdirSync(artifacts, { recursive: true });

  const lock = {
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
    },
  };
  const lockPath = join(root, 'package-lock.json');
  writeFileSync(lockPath, `${JSON.stringify(lock)}\n`);

  const tarball = join(evidenceRoot, 'sovereign-guard-1.0.0.tgz');
  writeFileSync(tarball, Buffer.from('deterministic-release-preflight-fixture'));
  const tarballSha256 = sha256(readFileSync(tarball));

  const pkgCore = stable({
    receipt_version: 'NpmPackageReceiptV1',
    source: {
      repository: 'Aegis-Omega/sovereign-guard',
      git_sha: SOURCE_SHA,
    },
    package: {
      name: 'sovereign-guard',
      version: '1.0.0',
      sha256: tarballSha256,
    },
    reproducibility: {
      independent_pack_count: 2,
      byte_for_byte_equal: true,
    },
    verification: {
      authority: 'REMOTE_EXACT_SOURCE_PACK_VERIFIED',
      exact_source_sha_verified: true,
      reproducible_pack_verified: true,
      local_64_suite_bound: false,
    },
    non_claims: {
      operator_reported_64_suite_authenticated: false,
      aegis_mathematical_claims_established: false,
    },
  });
  const pkgReceipt = stable({
    ...pkgCore,
    receipt_sha256: sha256(Buffer.from(`${JSON.stringify(pkgCore, null, 2)}\n`)),
  });
  const pkgPath = join(artifacts, 'NpmPackageReceiptV1.json');
  writeFileSync(pkgPath, `${JSON.stringify(pkgReceipt, null, 2)}\n`);
  const pkgFileSha256 = sha256(readFileSync(pkgPath));

  const audit = {
    metadata: {
      vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 },
      dependencies: { prod: 1, dev: 0, optional: 0, peer: 0, peerOptional: 0, total: 1 },
    },
  };
  const auditPath = join(artifacts, 'npm-audit.json');
  writeFileSync(auditPath, `${JSON.stringify(audit, null, 2)}\n`);

  const signatures = {
    invalid: [],
    missing: [],
    verified: [
      {
        name: 'tsx',
        version: '4.23.12',
        location: 'node_modules/tsx',
        registry: 'https://registry.npmjs.org/',
        attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } },
      },
    ],
  };
  const signaturesPath = join(artifacts, 'npm-signatures.json');
  writeFileSync(signaturesPath, `${JSON.stringify(signatures, null, 2)}\n`);

  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: 'urn:uuid:fixture',
    metadata: {
      timestamp: '2026-09-23T00:00:00Z',
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
    ],
    dependencies: [
      { ref: 'sovereign-guard@1.0.0', dependsOn: ['tsx@4.23.12'] },
      { ref: 'tsx@4.23.12', dependsOn: [] },
    ],
  };
  const sbomPath = join(artifacts, 'sbom.cdx.json');
  writeFileSync(sbomPath, `${JSON.stringify(sbom, null, 2)}\n`);

  const supplyCore = {
    receipt_version: 'NpmSupplyChainReceiptV1',
    source: {
      repository: 'Aegis-Omega/sovereign-guard',
      git_sha: SOURCE_SHA,
    },
    observation: {
      provider: 'github-actions',
      run_id: Number(RUN_ID),
      run_attempt: Number(RUN_ATTEMPT),
      run_number: 74,
      workflow: 'NPM Verified Release',
      event_name: 'release',
    },
    package: {
      name: 'sovereign-guard',
      version: '1.0.0',
    },
    package_receipt: {
      receipt_root: pkgReceipt.receipt_sha256,
      file_sha256: pkgFileSha256,
      tarball_sha256: tarballSha256,
      authority: 'REMOTE_EXACT_SOURCE_PACK_VERIFIED',
    },
    lockfile: {
      lockfile_version: 3,
      sha256: sha256(readFileSync(lockPath)),
    },
    audit: {
      vulnerabilities: audit.metadata.vulnerabilities,
      dependencies: audit.metadata.dependencies,
      lock_package_count: 1,
      canonical_sha256: canonicalSha256(audit),
    },
    signatures: {
      verified_count: 1,
      missing_count: 0,
      invalid_count: 0,
      provenance_attestation_count: 1,
      lock_bound_verified_count: 1,
      canonical_sha256: canonicalSha256(signatures),
    },
    sbom: {
      format: 'CycloneDX',
      spec_version: '1.6',
      lock_bound_component_count: 1,
      dependency_node_count: 2,
      normalized_sha256: canonicalSha256(normalizeSbom(sbom)),
    },
    verification: {
      authority: 'REMOTE_EXACT_SOURCE_SUPPLY_CHAIN_VERIFIED',
      exact_source_sha_verified: true,
      package_receipt_bound: true,
      lockfile_bound: true,
      zero_vulnerability_snapshot_verified: true,
      audit_lock_graph_count_bound: true,
      registry_signatures_verified: true,
      registry_signatures_lock_bound: true,
      provenance_attestations_observed: true,
      normalized_sbom_bound: true,
      sbom_lock_bound: true,
      sbom_graph_closed: true,
      local_64_suite_bound: false,
    },
  };
  const supplyReceipt = {
    ...supplyCore,
    receipt_sha256: canonicalSha256(supplyCore),
  };
  const supplyPath = join(artifacts, 'NpmSupplyChainReceiptV1.json');
  writeFileSync(supplyPath, `${JSON.stringify(supplyReceipt, null, 2)}\n`);

  const manifestPath = join(artifacts, 'supply-chain.sha256');
  const f = {
    root,
    evidenceRoot,
    artifacts,
    lockPath,
    tarball,
    pkgPath,
    auditPath,
    signaturesPath,
    sbomPath,
    supplyPath,
    manifestPath,
  };
  writeManifest(f);
  return f;
}

function run(f, env = {}) {
  return spawnSync(process.execPath, [SCRIPT.pathname, f.tarball], {
    cwd: f.root,
    env: {
      ...process.env,
      VERIFIED_PACKAGE_ROOT: f.evidenceRoot,
      EXPECTED_SOURCE_SHA: SOURCE_SHA,
      EXPECTED_RUN_ID: RUN_ID,
      EXPECTED_RUN_ATTEMPT: RUN_ATTEMPT,
      ...env,
    },
    encoding: 'utf8',
  });
}

test('release preflight accepts fully bound release evidence', () => {
  const f = fixture();
  const result = run(f);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const output = JSON.parse(result.stdout);
  assert.equal(output.status, 'RELEASE_PREFLIGHT_VERIFIED');
  assert.equal(output.source_sha, SOURCE_SHA);
  assert.equal(output.evidence_manifest_entries, 5);
});

test('manifest mismatch fails before receipt admission', () => {
  const f = fixture();
  writeFileSync(f.auditPath, '{}\n');
  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /EVIDENCE_MANIFEST_DIGEST_MISMATCH/);
});

test('tampered package receipt fails closed even if manifest is refreshed', () => {
  const f = fixture();
  const pkg = JSON.parse(readFileSync(f.pkgPath, 'utf8'));
  pkg.package.version = '9.9.9';
  writeFileSync(f.pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);
  writeManifest(f);
  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /SUPPLY_CHAIN_PACKAGE_IDENTITY_MISMATCH|PACKAGE_RECEIPT_ROOT_INVALID/);
});

test('lockfile root package identity mismatch fails closed before hash admission', () => {
  const f = fixture();
  const lock = JSON.parse(readFileSync(f.lockPath, 'utf8'));
  lock.packages[''].version = '9.9.9';
  writeFileSync(f.lockPath, `${JSON.stringify(lock)}\n`);
  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(
    `${result.stderr}\n${result.stdout}`,
    /LOCK_ROOT_PACKAGE_IDENTITY_MISMATCH/,
  );
});

test('unexpected lockfile version fails closed', () => {
  const f = fixture();
  const lock = JSON.parse(readFileSync(f.lockPath, 'utf8'));
  lock.lockfileVersion = 2;
  writeFileSync(f.lockPath, `${JSON.stringify(lock)}\n`);
  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /LOCKFILE_VERSION_MISMATCH/);
});

test('source lockfile mismatch fails closed', () => {
  const f = fixture();
  writeFileSync(f.lockPath, '{"name":"sovereign-guard","version":"9.9.9","lockfileVersion":3}\n');
  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /LOCKFILE_HASH_MISMATCH/);
});

test('audit dependency total must equal the locked graph size', () => {
  const f = fixture();
  const audit = JSON.parse(readFileSync(f.auditPath, 'utf8'));
  audit.metadata.dependencies.total = 999;
  writeFileSync(f.auditPath, `${JSON.stringify(audit, null, 2)}\n`);
  refreshSupply(f, (supply) => {
    supply.audit.dependencies = audit.metadata.dependencies;
    supply.audit.lock_package_count = 1;
    supply.audit.canonical_sha256 = canonicalSha256(audit);
  });
  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /AUDIT_LOCK_GRAPH_COUNT_MISMATCH/);
});

test('audit evidence hash mismatch fails closed', () => {
  const f = fixture();
  const audit = JSON.parse(readFileSync(f.auditPath, 'utf8'));
  audit.metadata.dependencies.total = 999;
  writeFileSync(f.auditPath, `${JSON.stringify(audit, null, 2)}\n`);
  writeManifest(f);
  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /AUDIT_EVIDENCE_HASH_MISMATCH/);
});

test('non-zero vulnerability snapshot fails closed with internally consistent evidence', () => {
  const f = fixture();
  const audit = JSON.parse(readFileSync(f.auditPath, 'utf8'));
  audit.metadata.vulnerabilities.low = 1;
  audit.metadata.vulnerabilities.total = 1;
  writeFileSync(f.auditPath, `${JSON.stringify(audit, null, 2)}\n`);
  refreshSupply(f, (supply) => {
    supply.audit.vulnerabilities = audit.metadata.vulnerabilities;
    supply.audit.canonical_sha256 = canonicalSha256(audit);
  });
  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /NON_ZERO_VULNERABILITY_SNAPSHOT/);
});

test('inconsistent audit total fails closed even when receipt and manifest are refreshed', () => {
  const f = fixture();
  const audit = JSON.parse(readFileSync(f.auditPath, 'utf8'));
  audit.metadata.vulnerabilities.low = 1;
  audit.metadata.vulnerabilities.total = 0;
  writeFileSync(f.auditPath, `${JSON.stringify(audit, null, 2)}\n`);
  refreshSupply(f, (supply) => {
    supply.audit.vulnerabilities = audit.metadata.vulnerabilities;
    supply.audit.canonical_sha256 = canonicalSha256(audit);
  });
  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(
    `${result.stderr}\n${result.stdout}`,
    /AUDIT_VULNERABILITY_TOTAL_MISMATCH/,
  );
});

test('registry signature lock binding mismatch fails closed', () => {
  const f = fixture();
  const signatures = JSON.parse(readFileSync(f.signaturesPath, 'utf8'));
  signatures.verified[0].version = '9.9.9';
  writeFileSync(f.signaturesPath, `${JSON.stringify(signatures, null, 2)}\n`);
  refreshSupply(f, (supply) => {
    supply.signatures.canonical_sha256 = canonicalSha256(signatures);
  });
  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(
    `${result.stderr}\n${result.stdout}`,
    /REGISTRY_SIGNATURE_PACKAGE_VERSION_MISMATCH/,
  );
});

test('registry signature debt fails closed with internally consistent evidence', () => {
  const f = fixture();
  const signatures = JSON.parse(readFileSync(f.signaturesPath, 'utf8'));
  signatures.invalid.push({ name: 'dependency-x', version: '1.0.0' });
  writeFileSync(f.signaturesPath, `${JSON.stringify(signatures, null, 2)}\n`);
  refreshSupply(f, (supply) => {
    supply.signatures.invalid_count = 1;
    supply.signatures.canonical_sha256 = canonicalSha256(signatures);
  });
  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /REGISTRY_SIGNATURE_DEBT/);
});

test('foreign SBOM component fails closed even with refreshed receipt and manifest', () => {
  const f = fixture();
  const sbom = JSON.parse(readFileSync(f.sbomPath, 'utf8'));
  sbom.components.push({
    type: 'library',
    name: 'not-locked',
    version: '1.0.0',
    'bom-ref': 'not-locked@1.0.0',
    purl: 'pkg:npm/not-locked@1.0.0',
  });
  sbom.dependencies.push({ ref: 'not-locked@1.0.0', dependsOn: [] });
  writeFileSync(f.sbomPath, `${JSON.stringify(sbom, null, 2)}\n`);
  refreshSupply(f, (supply) => {
    supply.sbom.normalized_sha256 = canonicalSha256(normalizeSbom(sbom));
    supply.sbom.lock_bound_component_count = 2;
    supply.sbom.dependency_node_count = 3;
  });
  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /SBOM_COMPONENT_NOT_LOCKED/);
});

test('dangling SBOM dependency target fails closed with refreshed hashes', () => {
  const f = fixture();
  const sbom = JSON.parse(readFileSync(f.sbomPath, 'utf8'));
  sbom.dependencies[0].dependsOn.push('ghost@1.0.0');
  writeFileSync(f.sbomPath, `${JSON.stringify(sbom, null, 2)}\n`);
  refreshSupply(f, (supply) => {
    supply.sbom.normalized_sha256 = canonicalSha256(normalizeSbom(sbom));
  });
  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /SBOM_DEPENDENCY_TARGET_UNKNOWN/);
});

test('SBOM evidence hash mismatch fails closed', () => {
  const f = fixture();
  const sbom = JSON.parse(readFileSync(f.sbomPath, 'utf8'));
  sbom.components.push({ name: 'unexpected', version: '1.0.0' });
  writeFileSync(f.sbomPath, `${JSON.stringify(sbom, null, 2)}\n`);
  writeManifest(f);
  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /SBOM_EVIDENCE_HASH_MISMATCH/);
});

test('repository identity mismatch fails closed even with recomputed receipt roots', () => {
  const f = fixture();

  const pkg = JSON.parse(readFileSync(f.pkgPath, 'utf8'));
  pkg.source.repository = 'Other-Org/other-repo';
  const pkgCore = structuredClone(pkg);
  delete pkgCore.receipt_sha256;
  pkg.receipt_sha256 = sha256(
    Buffer.from(`${JSON.stringify(stable(pkgCore), null, 2)}\n`),
  );
  writeFileSync(f.pkgPath, `${JSON.stringify(stable(pkg), null, 2)}\n`);

  const supply = JSON.parse(readFileSync(f.supplyPath, 'utf8'));
  supply.source.repository = 'Other-Org/other-repo';
  supply.package_receipt.receipt_root = pkg.receipt_sha256;
  supply.package_receipt.file_sha256 = sha256(readFileSync(f.pkgPath));
  const supplyCore = structuredClone(supply);
  delete supplyCore.receipt_sha256;
  supply.receipt_sha256 = canonicalSha256(supplyCore);
  writeFileSync(f.supplyPath, `${JSON.stringify(supply, null, 2)}\n`);
  writeManifest(f);

  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(
    `${result.stderr}\n${result.stdout}`,
    /PACKAGE_RECEIPT_REPOSITORY_MISMATCH|SUPPLY_CHAIN_RECEIPT_REPOSITORY_MISMATCH/,
  );
});

test('unexpected supply-chain receipt version fails closed', () => {
  const f = fixture();
  refreshSupply(f, (supply) => {
    supply.receipt_version = 'NpmSupplyChainReceiptV0';
  });
  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(
    `${result.stderr}\n${result.stdout}`,
    /SUPPLY_CHAIN_RECEIPT_VERSION_MISMATCH/,
  );
});

test('source mismatch and workflow run mismatch fail closed', () => {
  const f = fixture();
  const source = run(f, { EXPECTED_SOURCE_SHA: 'b'.repeat(40) });
  assert.notEqual(source.status, 0);
  assert.match(`${source.stderr}\n${source.stdout}`, /PACKAGE_RECEIPT_SOURCE_MISMATCH/);

  const runId = run(f, { EXPECTED_RUN_ID: '1' });
  assert.notEqual(runId.status, 0);
  assert.match(`${runId.stderr}\n${runId.stdout}`, /WORKFLOW_RUN_ID_MISMATCH/);
});
