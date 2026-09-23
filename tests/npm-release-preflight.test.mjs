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

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'guard-release-preflight-'));
  const evidenceRoot = join(root, 'verified-package');
  const artifacts = join(evidenceRoot, 'artifacts');
  mkdirSync(artifacts, { recursive: true });

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
    audit: {
      vulnerabilities: {
        info: 0,
        low: 0,
        moderate: 0,
        high: 0,
        critical: 0,
        total: 0,
      },
    },
    signatures: {
      verified_count: 2,
      missing_count: 0,
      invalid_count: 0,
      provenance_attestation_count: 2,
    },
    verification: {
      authority: 'REMOTE_EXACT_SOURCE_SUPPLY_CHAIN_VERIFIED',
      local_64_suite_bound: false,
    },
  };
  const supplyReceipt = {
    ...supplyCore,
    receipt_sha256: sha256(Buffer.from(JSON.stringify(stable(supplyCore)))),
  };
  const supplyPath = join(artifacts, 'NpmSupplyChainReceiptV1.json');
  writeFileSync(supplyPath, `${JSON.stringify(supplyReceipt, null, 2)}\n`);

  return { root, evidenceRoot, artifacts, tarball, pkgPath, supplyPath };
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

function rewriteJson(path, mutate) {
  const value = JSON.parse(readFileSync(path, 'utf8'));
  mutate(value);
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

test('release preflight accepts fully bound release evidence', () => {
  const f = fixture();
  const result = run(f);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const output = JSON.parse(result.stdout);
  assert.equal(output.status, 'RELEASE_PREFLIGHT_VERIFIED');
  assert.equal(output.source_sha, SOURCE_SHA);
  assert.match(output.tarball_sha256, /^[0-9a-f]{64}$/);
});

test('tampered package receipt fails closed', () => {
  const f = fixture();
  rewriteJson(f.pkgPath, (pkg) => {
    pkg.package.version = '9.9.9';
  });
  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /PACKAGE_RECEIPT_ROOT_INVALID/);
});

test('source mismatch fails closed', () => {
  const f = fixture();
  const result = run(f, { EXPECTED_SOURCE_SHA: 'b'.repeat(40) });
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /PACKAGE_RECEIPT_SOURCE_MISMATCH/);
});

test('workflow run identity mismatch fails closed', () => {
  const f = fixture();
  const result = run(f, { EXPECTED_RUN_ID: '1' });
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /WORKFLOW_RUN_ID_MISMATCH/);
});

test('non-zero vulnerability snapshot fails closed', () => {
  const f = fixture();
  rewriteJson(f.supplyPath, (supply) => {
    supply.audit.vulnerabilities.low = 1;
    supply.audit.vulnerabilities.total = 1;
    const root = structuredClone(supply);
    delete root.receipt_sha256;
    supply.receipt_sha256 = sha256(Buffer.from(JSON.stringify(stable(root))));
  });
  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /NON_ZERO_VULNERABILITY_SNAPSHOT/);
});

test('registry signature debt fails closed', () => {
  const f = fixture();
  rewriteJson(f.supplyPath, (supply) => {
    supply.signatures.invalid_count = 1;
    const root = structuredClone(supply);
    delete root.receipt_sha256;
    supply.receipt_sha256 = sha256(Buffer.from(JSON.stringify(stable(root))));
  });
  const result = run(f);
  assert.notEqual(result.status, 0);
  assert.match(`${result.stderr}\n${result.stdout}`, /REGISTRY_SIGNATURE_DEBT/);
});
