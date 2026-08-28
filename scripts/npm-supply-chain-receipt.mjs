#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

function fail(code, detail = '') {
  const suffix = detail ? ` ${detail}` : '';
  throw new Error(`${code}${suffix}`);
}

function sha256Bytes(value) {
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

function canonicalJson(value) {
  return JSON.stringify(stable(value));
}

function canonicalSha256(value) {
  return sha256Bytes(canonicalJson(value));
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function fileSha256(path) {
  return sha256Bytes(readFileSync(path));
}

function normalizeSbom(input) {
  const sbom = structuredClone(input);
  const removedSerialNumber = Object.hasOwn(sbom, 'serialNumber');
  if (removedSerialNumber) delete sbom.serialNumber;

  const removedMetadataTimestamp = Boolean(sbom.metadata && Object.hasOwn(sbom.metadata, 'timestamp'));
  if (removedMetadataTimestamp) delete sbom.metadata.timestamp;

  return {
    sbom,
    removedSerialNumber,
    removedMetadataTimestamp,
  };
}

const root = process.cwd();
const artifacts = resolve(root, 'artifacts');
const packageReceiptPath = resolve(artifacts, 'NpmPackageReceiptV1.json');
const auditPath = resolve(artifacts, 'npm-audit.json');
const signaturesPath = resolve(artifacts, 'npm-signatures.json');
const sbomPath = resolve(artifacts, 'sbom.cdx.json');
const lockPath = resolve(root, 'package-lock.json');

const packageReceipt = readJson(packageReceiptPath);
const audit = readJson(auditPath);
const signatures = readJson(signaturesPath);
const sbomRaw = readJson(sbomPath);
const lock = readJson(lockPath);

if (packageReceipt.receipt_version !== 'NpmPackageReceiptV1') fail('PACKAGE_RECEIPT_VERSION_MISMATCH');
if (packageReceipt.source?.repository !== 'Aegis-Omega/sovereign-guard') fail('PACKAGE_RECEIPT_REPOSITORY_MISMATCH');
if (!/^[0-9a-f]{40}$/.test(packageReceipt.source?.git_sha ?? '')) fail('PACKAGE_RECEIPT_SOURCE_SHA_INVALID');
if (packageReceipt.verification?.authority !== 'REMOTE_EXACT_SOURCE_PACK_VERIFIED') fail('PACKAGE_RECEIPT_AUTHORITY_INSUFFICIENT');
if (packageReceipt.verification?.exact_source_sha_verified !== true) fail('PACKAGE_RECEIPT_SOURCE_UNVERIFIED');
if (packageReceipt.verification?.reproducible_pack_verified !== true) fail('PACKAGE_RECEIPT_PACK_UNREPRODUCIBLE');
if (packageReceipt.verification?.local_64_suite_bound !== false) fail('LOCAL_64_SUITE_AUTHORITY_LAUNDERING');

const expectedSource = process.env.AEGIS_SOURCE_SHA || packageReceipt.source.git_sha;
if (expectedSource !== packageReceipt.source.git_sha) {
  fail('SOURCE_SHA_MISMATCH', `expected=${expectedSource} actual=${packageReceipt.source.git_sha}`);
}

if (lock.name !== packageReceipt.package?.name || lock.version !== packageReceipt.package?.version) {
  fail('LOCK_PACKAGE_IDENTITY_MISMATCH');
}

const vulnerabilities = audit.metadata?.vulnerabilities;
if (!vulnerabilities || typeof vulnerabilities.total !== 'number') fail('AUDIT_METADATA_MISSING');
for (const severity of ['info', 'low', 'moderate', 'high', 'critical', 'total']) {
  if (!Number.isInteger(vulnerabilities[severity]) || vulnerabilities[severity] < 0) {
    fail('AUDIT_METADATA_INVALID', `severity=${severity}`);
  }
}
if (vulnerabilities.total !== 0) {
  fail('AUDIT_VULNERABILITY_DEBT', `total=${vulnerabilities.total}`);
}

const missing = Array.isArray(signatures.missing) ? signatures.missing : null;
const invalid = Array.isArray(signatures.invalid) ? signatures.invalid : null;
const verified = Array.isArray(signatures.verified) ? signatures.verified : null;
if (!missing || !invalid || !verified) fail('REGISTRY_SIGNATURE_METADATA_MISSING');
if (missing.length !== 0 || invalid.length !== 0) {
  fail('REGISTRY_SIGNATURE_DEBT', `missing=${missing.length} invalid=${invalid.length}`);
}
if (verified.length === 0) fail('REGISTRY_SIGNATURE_VERIFICATION_EMPTY');

const provenanceAttestationCount = verified.filter(
  (entry) => Boolean(entry?.attestations?.provenance),
).length;
if (provenanceAttestationCount === 0) fail('PROVENANCE_ATTESTATION_EMPTY');

if (sbomRaw.bomFormat !== 'CycloneDX') fail('SBOM_FORMAT_MISMATCH');
const sbomComponent = sbomRaw.metadata?.component;
if (
  sbomComponent?.name !== packageReceipt.package?.name ||
  sbomComponent?.version !== packageReceipt.package?.version
) {
  fail('SBOM_PACKAGE_IDENTITY_MISMATCH');
}

const normalized = normalizeSbom(sbomRaw);
const normalizedSbomSha256 = canonicalSha256(normalized.sbom);
const packageReceiptFileSha256 = fileSha256(packageReceiptPath);
const auditCanonicalSha256 = canonicalSha256(audit);
const signaturesCanonicalSha256 = canonicalSha256(signatures);
const lockSha256 = fileSha256(lockPath);

const receiptCore = {
  receipt_version: 'NpmSupplyChainReceiptV1',
  source: {
    repository: packageReceipt.source.repository,
    git_sha: packageReceipt.source.git_sha,
  },
  package: {
    name: packageReceipt.package.name,
    version: packageReceipt.package.version,
  },
  package_receipt: {
    receipt_root: packageReceipt.receipt_sha256,
    file_sha256: packageReceiptFileSha256,
    tarball_sha256: packageReceipt.package.sha256,
    authority: packageReceipt.verification.authority,
  },
  lockfile: {
    lockfile_version: lock.lockfileVersion,
    sha256: lockSha256,
  },
  audit: {
    policy_threshold: 'low',
    include_dev_dependencies: true,
    vulnerabilities: {
      info: vulnerabilities.info,
      low: vulnerabilities.low,
      moderate: vulnerabilities.moderate,
      high: vulnerabilities.high,
      critical: vulnerabilities.critical,
      total: vulnerabilities.total,
    },
    dependencies: audit.metadata?.dependencies ?? null,
    canonical_sha256: auditCanonicalSha256,
  },
  signatures: {
    verified_count: verified.length,
    missing_count: missing.length,
    invalid_count: invalid.length,
    provenance_attestation_count: provenanceAttestationCount,
    canonical_sha256: signaturesCanonicalSha256,
  },
  sbom: {
    format: sbomRaw.bomFormat,
    spec_version: sbomRaw.specVersion,
    component_count: Array.isArray(sbomRaw.components) ? sbomRaw.components.length : 0,
    dependency_edge_count: Array.isArray(sbomRaw.dependencies) ? sbomRaw.dependencies.length : 0,
    normalized_sha256: normalizedSbomSha256,
    normalization: {
      removed_serial_number: normalized.removedSerialNumber,
      removed_metadata_timestamp: normalized.removedMetadataTimestamp,
    },
  },
  verification: {
    authority: 'REMOTE_EXACT_SOURCE_SUPPLY_CHAIN_VERIFIED',
    exact_source_sha_verified: true,
    package_receipt_bound: true,
    lockfile_bound: true,
    zero_vulnerability_snapshot_verified: true,
    registry_signatures_verified: true,
    provenance_attestations_observed: true,
    normalized_sbom_bound: true,
    local_64_suite_bound: false,
  },
  non_claims: {
    advisory_state_is_timeless: false,
    operator_reported_64_suite_authenticated: false,
  },
};

const receipt = {
  ...receiptCore,
  receipt_sha256: canonicalSha256(receiptCore),
};

mkdirSync(artifacts, { recursive: true });
const target = resolve(artifacts, 'NpmSupplyChainReceiptV1.json');
writeFileSync(target, `${JSON.stringify(receipt, null, 2)}\n`);
console.log(JSON.stringify(receipt, null, 2));
