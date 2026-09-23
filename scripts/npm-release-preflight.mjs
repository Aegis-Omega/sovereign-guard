#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

function fail(code, detail = '') {
  throw new Error(detail ? `${code} ${detail}` : code);
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

function canonicalSha256(value) {
  return sha256Bytes(Buffer.from(JSON.stringify(stable(value))));
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function requiredEnv(name) {
  const value = (process.env[name] ?? '').trim();
  if (!value) fail('RELEASE_PREFLIGHT_ENV_MISSING', `name=${name}`);
  return value;
}

function normalizeSbom(input) {
  const sbom = structuredClone(input);
  if (Object.hasOwn(sbom, 'serialNumber')) delete sbom.serialNumber;
  if (sbom.metadata && Object.hasOwn(sbom.metadata, 'timestamp')) {
    delete sbom.metadata.timestamp;
  }
  return sbom;
}

function verifyEvidenceManifest(evidenceRoot, manifestPath) {
  const required = new Set([
    'artifacts/NpmPackageReceiptV1.json',
    'artifacts/NpmSupplyChainReceiptV1.json',
    'artifacts/npm-audit.json',
    'artifacts/npm-signatures.json',
    'artifacts/sbom.cdx.json',
  ]);
  const seen = new Set();
  const lines = readFileSync(manifestPath, 'utf8').split(/\r?\n/).filter(Boolean);
  if (lines.length === 0) fail('EVIDENCE_MANIFEST_EMPTY');

  for (const line of lines) {
    const match = /^([0-9a-f]{64}) [ *](artifacts\/[A-Za-z0-9._-]+)$/.exec(line);
    if (!match) fail('EVIDENCE_MANIFEST_LINE_INVALID', `line=${JSON.stringify(line)}`);
    const [, expected, relative] = match;
    if (seen.has(relative)) fail('EVIDENCE_MANIFEST_DUPLICATE_PATH', `path=${relative}`);
    seen.add(relative);
    const actual = sha256Bytes(readFileSync(resolve(evidenceRoot, relative)));
    if (actual !== expected) {
      fail('EVIDENCE_MANIFEST_DIGEST_MISMATCH', `path=${relative}`);
    }
  }

  for (const relative of required) {
    if (!seen.has(relative)) fail('EVIDENCE_MANIFEST_REQUIRED_PATH_MISSING', `path=${relative}`);
  }
  return { entry_count: seen.size };
}

const tarballArg = process.argv[2];
if (!tarballArg) fail('RELEASE_PREFLIGHT_TARBALL_MISSING');

const expectedSource = requiredEnv('EXPECTED_SOURCE_SHA');
if (!/^[0-9a-f]{40}$/i.test(expectedSource)) {
  fail('RELEASE_PREFLIGHT_SOURCE_SHA_INVALID', `value=${expectedSource}`);
}

const expectedRunId = requiredEnv('EXPECTED_RUN_ID');
const expectedRunAttempt = requiredEnv('EXPECTED_RUN_ATTEMPT');
if (!/^[1-9]\d*$/.test(expectedRunId) || !/^[1-9]\d*$/.test(expectedRunAttempt)) {
  fail('RELEASE_PREFLIGHT_RUN_IDENTITY_INVALID');
}

const evidenceRoot = resolve(process.env.VERIFIED_PACKAGE_ROOT || 'verified-package');
const artifactsRoot = resolve(evidenceRoot, 'artifacts');
const pkgPath = resolve(artifactsRoot, 'NpmPackageReceiptV1.json');
const supplyPath = resolve(artifactsRoot, 'NpmSupplyChainReceiptV1.json');
const auditPath = resolve(artifactsRoot, 'npm-audit.json');
const signaturesPath = resolve(artifactsRoot, 'npm-signatures.json');
const sbomPath = resolve(artifactsRoot, 'sbom.cdx.json');
const manifestPath = resolve(artifactsRoot, 'supply-chain.sha256');
const sourceLockPath = resolve('package-lock.json');
const tarballPath = resolve(tarballArg);

const manifest = verifyEvidenceManifest(evidenceRoot, manifestPath);
const pkgBytes = readFileSync(pkgPath);
const pkg = JSON.parse(pkgBytes);
const supply = readJson(supplyPath);
const audit = readJson(auditPath);
const signatures = readJson(signaturesPath);
const sbom = readJson(sbomPath);
const lockBytes = readFileSync(sourceLockPath);
const tarballSha256 = sha256Bytes(readFileSync(tarballPath));

if (pkg.receipt_version !== 'NpmPackageReceiptV1') fail('PACKAGE_RECEIPT_VERSION_MISMATCH');
if (pkg.verification?.authority !== 'REMOTE_EXACT_SOURCE_PACK_VERIFIED') fail('PACKAGE_RECEIPT_AUTHORITY_INSUFFICIENT');
if (pkg.verification?.exact_source_sha_verified !== true) fail('PACKAGE_RECEIPT_SOURCE_UNVERIFIED');
if (pkg.verification?.reproducible_pack_verified !== true) fail('PACKAGE_RECEIPT_PACK_UNREPRODUCIBLE');
if (pkg.verification?.local_64_suite_bound !== false) fail('LOCAL_64_SUITE_AUTHORITY_LAUNDERING');

if (pkg.source?.git_sha !== expectedSource) fail('PACKAGE_RECEIPT_SOURCE_MISMATCH');
if (supply.source?.git_sha !== expectedSource) fail('SUPPLY_CHAIN_RECEIPT_SOURCE_MISMATCH');
if (supply.package?.name !== pkg.package?.name || supply.package?.version !== pkg.package?.version) {
  fail('SUPPLY_CHAIN_PACKAGE_IDENTITY_MISMATCH');
}

const pkgCore = structuredClone(pkg);
const pkgRoot = pkgCore.receipt_sha256;
delete pkgCore.receipt_sha256;
const recomputedPkgRoot = sha256Bytes(
  Buffer.from(`${JSON.stringify(stable(pkgCore), null, 2)}\n`),
);
if (pkgRoot !== recomputedPkgRoot) fail('PACKAGE_RECEIPT_ROOT_INVALID');

const supplyCore = structuredClone(supply);
const supplyRoot = supplyCore.receipt_sha256;
delete supplyCore.receipt_sha256;
const recomputedSupplyRoot = canonicalSha256(supplyCore);
if (supplyRoot !== recomputedSupplyRoot) fail('SUPPLY_CHAIN_RECEIPT_ROOT_INVALID');

const pkgFileSha256 = sha256Bytes(pkgBytes);
if (supply.verification?.authority !== 'REMOTE_EXACT_SOURCE_SUPPLY_CHAIN_VERIFIED') {
  fail('SUPPLY_CHAIN_AUTHORITY_INSUFFICIENT');
}
if (supply.verification?.exact_source_sha_verified !== true) fail('SUPPLY_CHAIN_SOURCE_UNVERIFIED');
if (supply.verification?.package_receipt_bound !== true) fail('SUPPLY_CHAIN_PACKAGE_RECEIPT_UNBOUND');
if (supply.verification?.lockfile_bound !== true) fail('SUPPLY_CHAIN_LOCKFILE_UNBOUND');
if (supply.verification?.zero_vulnerability_snapshot_verified !== true) fail('SUPPLY_CHAIN_AUDIT_UNVERIFIED');
if (supply.verification?.registry_signatures_verified !== true) fail('SUPPLY_CHAIN_SIGNATURES_UNVERIFIED');
if (supply.verification?.provenance_attestations_observed !== true) fail('SUPPLY_CHAIN_PROVENANCE_UNVERIFIED');
if (supply.verification?.normalized_sbom_bound !== true) fail('SUPPLY_CHAIN_SBOM_UNBOUND');
if (supply.verification?.local_64_suite_bound !== false) fail('LOCAL_64_SUITE_AUTHORITY_LAUNDERING');

if (supply.package_receipt?.authority !== pkg.verification?.authority) {
  fail('PACKAGE_RECEIPT_AUTHORITY_BINDING_MISMATCH');
}
if (supply.package_receipt?.receipt_root !== pkg.receipt_sha256) {
  fail('PACKAGE_RECEIPT_ROOT_BINDING_MISMATCH');
}
if (supply.package_receipt?.file_sha256 !== pkgFileSha256) {
  fail('PACKAGE_RECEIPT_FILE_HASH_MISMATCH');
}
if (supply.package_receipt?.tarball_sha256 !== pkg.package?.sha256) {
  fail('SUPPLY_CHAIN_TARBALL_BINDING_MISMATCH');
}
if (pkg.package?.sha256 !== tarballSha256) fail('TARBALL_HASH_MISMATCH');

if (supply.lockfile?.sha256 !== sha256Bytes(lockBytes)) fail('LOCKFILE_HASH_MISMATCH');
if (supply.audit?.canonical_sha256 !== canonicalSha256(audit)) fail('AUDIT_EVIDENCE_HASH_MISMATCH');
if (supply.signatures?.canonical_sha256 !== canonicalSha256(signatures)) {
  fail('SIGNATURE_EVIDENCE_HASH_MISMATCH');
}
if (supply.sbom?.normalized_sha256 !== canonicalSha256(normalizeSbom(sbom))) {
  fail('SBOM_EVIDENCE_HASH_MISMATCH');
}

const vulnerabilities = audit.metadata?.vulnerabilities;
if (!vulnerabilities) fail('AUDIT_METADATA_MISSING');
for (const severity of ['info', 'low', 'moderate', 'high', 'critical', 'total']) {
  if (!Number.isInteger(vulnerabilities[severity]) || vulnerabilities[severity] < 0) {
    fail('AUDIT_METADATA_INVALID', `severity=${severity}`);
  }
  if (supply.audit?.vulnerabilities?.[severity] !== vulnerabilities[severity]) {
    fail('AUDIT_VULNERABILITY_COUNT_MISMATCH', `severity=${severity}`);
  }
}
const vulnerabilitySeverityTotal =
  vulnerabilities.info +
  vulnerabilities.low +
  vulnerabilities.moderate +
  vulnerabilities.high +
  vulnerabilities.critical;
if (vulnerabilities.total !== vulnerabilitySeverityTotal) {
  fail(
    'AUDIT_VULNERABILITY_TOTAL_MISMATCH',
    `reported=${vulnerabilities.total} summed=${vulnerabilitySeverityTotal}`,
  );
}
if (vulnerabilities.total !== 0) fail('NON_ZERO_VULNERABILITY_SNAPSHOT');

const verified = Array.isArray(signatures.verified) ? signatures.verified : null;
const missing = Array.isArray(signatures.missing) ? signatures.missing : null;
const invalid = Array.isArray(signatures.invalid) ? signatures.invalid : null;
if (!verified || !missing || !invalid) fail('REGISTRY_SIGNATURE_METADATA_MISSING');
const provenanceCount = verified.filter((entry) => Boolean(entry?.attestations?.provenance)).length;
if (
  supply.signatures?.verified_count !== verified.length ||
  supply.signatures?.missing_count !== missing.length ||
  supply.signatures?.invalid_count !== invalid.length ||
  supply.signatures?.provenance_attestation_count !== provenanceCount
) {
  fail('REGISTRY_SIGNATURE_COUNT_MISMATCH');
}
if (missing.length !== 0 || invalid.length !== 0) fail('REGISTRY_SIGNATURE_DEBT');
if (verified.length === 0 || provenanceCount === 0) fail('PROVENANCE_ATTESTATION_EMPTY');

if (sbom.bomFormat !== 'CycloneDX') fail('SBOM_FORMAT_MISMATCH');
if (
  sbom.metadata?.component?.name !== pkg.package?.name ||
  sbom.metadata?.component?.version !== pkg.package?.version
) {
  fail('SBOM_PACKAGE_IDENTITY_MISMATCH');
}

if (String(supply.observation?.run_id) !== expectedRunId) fail('WORKFLOW_RUN_ID_MISMATCH');
if (String(supply.observation?.run_attempt) !== expectedRunAttempt) {
  fail('WORKFLOW_RUN_ATTEMPT_MISMATCH');
}
if (supply.observation?.provider !== 'github-actions') fail('WORKFLOW_PROVIDER_MISMATCH');
if (supply.observation?.event_name !== 'release') fail('WORKFLOW_EVENT_MISMATCH');

process.stdout.write(
  `${JSON.stringify({
    status: 'RELEASE_PREFLIGHT_VERIFIED',
    source_sha: expectedSource,
    tarball_sha256: tarballSha256,
    package_receipt_root: pkg.receipt_sha256,
    supply_chain_receipt_root: supply.receipt_sha256,
    evidence_manifest_entries: manifest.entry_count,
    observation: supply.observation,
  })}\n`,
);
