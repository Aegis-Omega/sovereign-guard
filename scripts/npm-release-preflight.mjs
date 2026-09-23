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

function packageNameFromLocation(location) {
  if (typeof location !== 'string') fail('REGISTRY_SIGNATURE_LOCATION_INVALID');
  const marker = 'node_modules/';
  const index = location.lastIndexOf(marker);
  if (index < 0) fail('REGISTRY_SIGNATURE_LOCATION_INVALID', `location=${location}`);
  const name = location.slice(index + marker.length);
  if (!name || name.includes('/node_modules/')) {
    fail('REGISTRY_SIGNATURE_LOCATION_INVALID', `location=${location}`);
  }
  return name;
}

function verifySignatureLockBinding(entries, lock) {
  const seenLocations = new Set();
  for (const entry of entries) {
    const location = entry?.location;
    if (seenLocations.has(location)) {
      fail('REGISTRY_SIGNATURE_LOCATION_DUPLICATE', `location=${location}`);
    }
    seenLocations.add(location);

    const locked = lock.packages?.[location];
    if (!locked) {
      fail('REGISTRY_SIGNATURE_LOCK_ENTRY_MISSING', `location=${location}`);
    }
    const expectedName = locked.name ?? packageNameFromLocation(location);
    if (entry?.name !== expectedName) {
      fail(
        'REGISTRY_SIGNATURE_PACKAGE_NAME_MISMATCH',
        `location=${location} expected=${expectedName} actual=${entry?.name ?? '<missing>'}`,
      );
    }
    if (entry?.version !== locked.version) {
      fail(
        'REGISTRY_SIGNATURE_PACKAGE_VERSION_MISMATCH',
        `location=${location} expected=${locked.version ?? '<missing>'} actual=${entry?.version ?? '<missing>'}`,
      );
    }
    if (entry?.registry !== 'https://registry.npmjs.org/') {
      fail(
        'REGISTRY_SIGNATURE_REGISTRY_MISMATCH',
        `location=${location} registry=${entry?.registry ?? '<missing>'}`,
      );
    }
    if (
      typeof locked.resolved !== 'string' ||
      !locked.resolved.startsWith('https://registry.npmjs.org/')
    ) {
      fail('LOCK_REGISTRY_ORIGIN_MISMATCH', `location=${location}`);
    }
  }
  return seenLocations.size;
}

function npmPurl(name, version) {
  const encodedName = name.startsWith('@') ? `%40${name.slice(1)}` : name;
  return `pkg:npm/${encodedName}@${version}`;
}

function verifySbomLockBinding(sbom, lock, packageIdentity) {
  if (!Array.isArray(sbom.components)) fail('SBOM_COMPONENTS_MISSING');
  if (!Array.isArray(sbom.dependencies)) fail('SBOM_DEPENDENCIES_MISSING');

  const lockIdentities = new Set();
  for (const [location, locked] of Object.entries(lock.packages ?? {})) {
    if (!location || !locked || typeof locked.version !== 'string') continue;
    const name = locked.name ?? packageNameFromLocation(location);
    lockIdentities.add(`${name}@${locked.version}`);
  }

  const rootRef = `${packageIdentity.name}@${packageIdentity.version}`;
  const root = sbom.metadata?.component;
  if (
    root?.type !== 'library' ||
    root?.name !== packageIdentity.name ||
    root?.version !== packageIdentity.version ||
    root?.['bom-ref'] !== rootRef ||
    root?.purl !== npmPurl(packageIdentity.name, packageIdentity.version)
  ) {
    fail('SBOM_ROOT_IDENTITY_MISMATCH');
  }

  const knownRefs = new Set([rootRef]);
  const componentRefs = new Set();
  for (const component of sbom.components) {
    if (
      component?.type !== 'library' ||
      typeof component?.name !== 'string' ||
      typeof component?.version !== 'string'
    ) {
      fail('SBOM_COMPONENT_IDENTITY_INVALID');
    }
    const ref = `${component.name}@${component.version}`;
    if (componentRefs.has(ref)) fail('SBOM_COMPONENT_DUPLICATE', `ref=${ref}`);
    componentRefs.add(ref);

    if (!lockIdentities.has(ref)) {
      fail('SBOM_COMPONENT_NOT_LOCKED', `ref=${ref}`);
    }
    if (component['bom-ref'] !== ref) {
      fail('SBOM_COMPONENT_REF_MISMATCH', `ref=${ref}`);
    }
    if (component.purl !== npmPurl(component.name, component.version)) {
      fail('SBOM_COMPONENT_PURL_MISMATCH', `ref=${ref}`);
    }
    knownRefs.add(ref);
  }

  const dependencyRefs = new Set();
  for (const dependency of sbom.dependencies) {
    const ref = dependency?.ref;
    if (typeof ref !== 'string' || !knownRefs.has(ref)) {
      fail('SBOM_DEPENDENCY_REF_UNKNOWN', `ref=${ref ?? '<missing>'}`);
    }
    if (dependencyRefs.has(ref)) fail('SBOM_DEPENDENCY_REF_DUPLICATE', `ref=${ref}`);
    dependencyRefs.add(ref);
    if (!Array.isArray(dependency.dependsOn)) {
      fail('SBOM_DEPENDENCY_TARGETS_INVALID', `ref=${ref}`);
    }
    const seenTargets = new Set();
    for (const target of dependency.dependsOn) {
      if (!knownRefs.has(target)) {
        fail('SBOM_DEPENDENCY_TARGET_UNKNOWN', `ref=${ref} target=${target}`);
      }
      if (seenTargets.has(target)) {
        fail('SBOM_DEPENDENCY_TARGET_DUPLICATE', `ref=${ref} target=${target}`);
      }
      seenTargets.add(target);
    }
  }

  if (!dependencyRefs.has(rootRef)) fail('SBOM_ROOT_DEPENDENCY_NODE_MISSING');
  for (const ref of componentRefs) {
    if (!dependencyRefs.has(ref)) fail('SBOM_COMPONENT_DEPENDENCY_NODE_MISSING', `ref=${ref}`);
  }

  return {
    lock_bound_component_count: componentRefs.size,
    dependency_node_count: dependencyRefs.size,
  };
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
const lock = JSON.parse(lockBytes);
const tarballSha256 = sha256Bytes(readFileSync(tarballPath));

if (pkg.receipt_version !== 'NpmPackageReceiptV1') fail('PACKAGE_RECEIPT_VERSION_MISMATCH');
if (supply.receipt_version !== 'NpmSupplyChainReceiptV1') {
  fail('SUPPLY_CHAIN_RECEIPT_VERSION_MISMATCH');
}
if (pkg.source?.repository !== 'Aegis-Omega/sovereign-guard') {
  fail('PACKAGE_RECEIPT_REPOSITORY_MISMATCH');
}
if (supply.source?.repository !== 'Aegis-Omega/sovereign-guard') {
  fail('SUPPLY_CHAIN_RECEIPT_REPOSITORY_MISMATCH');
}
if (supply.source?.repository !== pkg.source?.repository) {
  fail('REPOSITORY_BINDING_MISMATCH');
}
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
if (supply.verification?.audit_lock_graph_count_bound !== true) {
  fail('SUPPLY_CHAIN_AUDIT_LOCK_GRAPH_UNVERIFIED');
}
if (supply.verification?.registry_signatures_verified !== true) fail('SUPPLY_CHAIN_SIGNATURES_UNVERIFIED');
if (supply.verification?.registry_signatures_lock_bound !== true) {
  fail('SUPPLY_CHAIN_SIGNATURE_LOCK_BINDING_UNVERIFIED');
}
if (supply.verification?.provenance_attestations_observed !== true) fail('SUPPLY_CHAIN_PROVENANCE_UNVERIFIED');
if (supply.verification?.normalized_sbom_bound !== true) fail('SUPPLY_CHAIN_SBOM_UNBOUND');
if (supply.verification?.sbom_lock_bound !== true) fail('SUPPLY_CHAIN_SBOM_LOCK_BINDING_UNVERIFIED');
if (supply.verification?.sbom_graph_closed !== true) fail('SUPPLY_CHAIN_SBOM_GRAPH_UNVERIFIED');
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

if (lock.lockfileVersion !== 3) {
  fail('LOCKFILE_VERSION_MISMATCH', `actual=${lock.lockfileVersion}`);
}
if (lock.name !== pkg.package?.name || lock.version !== pkg.package?.version) {
  fail('LOCK_PACKAGE_IDENTITY_MISMATCH');
}
const lockRoot = lock.packages?.[''];
if (
  !lockRoot ||
  lockRoot.name !== pkg.package?.name ||
  lockRoot.version !== pkg.package?.version
) {
  fail('LOCK_ROOT_PACKAGE_IDENTITY_MISMATCH');
}
if (supply.lockfile?.lockfile_version !== lock.lockfileVersion) {
  fail('LOCKFILE_VERSION_RECEIPT_MISMATCH');
}
if (supply.lockfile?.sha256 !== sha256Bytes(lockBytes)) fail('LOCKFILE_HASH_MISMATCH');
if (supply.audit?.canonical_sha256 !== canonicalSha256(audit)) fail('AUDIT_EVIDENCE_HASH_MISMATCH');
if (supply.signatures?.canonical_sha256 !== canonicalSha256(signatures)) {
  fail('SIGNATURE_EVIDENCE_HASH_MISMATCH');
}
if (supply.sbom?.normalized_sha256 !== canonicalSha256(normalizeSbom(sbom))) {
  fail('SBOM_EVIDENCE_HASH_MISMATCH');
}
const sbomBinding = verifySbomLockBinding(sbom, lock, pkg.package);
if (
  supply.sbom?.lock_bound_component_count !== sbomBinding.lock_bound_component_count ||
  supply.sbom?.dependency_node_count !== sbomBinding.dependency_node_count
) {
  fail('SBOM_BINDING_COUNT_MISMATCH');
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

const auditDependencies = audit.metadata?.dependencies;
if (!auditDependencies || !Number.isInteger(auditDependencies.total) || auditDependencies.total < 0) {
  fail('AUDIT_DEPENDENCY_METADATA_INVALID');
}
const lockPackageCount = Object.keys(lock.packages ?? {}).filter((location) => location !== '').length;
if (auditDependencies.total !== lockPackageCount) {
  fail(
    'AUDIT_LOCK_GRAPH_COUNT_MISMATCH',
    `audit=${auditDependencies.total} lock=${lockPackageCount}`,
  );
}
if (
  supply.audit?.dependencies?.total !== auditDependencies.total ||
  supply.audit?.lock_package_count !== lockPackageCount
) {
  fail('AUDIT_LOCK_GRAPH_RECEIPT_MISMATCH');
}

const verified = Array.isArray(signatures.verified) ? signatures.verified : null;
const missing = Array.isArray(signatures.missing) ? signatures.missing : null;
const invalid = Array.isArray(signatures.invalid) ? signatures.invalid : null;
if (!verified || !missing || !invalid) fail('REGISTRY_SIGNATURE_METADATA_MISSING');
const verifiedLockBindingCount = verifySignatureLockBinding(verified, lock);
const provenanceCount = verified.filter((entry) => Boolean(entry?.attestations?.provenance)).length;
if (
  supply.signatures?.verified_count !== verified.length ||
  supply.signatures?.missing_count !== missing.length ||
  supply.signatures?.invalid_count !== invalid.length ||
  supply.signatures?.provenance_attestation_count !== provenanceCount ||
  supply.signatures?.lock_bound_verified_count !== verifiedLockBindingCount
) {
  fail('REGISTRY_SIGNATURE_COUNT_MISMATCH');
}
if (missing.length !== 0 || invalid.length !== 0) fail('REGISTRY_SIGNATURE_DEBT');
if (verified.length === 0 || provenanceCount === 0) fail('PROVENANCE_ATTESTATION_EMPTY');

if (sbom.bomFormat !== 'CycloneDX') fail('SBOM_FORMAT_MISMATCH');

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
