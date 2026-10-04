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

function packageReceiptRoot(receipt) {
  const core = structuredClone(receipt);
  const claimed = core.receipt_sha256;
  delete core.receipt_sha256;
  const recomputed = sha256Bytes(
    Buffer.from(`${JSON.stringify(stable(core), null, 2)}\n`),
  );
  return { claimed, recomputed };
}

function requiredEnv(name) {
  const value = (process.env[name] ?? '').trim();
  if (!value) fail('OBSERVATION_ENV_MISSING', `name=${name}`);
  return value;
}

function requiredPositiveIntegerEnv(name) {
  const raw = requiredEnv(name);
  if (!/^[1-9]\d*$/.test(raw)) fail('OBSERVATION_ENV_INVALID', `name=${name} value=${raw}`);
  return Number(raw);
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

const observation = {
  provider: 'github-actions',
  run_id: requiredPositiveIntegerEnv('AEGIS_GITHUB_RUN_ID'),
  run_attempt: requiredPositiveIntegerEnv('AEGIS_GITHUB_RUN_ATTEMPT'),
  run_number: requiredPositiveIntegerEnv('AEGIS_GITHUB_RUN_NUMBER'),
  workflow: requiredEnv('AEGIS_GITHUB_WORKFLOW'),
  event_name: requiredEnv('AEGIS_GITHUB_EVENT_NAME'),
};

if (packageReceipt.receipt_version !== 'NpmPackageReceiptV1') fail('PACKAGE_RECEIPT_VERSION_MISMATCH');
if (packageReceipt.source?.repository !== 'Aegis-Omega/sovereign-guard') fail('PACKAGE_RECEIPT_REPOSITORY_MISMATCH');
if (!/^[0-9a-f]{40}$/.test(packageReceipt.source?.git_sha ?? '')) fail('PACKAGE_RECEIPT_SOURCE_SHA_INVALID');
if (packageReceipt.verification?.authority !== 'REMOTE_EXACT_SOURCE_PACK_VERIFIED') fail('PACKAGE_RECEIPT_AUTHORITY_INSUFFICIENT');
if (packageReceipt.verification?.exact_source_sha_verified !== true) fail('PACKAGE_RECEIPT_SOURCE_UNVERIFIED');
if (packageReceipt.verification?.reproducible_pack_verified !== true) fail('PACKAGE_RECEIPT_PACK_UNREPRODUCIBLE');
if (packageReceipt.verification?.local_64_suite_bound !== false) fail('LOCAL_64_SUITE_AUTHORITY_LAUNDERING');

const packageRoot = packageReceiptRoot(packageReceipt);
if (!/^[0-9a-f]{64}$/.test(packageRoot.claimed ?? '')) {
  fail('PACKAGE_RECEIPT_ROOT_INVALID');
}
if (packageRoot.claimed !== packageRoot.recomputed) {
  fail(
    'PACKAGE_RECEIPT_ROOT_INVALID',
    `claimed=${packageRoot.claimed} recomputed=${packageRoot.recomputed}`,
  );
}

const expectedSource = process.env.AEGIS_SOURCE_SHA || packageReceipt.source.git_sha;
if (expectedSource !== packageReceipt.source.git_sha) {
  fail('SOURCE_SHA_MISMATCH', `expected=${expectedSource} actual=${packageReceipt.source.git_sha}`);
}

if (lock.lockfileVersion !== 3) {
  fail('LOCKFILE_VERSION_MISMATCH', `actual=${lock.lockfileVersion}`);
}
if (lock.name !== packageReceipt.package?.name || lock.version !== packageReceipt.package?.version) {
  fail('LOCK_PACKAGE_IDENTITY_MISMATCH');
}
const lockRoot = lock.packages?.[''];
if (
  !lockRoot ||
  lockRoot.name !== packageReceipt.package?.name ||
  lockRoot.version !== packageReceipt.package?.version
) {
  fail('LOCK_ROOT_PACKAGE_IDENTITY_MISMATCH');
}

const vulnerabilities = audit.metadata?.vulnerabilities;
if (!vulnerabilities || typeof vulnerabilities.total !== 'number') fail('AUDIT_METADATA_MISSING');
for (const severity of ['info', 'low', 'moderate', 'high', 'critical', 'total']) {
  if (!Number.isInteger(vulnerabilities[severity]) || vulnerabilities[severity] < 0) {
    fail('AUDIT_METADATA_INVALID', `severity=${severity}`);
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
if (vulnerabilities.total !== 0) {
  fail('AUDIT_VULNERABILITY_DEBT', `total=${vulnerabilities.total}`);
}

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

const missing = Array.isArray(signatures.missing) ? signatures.missing : null;
const invalid = Array.isArray(signatures.invalid) ? signatures.invalid : null;
const verified = Array.isArray(signatures.verified) ? signatures.verified : null;
if (!missing || !invalid || !verified) fail('REGISTRY_SIGNATURE_METADATA_MISSING');
if (missing.length !== 0 || invalid.length !== 0) {
  fail('REGISTRY_SIGNATURE_DEBT', `missing=${missing.length} invalid=${invalid.length}`);
}
if (verified.length === 0) fail('REGISTRY_SIGNATURE_VERIFICATION_EMPTY');
const verifiedLockBindingCount = verifySignatureLockBinding(verified, lock);

const provenanceAttestationCount = verified.filter(
  (entry) =>
    entry?.attestations?.provenance?.predicateType ===
    'https://slsa.dev/provenance/v1',
).length;
if (provenanceAttestationCount !== verified.length) {
  fail(
    'PROVENANCE_ATTESTATION_COVERAGE_INCOMPLETE',
    `verified=${verified.length} provenance=${provenanceAttestationCount}`,
  );
}

if (sbomRaw.bomFormat !== 'CycloneDX') fail('SBOM_FORMAT_MISMATCH');
const sbomBinding = verifySbomLockBinding(sbomRaw, lock, packageReceipt.package);

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
  observation,
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
    dependencies: auditDependencies,
    lock_package_count: lockPackageCount,
    canonical_sha256: auditCanonicalSha256,
  },
  signatures: {
    verified_count: verified.length,
    missing_count: missing.length,
    invalid_count: invalid.length,
    provenance_attestation_count: provenanceAttestationCount,
    lock_bound_verified_count: verifiedLockBindingCount,
    canonical_sha256: signaturesCanonicalSha256,
  },
  sbom: {
    format: sbomRaw.bomFormat,
    spec_version: sbomRaw.specVersion,
    component_count: Array.isArray(sbomRaw.components) ? sbomRaw.components.length : 0,
    dependency_edge_count: sbomRaw.dependencies.length,
    lock_bound_component_count: sbomBinding.lock_bound_component_count,
    dependency_node_count: sbomBinding.dependency_node_count,
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
    audit_lock_graph_count_bound: true,
    registry_signatures_verified: true,
    registry_signatures_lock_bound: true,
    provenance_attestations_observed: true,
    provenance_attestations_cover_verified_set: true,
    normalized_sbom_bound: true,
    sbom_lock_bound: true,
    sbom_graph_closed: true,
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
