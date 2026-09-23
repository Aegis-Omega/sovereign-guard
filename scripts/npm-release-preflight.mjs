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

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function requiredEnv(name) {
  const value = (process.env[name] ?? '').trim();
  if (!value) fail('RELEASE_PREFLIGHT_ENV_MISSING', `name=${name}`);
  return value;
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
const pkgPath = resolve(evidenceRoot, 'artifacts', 'NpmPackageReceiptV1.json');
const supplyPath = resolve(evidenceRoot, 'artifacts', 'NpmSupplyChainReceiptV1.json');
const tarballPath = resolve(tarballArg);

const pkgBytes = readFileSync(pkgPath);
const pkg = JSON.parse(pkgBytes);
const supply = readJson(supplyPath);
const tarballSha256 = sha256Bytes(readFileSync(tarballPath));

if (pkg.receipt_version !== 'NpmPackageReceiptV1') fail('PACKAGE_RECEIPT_VERSION_MISMATCH');
if (pkg.verification?.authority !== 'REMOTE_EXACT_SOURCE_PACK_VERIFIED') fail('PACKAGE_RECEIPT_AUTHORITY_INSUFFICIENT');
if (pkg.verification?.exact_source_sha_verified !== true) fail('PACKAGE_RECEIPT_SOURCE_UNVERIFIED');
if (pkg.verification?.reproducible_pack_verified !== true) fail('PACKAGE_RECEIPT_PACK_UNREPRODUCIBLE');
if (pkg.verification?.local_64_suite_bound !== false) fail('LOCAL_64_SUITE_AUTHORITY_LAUNDERING');

if (pkg.source?.git_sha !== expectedSource) fail('PACKAGE_RECEIPT_SOURCE_MISMATCH');
if (supply.source?.git_sha !== expectedSource) fail('SUPPLY_CHAIN_RECEIPT_SOURCE_MISMATCH');

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
const recomputedSupplyRoot = sha256Bytes(Buffer.from(JSON.stringify(stable(supplyCore))));
if (supplyRoot !== recomputedSupplyRoot) fail('SUPPLY_CHAIN_RECEIPT_ROOT_INVALID');

const pkgFileSha256 = sha256Bytes(pkgBytes);
if (supply.verification?.authority !== 'REMOTE_EXACT_SOURCE_SUPPLY_CHAIN_VERIFIED') {
  fail('SUPPLY_CHAIN_AUTHORITY_INSUFFICIENT');
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
if (supply.audit?.vulnerabilities?.total !== 0) fail('NON_ZERO_VULNERABILITY_SNAPSHOT');
if (supply.signatures?.missing_count !== 0 || supply.signatures?.invalid_count !== 0) {
  fail('REGISTRY_SIGNATURE_DEBT');
}
if (supply.verification?.local_64_suite_bound !== false) {
  fail('LOCAL_64_SUITE_AUTHORITY_LAUNDERING');
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
    observation: supply.observation,
  })}\n`,
);
