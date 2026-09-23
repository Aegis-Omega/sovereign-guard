#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';

function fail(code, detail = '') {
  throw new Error(detail ? `${code} ${detail}` : code);
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

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function receiptRoot(receipt) {
  const core = structuredClone(receipt);
  const claimed = core.receipt_sha256;
  delete core.receipt_sha256;
  const recomputed = sha256(Buffer.from(JSON.stringify(stable(core))));
  if (claimed !== recomputed) fail('ENGINE_COMPAT_RECEIPT_ROOT_INVALID');
  return recomputed;
}

function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(path));
    else out.push(path);
  }
  return out;
}

const inputRoot = resolve(process.argv[2] || 'compat-receipts');
const sourceSha = (process.env.AEGIS_SOURCE_SHA || '').trim();
if (!/^[0-9a-f]{40}$/.test(sourceSha)) fail('ENGINE_MATRIX_SOURCE_SHA_INVALID');

const expectedMajors = ['20', '22', '24'];
const files = walk(inputRoot).filter((path) =>
  /^NodeEngineCompatibilityReceiptV1-node-(20|22|24)\.json$/.test(basename(path)),
);
if (files.length !== expectedMajors.length) {
  fail('ENGINE_MATRIX_RECEIPT_COUNT_MISMATCH', `actual=${files.length}`);
}

const byMajor = new Map();
for (const path of files) {
  const receipt = JSON.parse(readFileSync(path, 'utf8'));
  receiptRoot(receipt);
  if (receipt.receipt_version !== 'NodeEngineCompatibilityReceiptV1') {
    fail('ENGINE_COMPAT_RECEIPT_VERSION_MISMATCH');
  }
  if (receipt.source?.repository !== 'Aegis-Omega/sovereign-guard') {
    fail('ENGINE_COMPAT_REPOSITORY_MISMATCH');
  }
  if (receipt.source?.git_sha !== sourceSha) fail('ENGINE_COMPAT_SOURCE_SHA_MISMATCH');
  if (receipt.package?.name !== 'sovereign-guard' || receipt.package?.engines_node !== '>=20') {
    fail('ENGINE_COMPAT_PACKAGE_CONTRACT_MISMATCH');
  }
  const major = String(receipt.runtime?.node_major ?? '');
  if (!expectedMajors.includes(major)) fail('ENGINE_COMPAT_UNEXPECTED_MAJOR', `major=${major}`);
  if (byMajor.has(major)) fail('ENGINE_COMPAT_DUPLICATE_MAJOR', `major=${major}`);
  if (receipt.runtime?.engine_strict !== true) fail('ENGINE_COMPAT_ENGINE_STRICT_UNVERIFIED');
  for (const flag of [
    'npm_ci_completed_upstream',
    'build_completed_upstream',
    'isolated_tarball_install_verified',
    'public_api_load_verified',
    'cli_execution_verified',
    'declared_entrypoints_present',
  ]) {
    if (receipt.verification?.[flag] !== true) {
      fail('ENGINE_COMPAT_VERIFICATION_FLAG_MISSING', `flag=${flag} major=${major}`);
    }
  }
  if (!/^[0-9a-f]{64}$/.test(receipt.package?.tarball_sha256 ?? '')) {
    fail('ENGINE_COMPAT_TARBALL_SHA_INVALID');
  }
  byMajor.set(major, receipt);
}

for (const major of expectedMajors) {
  if (!byMajor.has(major)) fail('ENGINE_COMPAT_REQUIRED_MAJOR_MISSING', `major=${major}`);
}

const versions = new Set([...byMajor.values()].map((r) => r.package.version));
if (versions.size !== 1) fail('ENGINE_COMPAT_PACKAGE_VERSION_DIVERGENCE');
const tarballDigests = new Set([...byMajor.values()].map((r) => r.package.tarball_sha256));
if (tarballDigests.size !== 1) fail('ENGINE_COMPAT_TARBALL_DIVERGENCE');

const receiptCore = {
  receipt_version: 'NodeEngineMatrixReceiptV1',
  source: {
    repository: 'Aegis-Omega/sovereign-guard',
    git_sha: sourceSha,
  },
  package: {
    name: 'sovereign-guard',
    version: [...versions][0],
    engines_node: '>=20',
    tarball_sha256: [...tarballDigests][0],
  },
  tested_node_majors: expectedMajors.map(Number),
  receipts: expectedMajors.map((major) => ({
    node_major: Number(major),
    node_version: byMajor.get(major).runtime.node_version,
    npm_version: byMajor.get(major).runtime.npm_version,
    receipt_sha256: byMajor.get(major).receipt_sha256,
  })),
  verification: {
    engine_strict_matrix_verified: true,
    isolated_install_matrix_verified: true,
    public_api_matrix_verified: true,
    cli_matrix_verified: true,
    cross_runtime_tarball_sha256_equal: true,
  },
};
const receipt = {
  ...receiptCore,
  receipt_sha256: sha256(Buffer.from(JSON.stringify(stable(receiptCore)))),
};

const artifacts = resolve('artifacts');
mkdirSync(artifacts, { recursive: true });
writeFileSync(
  join(artifacts, 'NodeEngineMatrixReceiptV1.json'),
  `${JSON.stringify(receipt, null, 2)}\n`,
);

if (process.env.GITHUB_OUTPUT) {
  const lines = [
    `source_sha=${sourceSha}`,
    `receipt_sha256=${receipt.receipt_sha256}`,
    `tarball_sha256=${receipt.package.tarball_sha256}`,
  ];
  writeFileSync(process.env.GITHUB_OUTPUT, `${lines.join('\n')}\n`, { flag: 'a' });
}
process.stdout.write(`${JSON.stringify(receipt)}\n`);
