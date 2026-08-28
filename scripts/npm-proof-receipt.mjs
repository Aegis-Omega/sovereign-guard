#!/usr/bin/env node

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const pkgPath = resolve(root, 'package.json');
const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));

function command(bin, args, options = {}) {
  return execFileSync(bin, args, {
    cwd: root,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options,
  }).trim();
}

function digest(algorithm, bytes) {
  return createHash(algorithm).update(bytes).digest('hex');
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonical(value[key])]),
    );
  }
  return value;
}

function runPack() {
  const packRaw = command('npm', ['pack', '--json', '--ignore-scripts']);
  const pack = JSON.parse(packRaw);
  if (!Array.isArray(pack) || pack.length !== 1) {
    throw new Error(
      `expected exactly one npm pack result, received ${Array.isArray(pack) ? pack.length : 'non-array'}`,
    );
  }

  const meta = pack[0];
  const tarball = resolve(root, meta.filename);
  const bytes = readFileSync(tarball);
  const files = [...(meta.files ?? [])]
    .map((file) => ({ path: file.path, size: file.size, mode: file.mode ?? null }))
    .sort((a, b) => a.path.localeCompare(b.path));
  const fileCensusCanonical = JSON.stringify(canonical(files));

  return {
    meta,
    tarball,
    bytes,
    files,
    sha256: digest('sha256', bytes),
    sha512: digest('sha512', bytes),
    fileCensusSha256: digest('sha256', Buffer.from(fileCensusCanonical)),
  };
}

const sourceSha = process.env.AEGIS_SOURCE_SHA || command('git', ['rev-parse', 'HEAD']);
if (!/^[0-9a-f]{40}$/i.test(sourceSha)) {
  throw new Error(`invalid source SHA: ${sourceSha}`);
}

const headSha = command('git', ['rev-parse', 'HEAD']);
if (headSha !== sourceSha) {
  throw new Error(`source SHA mismatch: HEAD=${headSha} expected=${sourceSha}`);
}

if (process.env.RELEASE_TAG && process.env.RELEASE_TAG !== `v${pkg.version}`) {
  throw new Error(`release tag/version mismatch: tag=${process.env.RELEASE_TAG} package=v${pkg.version}`);
}

const first = runPack();
rmSync(first.tarball, { force: true });
const second = runPack();

try {
  const reproducible =
    first.sha256 === second.sha256 &&
    first.sha512 === second.sha512 &&
    first.meta.shasum === second.meta.shasum &&
    first.meta.integrity === second.meta.integrity &&
    first.fileCensusSha256 === second.fileCensusSha256;
  if (!reproducible) {
    throw new Error(
      `npm pack is not reproducible: sha256 ${first.sha256} != ${second.sha256} or metadata/census differs`,
    );
  }

  const packedManifest = JSON.parse(command('tar', ['-xOf', second.tarball, 'package/package.json']));
  if (packedManifest.name !== pkg.name || packedManifest.version !== pkg.version) {
    throw new Error(
      `packed manifest identity mismatch: committed=${pkg.name}@${pkg.version} packed=${packedManifest.name}@${packedManifest.version}`,
    );
  }

  const forbiddenHooks = ['preinstall', 'install', 'postinstall'].filter(
    (name) => packedManifest.scripts?.[name] !== undefined,
  );
  if (forbiddenHooks.length > 0) {
    throw new Error(`packed manifest contains install lifecycle hooks: ${forbiddenHooks.join(', ')}`);
  }

  const receipt = canonical({
    receipt_version: 'NpmPackageReceiptV1',
    source: {
      repository: 'Aegis-Omega/sovereign-guard',
      git_sha: sourceSha,
    },
    package: {
      name: pkg.name,
      version: pkg.version,
      filename: second.meta.filename,
      packed_size: second.meta.size,
      unpacked_size: second.meta.unpackedSize,
      file_count: second.files.length,
      npm_shasum: second.meta.shasum ?? null,
      npm_integrity: second.meta.integrity ?? null,
      sha256: second.sha256,
      sha512: second.sha512,
      file_census_sha256: second.fileCensusSha256,
      files: second.files,
    },
    reproducibility: {
      independent_pack_count: 2,
      byte_for_byte_equal: first.sha256 === second.sha256,
      sha512_equal: first.sha512 === second.sha512,
      npm_shasum_equal: first.meta.shasum === second.meta.shasum,
      npm_integrity_equal: first.meta.integrity === second.meta.integrity,
      file_census_equal: first.fileCensusSha256 === second.fileCensusSha256,
      first_sha256: first.sha256,
      second_sha256: second.sha256,
    },
    verification: {
      exact_source_sha_verified: true,
      release_tag_matches_package_version: process.env.RELEASE_TAG
        ? process.env.RELEASE_TAG === `v${pkg.version}`
        : null,
      packed_manifest_identity_verified: true,
      lifecycle_install_hooks_absent: true,
      reproducible_pack_verified: true,
      local_64_suite_bound: false,
      authority: 'REMOTE_EXACT_SOURCE_PACK_VERIFIED',
    },
    non_claims: {
      operator_reported_64_suite_authenticated: false,
      aegis_mathematical_claims_established: false,
    },
  });

  const canonicalReceipt = `${JSON.stringify(receipt, null, 2)}\n`;
  const receiptRoot = digest('sha256', Buffer.from(canonicalReceipt));
  const output = canonical({ ...receipt, receipt_sha256: receiptRoot });

  const outDir = resolve(root, 'artifacts');
  mkdirSync(outDir, { recursive: true });
  const outPath = resolve(outDir, 'NpmPackageReceiptV1.json');
  writeFileSync(outPath, `${JSON.stringify(output, null, 2)}\n`);

  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
} finally {
  if (process.env.KEEP_NPM_TARBALL !== '1') {
    rmSync(second.tarball, { force: true });
  }
}
