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

const sourceSha = process.env.GITHUB_SHA || command('git', ['rev-parse', 'HEAD']);
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

const packRaw = command('npm', ['pack', '--json', '--ignore-scripts']);
const pack = JSON.parse(packRaw);
if (!Array.isArray(pack) || pack.length !== 1) {
  throw new Error(`expected exactly one npm pack result, received ${Array.isArray(pack) ? pack.length : 'non-array'}`);
}

const packed = pack[0];
const tarball = resolve(root, packed.filename);
const tarBytes = readFileSync(tarball);

try {
  const packedManifest = JSON.parse(command('tar', ['-xOf', tarball, 'package/package.json']));
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

  const files = [...(packed.files ?? [])]
    .map((file) => ({ path: file.path, size: file.size, mode: file.mode ?? null }))
    .sort((a, b) => a.path.localeCompare(b.path));

  const fileCensusCanonical = JSON.stringify(canonical(files));
  const receipt = canonical({
    receipt_version: 'NpmPackageReceiptV1',
    source: {
      repository: 'Aegis-Omega/sovereign-guard',
      git_sha: sourceSha,
    },
    package: {
      name: pkg.name,
      version: pkg.version,
      filename: packed.filename,
      packed_size: packed.size,
      unpacked_size: packed.unpackedSize,
      file_count: files.length,
      npm_shasum: packed.shasum ?? null,
      npm_integrity: packed.integrity ?? null,
      sha256: digest('sha256', tarBytes),
      sha512: digest('sha512', tarBytes),
      file_census_sha256: digest('sha256', Buffer.from(fileCensusCanonical)),
      files,
    },
    verification: {
      exact_source_sha_verified: true,
      release_tag_matches_package_version: process.env.RELEASE_TAG
        ? process.env.RELEASE_TAG === `v${pkg.version}`
        : null,
      packed_manifest_identity_verified: true,
      lifecycle_install_hooks_absent: true,
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
    rmSync(tarball, { force: true });
  }
}
