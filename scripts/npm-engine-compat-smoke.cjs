#!/usr/bin/env node

const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} = require('node:fs');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');

const root = resolve(__dirname, '..');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

function command(bin, args, cwd = root) {
  return execFileSync(bin, args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

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

const sourceSha = (process.env.AEGIS_SOURCE_SHA || '').trim();
const expectedMajor = (process.env.AEGIS_NODE_MAJOR || '').trim();
if (!/^[0-9a-f]{40}$/.test(sourceSha)) throw new Error('ENGINE_COMPAT_SOURCE_SHA_INVALID');
if (!/^(20|22|24)$/.test(expectedMajor)) throw new Error('ENGINE_COMPAT_NODE_MAJOR_INVALID');

const actualMajor = process.versions.node.split('.')[0];
if (actualMajor !== expectedMajor) {
  throw new Error(`ENGINE_COMPAT_NODE_MAJOR_MISMATCH expected=${expectedMajor} actual=${actualMajor}`);
}
if (pkg.engines?.node !== '>=20') {
  throw new Error(`ENGINE_CONTRACT_MISMATCH actual=${pkg.engines?.node ?? '<missing>'}`);
}
if ((process.env.npm_config_engine_strict || '').toLowerCase() !== 'true') {
  throw new Error('ENGINE_STRICT_NOT_ENABLED');
}

const npmVersion = command('npm', ['--version']);
const pack = JSON.parse(command('npm', ['pack', '--json', '--ignore-scripts']));
if (!Array.isArray(pack) || pack.length !== 1) throw new Error('ENGINE_COMPAT_PACK_RESULT_INVALID');
const meta = pack[0];
const tarball = resolve(root, meta.filename);
const tarballBytes = readFileSync(tarball);
const tarballSha256 = sha256(tarballBytes);

const sandbox = mkdtempSync(join(tmpdir(), `sovereign-guard-node-${expectedMajor}-`));
try {
  command('npm', ['init', '-y'], sandbox);
  command(
    'npm',
    ['install', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', tarball],
    sandbox,
  );

  const installedRoot = join(sandbox, 'node_modules', 'sovereign-guard');
  const api = require(installedRoot);
  for (const key of ['runScan', 'generatePatch', 'generateSeal', 'loadConfig']) {
    assert.equal(typeof api[key], 'function', `missing public API ${key}`);
  }

  const mainPath = join(installedRoot, 'dist', 'src', 'index.js');
  const typesPath = join(installedRoot, 'dist', 'src', 'index.d.ts');
  const cliPath = join(installedRoot, 'dist', 'bin', 'guard.js');
  for (const path of [mainPath, typesPath, cliPath]) {
    if (!existsSync(path)) throw new Error(`ENGINE_COMPAT_INSTALLED_PATH_MISSING path=${path}`);
  }

  const cliVersion = command(process.execPath, [cliPath, '--version'], sandbox);
  if (cliVersion !== pkg.version) {
    throw new Error(`ENGINE_COMPAT_CLI_VERSION_MISMATCH expected=${pkg.version} actual=${cliVersion}`);
  }

  const receiptCore = {
    receipt_version: 'NodeEngineCompatibilityReceiptV1',
    source: {
      repository: 'Aegis-Omega/sovereign-guard',
      git_sha: sourceSha,
    },
    package: {
      name: pkg.name,
      version: pkg.version,
      engines_node: pkg.engines.node,
      tarball_sha256: tarballSha256,
    },
    runtime: {
      node_version: process.versions.node,
      node_major: Number(actualMajor),
      npm_version: npmVersion,
      engine_strict: true,
    },
    verification: {
      npm_ci_completed_upstream: true,
      build_completed_upstream: true,
      isolated_tarball_install_verified: true,
      public_api_load_verified: true,
      cli_execution_verified: true,
      declared_entrypoints_present: true,
    },
  };
  const receipt = {
    ...receiptCore,
    receipt_sha256: sha256(Buffer.from(JSON.stringify(stable(receiptCore)))),
  };

  const artifacts = join(root, 'artifacts');
  mkdirSync(artifacts, { recursive: true });
  const target = join(
    artifacts,
    `NodeEngineCompatibilityReceiptV1-node-${expectedMajor}.json`,
  );
  writeFileSync(target, `${JSON.stringify(receipt, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(receipt)}\n`);
} finally {
  rmSync(tarball, { force: true });
  rmSync(sandbox, { recursive: true, force: true });
}
