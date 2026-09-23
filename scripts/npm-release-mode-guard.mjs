#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export function evaluateReleaseMode(mode, registryState) {
  if (!['trusted-stage', 'bootstrap-token'].includes(mode)) {
    throw new Error(`RELEASE_MODE_INVALID mode=${mode || '<empty>'}`);
  }
  if (!['PACKAGE_PRESENT', 'PACKAGE_ABSENT'].includes(registryState)) {
    throw new Error(`REGISTRY_STATE_INVALID state=${registryState || '<empty>'}`);
  }
  if (mode === 'trusted-stage' && registryState !== 'PACKAGE_PRESENT') {
    throw new Error('TRUSTED_STAGE_REQUIRES_EXISTING_PACKAGE');
  }
  if (mode === 'bootstrap-token' && registryState !== 'PACKAGE_ABSENT') {
    throw new Error('BOOTSTRAP_TOKEN_REQUIRES_ABSENT_PACKAGE');
  }
  return { mode, registry_state: registryState };
}

async function observeRegistryState(packageName) {
  const url = `https://registry.npmjs.org/${encodeURIComponent(packageName)}`;
  let response;
  try {
    response = await fetch(url, {
      headers: { accept: 'application/json' },
      signal: AbortSignal.timeout(10000),
    });
  } catch (error) {
    throw new Error(`NPM_REGISTRY_OBSERVATION_FAILED cause=${error?.name || 'unknown'}`);
  }

  if (response.status === 404) return 'PACKAGE_ABSENT';
  if (response.status !== 200) {
    throw new Error(`NPM_REGISTRY_OBSERVATION_FAILED status=${response.status}`);
  }

  let metadata;
  try {
    metadata = await response.json();
  } catch {
    throw new Error('NPM_REGISTRY_METADATA_INVALID');
  }
  if (metadata?.name !== packageName) {
    throw new Error(
      `NPM_REGISTRY_PACKAGE_IDENTITY_MISMATCH expected=${packageName} actual=${metadata?.name ?? '<missing>'}`,
    );
  }
  return 'PACKAGE_PRESENT';
}

async function main() {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  if (typeof pkg.name !== 'string' || pkg.name.length === 0) {
    throw new Error('PACKAGE_NAME_INVALID');
  }

  const mode = (process.env.NPM_RELEASE_MODE ?? '').trim();
  const registryState = await observeRegistryState(pkg.name);
  const result = evaluateReleaseMode(mode, registryState);
  process.stdout.write(
    `${JSON.stringify({
      status: 'NPM_RELEASE_MODE_VERIFIED',
      package: pkg.name,
      ...result,
    })}\n`,
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
