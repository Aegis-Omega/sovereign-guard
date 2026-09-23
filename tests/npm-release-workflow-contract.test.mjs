import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const workflow = readFileSync(
  new URL('../.github/workflows/npm-publish.yml', import.meta.url),
  'utf8',
);

test('npm release workflow starts only at the published-release boundary', () => {
  assert.match(workflow, /release:\n\s+types: \[published\]/);
  assert.doesNotMatch(workflow, /types: \[created\]/);
});

test('release event SHA and tag are bound before verification', () => {
  assert.match(workflow, /ref: \$\{\{ github\.sha \}\}/);
  assert.match(workflow, /event_sha='\$\{\{ github\.sha \}\}'/);
  assert.match(workflow, /test "\$head" = "\$event_sha"/);
  assert.match(workflow, /test "\$tagged" = "\$event_sha"/);
  assert.match(
    workflow,
    /release-npm:[\s\S]*?ref: \$\{\{ needs\.verify-package\.outputs\.source_sha \}\}/,
  );
});

test('release source must be admitted by master history', () => {
  assert.match(
    workflow,
    /git merge-base --is-ancestor "\$head" refs\/remotes\/origin\/master/,
  );
});

test('release job reasserts the exact verified source after checkout', () => {
  assert.match(
    workflow,
    /test "\$\(git rev-parse HEAD\)" = '\$\{\{ needs\.verify-package\.outputs\.source_sha \}\}'/,
  );
});

test('engine matrix tarball digest must equal canonical verify-package tarball', () => {
  assert.match(
    workflow,
    /tarball_sha256: \$\{\{ steps\.package_digest\.outputs\.tarball_sha256 \}\}/,
  );
  assert.match(
    workflow,
    /test '\$\{\{ needs\.node-engine-compatibility-summary\.outputs\.tarball_sha256 \}\}' = '\$\{\{ needs\.verify-package\.outputs\.tarball_sha256 \}\}'/,
  );
});

test('release artifact is bound to producer run and attempt', () => {
  assert.match(workflow, /evidence_run_id: \$\{\{ steps\.evidence\.outputs\.run_id \}\}/);
  assert.match(workflow, /evidence_run_attempt: \$\{\{ steps\.evidence\.outputs\.run_attempt \}\}/);
  assert.match(workflow, /artifact_name: \$\{\{ steps\.evidence\.outputs\.artifact_name \}\}/);
  assert.match(workflow, /artifact_id: \$\{\{ steps\.upload\.outputs\.artifact-id \}\}/);
  assert.match(workflow, /artifact_digest: \$\{\{ steps\.upload\.outputs\.artifact-digest \}\}/);
  assert.match(
    workflow,
    /artifact-ids: \$\{\{ needs\.verify-package\.outputs\.artifact_id \}\}/,
  );
  assert.match(workflow, /digest-mismatch: error/);
  assert.doesNotMatch(workflow, /pattern: sovereign-guard-npm-\*/);
  assert.doesNotMatch(workflow, /name: \$\{\{ needs\.verify-package\.outputs\.artifact_name \}\}/);
  assert.match(workflow, /ARTIFACT_ID: \$\{\{ needs\.verify-package\.outputs\.artifact_id \}\}/);
  assert.match(workflow, /ARTIFACT_DIGEST: \$\{\{ needs\.verify-package\.outputs\.artifact_digest \}\}/);
  assert.match(
    workflow,
    /EXPECTED_RUN_ID: \$\{\{ needs\.verify-package\.outputs\.evidence_run_id \}\}/,
  );
  assert.match(
    workflow,
    /EXPECTED_RUN_ATTEMPT: \$\{\{ needs\.verify-package\.outputs\.evidence_run_attempt \}\}/,
  );
});

test('registry authority uses committed release preflight instead of inline verifier', () => {
  assert.match(workflow, /node scripts\/npm-release-preflight\.mjs/);
  assert.doesNotMatch(workflow, /node - <<'NODE'/);
});

test('OIDC permission is not granted at workflow top level', () => {
  const [header] = workflow.split('\njobs:\n', 1);
  assert.doesNotMatch(header, /id-token:\s*write/);
  assert.match(
    workflow,
    /release-npm:[\s\S]*?permissions:\n\s+contents: read\n\s+id-token: write/,
  );
});


test('GitHub Actions dependencies are pinned to Node24-native signed release SHAs', () => {
  assert.match(workflow, /actions\/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1/);
  assert.match(workflow, /actions\/setup-node@820762786026740c76f36085b0efc47a31fe5020/);
  assert.match(workflow, /actions\/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a/);
  assert.match(workflow, /actions\/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c/);
  assert.doesNotMatch(workflow, /11d5960a326750d5838078e36cf38b85af677262|49933ea5288caeca8642d1e84afbd3f7d6820020|ea165f8d65b6e75b540449e92b4886f43607fa02|d3f86a106a0bac45b974a628896c90dbdf5c8093/);
});
