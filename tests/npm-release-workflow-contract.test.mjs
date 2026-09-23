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
