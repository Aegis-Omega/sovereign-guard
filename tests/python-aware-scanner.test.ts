import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { SovereignScanner } from '../src/engine';
import { DEFAULT_CONFIG, GuardConfig } from '../src/types';

async function scanFixture(
  files: Record<string, string>,
  config: Partial<GuardConfig> = {},
) {
  const dir = await mkdtemp(path.join(tmpdir(), 'sovereign-guard-python-'));
  try {
    for (const [name, content] of Object.entries(files)) {
      await writeFile(path.join(dir, name), content, 'utf8');
    }
    const scanner = new SovereignScanner({
      ...DEFAULT_CONFIG,
      ...config,
    });
    return await scanner.scan(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('default scan enumerates Python source', async () => {
  const report = await scanFixture({
    'safe.py': 'def add(a, b):\n    return a + b\n',
  });

  assert.equal(report.filesScanned, 1);
});

test('JavaScript/TypeScript-only rules do not run against Python source', async () => {
  const report = await scanFixture(
    {
      'embedded.py': [
        'payload = """',
        'async function ghost() {',
        '  console.log("not executable JavaScript")',
        '}',
        '"""',
      ].join('\n'),
    },
    { include: ['**/*.py'] },
  );

  const ids = new Set(report.findings.map((finding) => finding.ruleId));
  assert.equal(ids.has('missing-error-handling'), false);
  assert.equal(ids.has('no-console-log'), false);
});

test('cross-language secret rule detects a hardcoded Python API key', async () => {
  const report = await scanFixture(
    {
      'settings.py': 'API_KEY = "0123456789abcdef0123456789abcdef"\n',
    },
    { include: ['**/*.py'] },
  );

  assert.ok(report.findings.some((finding) => finding.ruleId === 'no-hardcoded-secrets'));
});

test('Python environment lookup is not treated as a hardcoded secret', async () => {
  const report = await scanFixture(
    {
      'settings.py': 'import os\nAPI_KEY = os.environ["API_KEY"]\n',
    },
    { include: ['**/*.py'] },
  );

  assert.equal(
    report.findings.some((finding) => finding.ruleId === 'no-hardcoded-secrets'),
    false,
  );
});

test('Python subprocess shell=True is reported', async () => {
  const report = await scanFixture(
    {
      'runner.py': 'import subprocess\nsubprocess.run("echo hi", shell=True)\n',
    },
    { include: ['**/*.py'] },
  );

  assert.ok(report.findings.some((finding) => finding.ruleId === 'python-subprocess-shell'));
});

test('Python eval/exec dynamic execution is reported', async () => {
  const report = await scanFixture(
    {
      'dynamic.py': 'def run(expr):\n    return eval(expr)\n',
    },
    { include: ['**/*.py'] },
  );

  assert.ok(
    report.findings.some((finding) => finding.ruleId === 'python-dynamic-code-execution'),
  );
});

test('existing TypeScript missing-error-handling behavior remains active', async () => {
  const report = await scanFixture({
    'worker.ts': 'async function boot() {\n  await start();\n}\n',
  });

  assert.ok(report.findings.some((finding) => finding.ruleId === 'missing-error-handling'));
});
