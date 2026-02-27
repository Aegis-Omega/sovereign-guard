# Sovereign Guard

**The AI code auditor that signs its own patches.**

Scan your TypeScript/JavaScript codebase for security issues, compliance gaps, and tech debt — then fix them with AI and seal your code with a cryptographic provenance stamp.

[![npm version](https://img.shields.io/npm/v/sovereign-guard.svg)](https://npmjs.com/package/sovereign-guard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Try It (Zero Setup)

```bash
npx sovereign-guard scan .
```

That's it. No config files, no accounts, no API keys needed for scanning.

## What It Finds

| Severity | Rule | What It Catches |
|:---|:---|:---|
| 🔴 **CRITICAL** | `no-hardcoded-secrets` | API keys, tokens, passwords in source |
| 🔴 **CRITICAL** | `hipaa-2026-audit` | Healthcare compliance violations |
| 🔴 **CRITICAL** | `dora-ict-risk` | EU financial resilience gaps (DORA) |
| 🔴 **CRITICAL** | `eu-ai-act` | AI transparency & oversight gaps |
| 🟠 **HIGH** | `no-silent-catch` | Empty catch blocks hiding errors |
| 🟠 **HIGH** | `missing-error-handling` | Async functions without try/catch |
| 🟠 **HIGH** | `no-math-random` | Math.random() in security contexts |
| 🟠 **HIGH** | `no-agent-auth-profile` | Missing auth in AI agent code |
| 🟡 **MEDIUM** | `no-any-type` | `: any` type escape hatches |
| 🟡 **MEDIUM** | `no-placeholder-logic` | PLACEHOLDER, STUB, MOCK left behind |
| 🟡 **MEDIUM** | `missing-audit-trail` | No logging in critical modules |
| 🟡 **MEDIUM** | `deprecated-api` | `substr`, `__proto__`, `new Buffer` |
| 🟢 **LOW** | `no-console-log` | console.log in production code |
| 🟢 **LOW** | `complexity-spike` | Functions >50 lines, files >200 lines |
| 🟢 **LOW** | `unused-imports` | Imported symbols never used |
| 🟢 **LOW** | `todo-debt` | TODO, FIXME, HACK comments |

## Commands

### `scan` — Find Issues (Free)

```bash
# Scan current directory
npx sovereign-guard scan .

# JSON output for CI/CD (exit code 1 on CRITICAL/HIGH)
npx sovereign-guard scan ./src --format json --output report.json

# Markdown report for stakeholders
npx sovereign-guard scan ./src --format md --output AUDIT.md

# Only show critical and high
npx sovereign-guard scan --min-severity HIGH
```

### `fix` — AI Auto-Patch (Pro)

Uses Google Gemini to generate fixes for every finding.

```bash
export GOOGLE_GENERATIVE_AI_API_KEY=your_key
npx sovereign-guard fix ./src --max-patches 5
```

Get a free API key at [aistudio.google.com/apikey](https://aistudio.google.com/apikey)

### `sign` — Cryptographic Seal (Pro)

Creates a SHA-256 provenance stamp proving your code was audited at this exact point in time.

```bash
npx sovereign-guard sign ./src
# Creates .sovereign-seal.json
```

## CI/CD Integration

```yaml
# .github/workflows/audit.yml
name: Security Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx sovereign-guard scan . --format json --min-severity HIGH
```

Exit code 1 if CRITICAL or HIGH findings are detected. Your PRs will fail if someone pushes a hardcoded API key.

## Configuration

Create `.guardrc.json` in your project root:

```json
{
  "include": ["**/*.ts", "**/*.js"],
  "exclude": ["node_modules/**", "dist/**"],
  "disableRules": ["no-console-log"],
  "minSeverity": "MEDIUM",
  "maxFiles": 500
}
```

## Why This Exists

ESLint catches syntax. SonarQube catches code smells. Neither catches an API key sitting in your config, an empty catch block hiding a payment failure, or a healthcare app missing its HIPAA revision date.

Sovereign Guard focuses on the **bugs that cost money** — the ones that become compliance violations, security incidents, and 3 AM pages.

## Built With

- TypeScript + Node.js
- [Google Gemini](https://ai.google.dev/) for AI patching
- [Commander.js](https://github.com/tj/commander.js/) for CLI

## License

MIT — use it, fork it, ship it.

---

Built in 🇧🇦 Bosnia & Herzegovina
