# NPM Proof-Carrying Release v1

Status: PREREGISTERED / RED EXPECTED

Base source: `Aegis-Omega/sovereign-guard@3c6568684fc58bbab015f0ea34a87f9df4cfe1aa`

The current package declares `sovereign-guard@1.0.0`, but the release workflow invokes `npm test` while the package manifest has no `test` script. There are no repository test files on the base tree and no GitHub Releases.

Required GREEN conditions:

1. Assert the exact candidate SHA before verification.
2. `npm ci`, `npm run build`, and committed `npm test` must pass.
3. `npm pack --json` must produce exactly one tarball.
4. Packed name/version must equal the committed manifest.
5. Emit source SHA, package name/version, file census, packed/unpacked sizes, SHA-256 and SHA-512 digests.
6. Canonical receipt generation must be deterministic and timestamp-free.
7. Publish must depend on complete verification and use npm provenance.
8. A package name, older source commit, or local PASS count cannot authenticate an unbound artifact.

Non-claims: this slice does not authenticate the newer operator-reported 64/64 suite until that exact suite is committed or artifact-bound, and it grants no mathematical authority to AEGIS claims.
