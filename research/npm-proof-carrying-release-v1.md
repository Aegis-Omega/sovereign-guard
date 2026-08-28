# NPM Proof-Carrying Release v1

Status: IMPLEMENTED / EXACT-HEAD RE-ATTESTATION REQUIRED AFTER EVERY SOURCE DELTA

Base source: `Aegis-Omega/sovereign-guard@3c6568684fc58bbab015f0ea34a87f9df4cfe1aa`

## Implemented authority contract

The branch now verifies `sovereign-guard@1.0.0` as a concrete npm artifact rather than treating repository source or a local PASS count as package authority.

Required verification path:

1. Assert the exact candidate SHA before verification.
2. Pin the verification toolchain to Node 24 and npm 11.19.0.
3. `npm ci`, `npm run build`, and committed `npm test` must pass.
4. Install the generated `.tgz` in an isolated project and execute both declared CLI bins.
5. Produce two independent `npm pack --json --ignore-scripts` outputs and require byte-for-byte equality, equal integrity metadata, and equal file census.
6. Packed name/version must equal the committed manifest and install lifecycle hooks must be absent.
7. Emit source SHA, package identity, file census, packed/unpacked sizes, npm shasum/integrity, SHA-256 and SHA-512 digests, and a deterministic timestamp-free `NpmPackageReceiptV1` root.
8. Run dependency vulnerability audit, registry signature/provenance verification, and generate a CycloneDX SBOM as supply-chain evidence.
9. Release must reuse the verified tarball. The workflow fails closed unless `NPM_RELEASE_MODE` explicitly selects `trusted-stage` or `bootstrap-token`; trusted staging is preferred and does not use a long-lived publish token.
10. A package name, older source commit, remote reference, or local PASS count cannot authenticate a different source/test artifact.

## Advisory-drift falsification and remediation

An independent AEGIS cross-runtime replay of the same previously verified Guard source later observed a newly surfaced LOW advisory against transitive `esbuild 0.27.3`. This demonstrated that source identity alone is insufficient to freeze registry/advisory state.

The dependency graph was therefore refreshed only within the already committed `tsx ^4.21.0` semver range by npm itself. A one-shot exact-head workflow generated and tested the candidate lock, required `npm audit --audit-level=low` to pass, and committed only after the resolved graph was:

- `tsx 4.23.12`
- `esbuild 0.28.2`
- vulnerability counts: info=0, low=0, moderate=0, high=0, critical=0, total=0

The generated `package-lock.json` SHA-256 was `07b6c8b2ddb35d8f28ca7e142234354b7a094c8a9f4b1c17fe71f87924f7a235`. The one-shot generator removed itself after committing the verified lock, so it is not part of the production workflow surface.

This audit result is a time-bound registry/advisory observation, not a timeless property of the source. Future exact-head verification must rerun the audit rather than inherit this count.

## Authority boundary

The public package can be promoted only when the current exact source is remotely replayed and the emitted npm receipt is inspected. The newer operator-reported 64/64 suite remains a separate component with `LOCAL_VERIFIED_UNBOUND` authority until its exact source and execution environment are committed or artifact-bound.

Non-claims: this slice does not authenticate the 64/64 suite by association, does not transfer authority from a remote package reference to local-only tests, and grants no mathematical authority to AEGIS claims.
