# NPM Proof-Carrying Release v1

Status: IMPLEMENTED / EXACT-HEAD RE-ATTESTATION REQUIRED AFTER EVERY SOURCE DELTA

Base source: `Aegis-Omega/sovereign-guard@3c6568684fc58bbab015f0ea34a87f9df4cfe1aa`

## Implemented authority contract

The branch now verifies `sovereign-guard@1.0.0` as a concrete npm artifact rather than treating repository source or a local PASS count as package authority.

Required verification path:

1. Assert the exact candidate SHA before verification.
2. Pin the verification toolchain to Node 24 and npm 11.19.0. GitHub action dependencies are also pinned to signed Node24-native release commits: checkout v7.0.1, setup-node v7.0.0, upload-artifact v7.0.1, and download-artifact v8.0.1.
3. `npm ci`, `npm run build`, and committed `npm test` must pass.
4. Install the generated `.tgz` in an isolated project and execute both declared CLI bins.
5. Produce two independent `npm pack --json --ignore-scripts` outputs and require byte-for-byte equality, equal integrity metadata, and equal file census.
6. Packed name/version must equal the committed manifest and install lifecycle hooks must be absent.
7. Emit source SHA, package identity, file census, packed/unpacked sizes, npm shasum/integrity, SHA-256 and SHA-512 digests, and a deterministic timestamp-free `NpmPackageReceiptV1` root.
8. Run dependency vulnerability audit, registry signature/provenance verification, and generate a CycloneDX SBOM as supply-chain evidence. Every verified registry-signature entry is bound by unique install location to an exact locked `name@version` under `lock.packages`, with npm registry origin required; unlocked, duplicate-location, wrong-version, or foreign-registry signature records fail closed. Every CycloneDX npm component must likewise map to a locked `name@version` with canonical npm purl/bom-ref, and every dependency edge must stay within the root-plus-component graph; foreign components and dangling refs fail closed. Before supply-chain authority is emitted, the generator independently recomputes the `NpmPackageReceiptV1` root instead of trusting its claimed `receipt_sha256`, requires npm lockfile v3, and binds both top-level and `packages[""]` lockfile package identity to the verified package. Vulnerability metadata is fail-closed: every severity count must be a non-negative integer and `total` must equal the sum of `info+low+moderate+high+critical` before a zero-vulnerability snapshot can be admitted. The canonical supply-chain receipt binds the GitHub Actions run id, attempt, run number, workflow, and event name so later advisory replays cannot inherit an older observation identity.
9. Registry release runs only on the GitHub `release.published` boundary. Verification checks out the immutable release-event `github.sha`, requires the named release tag to resolve to that same commit, and then requires that exact commit to be contained in canonical `master` history. A moved tag, draft-save/create event, or side-branch tag therefore cannot substitute the release candidate.
10. Release must reuse the verified tarball. The verify job emits the exact evidence producer `run_id`, `run_attempt`, attempt-bound artifact name, immutable GitHub artifact ID, and artifact digest; downstream registry action requires the producer metadata, downloads by immutable artifact ID with `digest-mismatch: error`, and then validates against the producer identity rather than the consumer retry attempt. Before registry action, the committed and PR-tested `scripts/npm-release-preflight.mjs` verifies both receipt versions and the exact repository identity `Aegis-Omega/sovereign-guard`, verifies the uploaded SHA-256 evidence manifest, recomputes both canonical receipt roots, rebinds the actual audit/signature/SBOM files and checkout `package-lock.json` to their receipt digests, requires package receipt source SHA = supply-chain receipt source SHA = admitted release SHA, verifies the concrete tarball bytes, and rechecks hosted run identity. `scripts/npm-release-mode-guard.mjs` then observes npm registry package and target-version state fail-closed: a `200` response must contain the exact package identity and a valid `versions` map, and the exact target version must be absent; `trusted-stage` is allowed only for an existing package with an unpublished target version, while `bootstrap-token` is allowed only for first publication when the package itself is absent. OIDC permission exists only on the registry-action job.
11. A package name, older source commit, remote reference, or local PASS count cannot authenticate a different source/test artifact.

## Advisory-drift falsification and remediation

An independent AEGIS cross-runtime replay of the same previously verified Guard source later observed a newly surfaced LOW advisory against transitive `esbuild 0.27.3`. This demonstrated that source identity alone is insufficient to freeze registry/advisory state.

The dependency graph was therefore refreshed only within the already committed `tsx ^4.21.0` semver range by npm itself. A one-shot exact-head workflow generated and tested the candidate lock, required `npm audit --audit-level=low` to pass, and committed only after the resolved graph was:

- `tsx 4.23.12`
- `esbuild 0.28.2`
- vulnerability counts: info=0, low=0, moderate=0, high=0, critical=0, total=0

The generated `package-lock.json` SHA-256 was `07b6c8b2ddb35d8f28ca7e142234354b7a094c8a9f4b1c17fe71f87924f7a235`. The one-shot generator removed itself after committing the verified lock, so it is not part of the production workflow surface.

This audit result is a time-bound registry/advisory observation, not a timeless property of the source. Future exact-head verification must rerun the audit rather than inherit this count. `NpmSupplyChainReceiptV1` therefore carries hosted run identity (`run_id`, `run_attempt`, `run_number`, workflow and event) in its canonical root.

## Authority boundary

The public package can be promoted only when the current exact source is remotely replayed and the emitted npm receipt is inspected. The newer operator-reported 64/64 suite remains a separate component with `LOCAL_VERIFIED_UNBOUND` authority until its exact source and execution environment are committed or artifact-bound.

Non-claims: this slice does not authenticate the 64/64 suite by association, does not transfer authority from a remote package reference to local-only tests, and grants no mathematical authority to AEGIS claims.
