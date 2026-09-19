# Engine Release Process

Everything below describes what `.github/workflows/release.yml` and
`.github/workflows/publish-docker.yml` actually do. Keep them in step: this file is a summary of
those workflows, not a separate process.

## Release checklist

1. Bump `version` in `Cargo.toml`.
2. Commit the bump.
3. Tag it: `git tag v0.3.0`. The tag must be the `Cargo.toml` version with a `v` prefix.
4. Push: `git push origin main --tags`.

The tag push runs `release.yml`, which does the rest in five stages.

### 1. Tag matches Cargo.toml

The job refuses to go further unless `${GITHUB_REF_NAME#v}` equals the crate version from
`cargo metadata`.

This gate is not cosmetic. `ENGINE_VERSION` comes from `CARGO_PKG_VERSION` through `build.rs`, and it
is bound to every row of `_supatype` migration history, written into the generated migration header,
and reported by both binaries. `Cargo.toml` once sat at `0.1.0` while tags ran to `v0.1.8`, so every
migration applied in that window recorded an engine version that was never released. A forgotten
bump is now a red release rather than a quiet mislabel.

### 2. Test

One `ubuntu-latest` job running `cargo test --workspace` against a `supatype/postgres:17-latest`
service, with `DATABASE_URL` and `SUPATYPE_FORCE_INTEGRATION_TESTS=1` set so an unreachable database
fails the release instead of skipping silently. The `wasm32-unknown-unknown` target is installed so
`test_wasm_build` runs here rather than taking its "target not installed" branch.

The language SDK exec tests deliberately skip here: they need a dozen toolchains, and `ci.yml`
already runs them on every push with `SUPATYPE_FORCE_EXEC_TESTS`.

### 3. Build

Five targets, in a matrix. Only the `supatype-engine` CLI binary is shipped; the server binary
reaches users through the Docker image instead.

| Artifact name | Runner | Rust target | Build |
|---|---|---|---|
| `supatype-engine-linux-amd64` | `ubuntu-22.04` | `x86_64-unknown-linux-gnu` | native |
| `supatype-engine-linux-arm64` | `ubuntu-22.04` | `aarch64-unknown-linux-gnu` | `cross` |
| `supatype-engine-darwin-arm64` | `macos-14` | `aarch64-apple-darwin` | native |
| `supatype-engine-darwin-amd64` | `macos-15-intel` | `x86_64-apple-darwin` | native |
| `supatype-engine-windows-amd64.exe` | `windows-2022` | `x86_64-pc-windows-msvc` | native |

Unix binaries are stripped after the build (`aarch64-linux-gnu-strip` for the cross target).

### 4. Sign, upload and release

1. `sha256sum supatype-engine-* > checksums.sha256`.
2. Sign it with minisign, trusted comment `supatype engine releases v<version>`, producing
   `checksums.sha256.minisig`.
3. Upload the binaries, `checksums.sha256` and `checksums.sha256.minisig` to
   `s3://<CDN_BUCKET>/engine/v<version>/`, each `immutable` with a one-year max-age.
4. Overwrite `s3://<CDN_BUCKET>/engine/latest.json` with `{version, date, checksums_url}`, cached
   `no-cache, no-store, must-revalidate`. Public URL base: `https://releases.supatype.com/engine/`.
5. Create the GitHub Release on this repo with generated notes, attaching the binaries, checksums
   and signature. A tag containing `-` is marked a prerelease.

Storage is Hetzner Object Storage, addressed with the plain `aws` CLI and an `--endpoint-url`. Do
not switch to `configure-aws-credentials`: it calls AWS STS, which Hetzner does not serve.

### 5. Publish the Docker image

`publish-docker.yml` runs as a reusable workflow once `publish` succeeds. It builds `linux/amd64` on
`ubuntu-latest` and `linux/arm64` on `ubuntu-24.04-arm`, pushes each by digest, then joins them into
one multi-platform manifest tagged `v<version>` and `latest` on `supatype/schema-engine`.

## What the workflow does not do

Worth stating, because earlier versions of this document claimed otherwise:

* No `CHANGELOG.md`. The GitHub Release notes are generated from commits
  (`generate_release_notes: true`), and no changelog file exists in this repo.
* No `versions.json`. Only `latest.json` is rewritten.
* No mirror to a public fallback repo.
* No automatic PR against the CLI repo to bump the engine version. The CLI's engine floor lives in
  `packages/cli/src/engine-floor.ts` in the `supatype` monorepo and is bumped by hand when a release
  introduces something the CLI must require.

## Versioning policy

* `0.x.y-alpha.N`: alpha releases.
* `0.x.y-beta.N`: beta releases.
* `0.x.y`: stable pre-1.0 releases.
* `1.0.0`: cloud launch.
* Major bump: breaking change to the schema AST wire format.
* Minor bump: new features.
* Patch bump: bug fixes.

Any tag containing `-` is published as a GitHub prerelease automatically.

## Minisign key management

### Generation

```bash
minisign -G -p supatype-engine.pub -s supatype-engine.key
```

### Storage

* **Private key**: GitHub Actions secrets on this repo, `MINISIGN_PRIVATE_KEY` (file contents) and
  `MINISIGN_PASSWORD`.
* **Public key**: the `MINISIGN_PUBLIC_KEY` secret in the `supatype` monorepo. It is baked into
  `packages/cli/src/release-public-key.ts` at CLI publish time by
  `scripts/embed-release-pubkey.mjs`, and can be overridden at runtime with
  `SUPATYPE_RELEASE_PUBLIC_KEY`. The checked-in constant is deliberately empty.
* **Backup**: encrypted USB plus a printed paper copy in a safe.

### Rotation (emergency)

If the private key is compromised:

1. Generate a new pair: `minisign -G`.
2. Replace the `MINISIGN_PRIVATE_KEY` and `MINISIGN_PASSWORD` secrets on this repo.
3. Replace the `MINISIGN_PUBLIC_KEY` secret on the `supatype` monorepo.
4. Publish a new CLI version so the new public key is embedded.
5. Re-sign existing releases and replace their `.minisig` files on the CDN.
6. Announce the rotation.

Step 4 is the one with a tail: a CLI already installed carries the old public key, so it cannot
verify anything signed with the new one until the user upgrades.

## CI secrets required

On `supatype-schema-engine`:

| Secret | Purpose |
|---|---|
| `MINISIGN_PRIVATE_KEY` | Signs `checksums.sha256` |
| `MINISIGN_PASSWORD` | Password for the minisign private key |
| `CDN_AWS_ACCESS_KEY_ID` | Hetzner Object Storage access key |
| `CDN_AWS_SECRET_ACCESS_KEY` | Hetzner Object Storage secret key |
| `CDN_AWS_REGION` | Region passed as `AWS_DEFAULT_REGION` |
| `CDN_BUCKET` | Bucket holding `engine/` |
| `CDN_ENDPOINT` | `--endpoint-url` for every `aws s3` call |
| `DOCKERHUB_USERNAME` | Docker Hub login for `supatype/schema-engine` |
| `DOCKERHUB_TOKEN` | Docker Hub access token |

On the `supatype` monorepo:

| Secret | Purpose |
|---|---|
| `MINISIGN_PUBLIC_KEY` | Embedded into the CLI so it can verify CDN downloads |

## Reproducible builds (future)

To reproduce a release binary:

* Rust version: the stable channel pinned by `rust-toolchain.toml`.
* Build flags: `cargo build --release --target <target>`, or `cross build` for
  `aarch64-unknown-linux-gnu`.
* Release profile in `Cargo.toml`: `opt-level = 3`, `lto = "thin"`, `codegen-units = 4`,
  `strip = true`.
* Runners: `ubuntu-22.04`, `macos-14`, `macos-15-intel`, `windows-2022`.

Note `codegen-units = 4` and thin LTO: output is not bit-for-bit deterministic across machines
today. Reproducibility would need `codegen-units = 1`, `lto = "fat"` and a pinned toolchain version
rather than `stable`.
