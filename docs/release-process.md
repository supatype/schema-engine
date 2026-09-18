# Engine Release Process

## Release Checklist

1. Update version in `Cargo.toml`, and run `cargo update -p supatype-engine` so
   `Cargo.lock` agrees
2. Commit: `git commit -m "release: v0.1.0-alpha.1"`
3. Tag: `git tag v0.1.0-alpha.1`
4. Push: `git push origin main --tags`
5. CI automatically:
   - Refuses the release unless the tag matches `Cargo.toml` (see below)
   - Runs `cargo test --workspace` against Postgres, with integration tests forced
   - Builds 5 platform binaries (linux-amd64, linux-arm64, darwin-amd64, darwin-arm64,
     windows-amd64)
   - Strips debug symbols
   - Generates checksums.sha256
   - Signs checksums with minisign
   - Uploads binaries, checksums and signature to CDN (releases.supatype.com)
   - Updates engine/latest.json
   - Creates a GitHub Release on supatype/schema-engine with generated notes
   - Builds and pushes the multi-platform `supatype/schema-engine` Docker image,
     tagged `v<version>` and `latest`

Step 1 is not optional book-keeping. `ENGINE_VERSION` comes from `CARGO_PKG_VERSION`
through `build.rs` and is written into every row of `_supatype` migration history and
into the generated migration header, so a tag that disagrees with the crate would label
its migrations with a version that was never released. The release's first job compares
the two and fails the whole run on a mismatch, before anything is built or published.

A tag pushed ahead of the bump therefore needs moving rather than re-running: commit the
bump, then `git push origin :refs/tags/vX.Y.Z && git tag -d vX.Y.Z && git tag vX.Y.Z &&
git push origin vX.Y.Z`.

## Versioning Policy

- `0.x.y-alpha.N` — alpha releases
- `0.x.y-beta.N` — beta releases
- `0.x.y` — stable pre-1.0 releases
- `1.0.0` — cloud launch
- Major bumps (1.0 → 2.0) — breaking changes to schema AST format
- Minor bumps — new features
- Patch bumps — bug fixes

## Minisign Key Management

### Key Generation

```bash
minisign -G -p supatype-engine.pub -s supatype-engine.key
```

### Key Storage

- **Public key**: Embedded in CLI source at `packages/cli/src/engine/verify.ts`
- **Private key**: Stored as GitHub Actions secrets:
  - `MINISIGN_PRIVATE_KEY` — the key file contents
  - `MINISIGN_PASSWORD` — the key password
- **Backup**: Encrypted USB + printed paper copy in a safe

### Key Rotation (Emergency Procedure)

If the private key is compromised:

1. Generate new key pair: `minisign -G`
2. Update `MINISIGN_PUBLIC_KEY` in CLI source
3. Update GitHub Actions secrets with new private key
4. Publish new CLI version with updated public key
5. Re-sign all existing releases with new key
6. Announce key rotation to users

## CI Secrets Required

| Secret | Purpose |
|--------|---------|
| `MINISIGN_PRIVATE_KEY` | Signs checksum files |
| `MINISIGN_PASSWORD` | Password for minisign private key |
| `CDN_AWS_ACCESS_KEY_ID` | Upload to Hetzner Object Storage CDN |
| `CDN_AWS_SECRET_ACCESS_KEY` | Upload to Hetzner Object Storage CDN |
| `CDN_AWS_REGION` | Region for the CDN bucket |
| `CDN_BUCKET` | CDN bucket name |
| `CDN_ENDPOINT` | S3 endpoint URL for the CDN bucket |
| `DOCKERHUB_USERNAME` | Push the engine image to Docker Hub |
| `DOCKERHUB_TOKEN` | Push the engine image to Docker Hub |

Hetzner Object Storage is S3-compatible but is not AWS: the upload steps pass
`--endpoint-url` and set the credentials as plain env vars. Do not reach for
`aws-actions/configure-aws-credentials`, which calls AWS STS.

## Reproducible Builds (Future)

To reproduce a release binary:

- Rust version: specified in `rust-toolchain.toml`
- Build flags: `cargo build --release --target <target>`
- LTO: thin (`lto = "thin"` in Cargo.toml release profile)
- Strip: enabled (`strip = true` in Cargo.toml release profile)
- OS: GitHub-hosted runners (ubuntu-22.04, macos-14, macos-15-intel, windows-2022)
