# Engine Release Process

## Release Checklist

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Commit: `git commit -m "release: v0.1.0-alpha.1"`
4. Tag: `git tag v0.1.0-alpha.1`
5. Push: `git push origin main --tags`
6. CI automatically:
   - Tests on all platforms
   - Builds 5 platform binaries (linux-x64, linux-arm64, darwin-x64, darwin-arm64, win-x64)
   - Strips debug symbols
   - Generates checksums.sha256
   - Signs checksums with minisign
   - Uploads to CDN (releases.supatype.io)
   - Updates latest.json and versions.json
   - Creates GitHub Release on supatype-schema-engine
   - Mirrors to supatype/engine-releases (public fallback)
   - Creates PR on CLI repo to bump ENGINE_VERSION

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
| `HETZNER_S3_ACCESS_KEY` | Upload to Object Storage CDN |
| `HETZNER_S3_SECRET_KEY` | Upload to Object Storage CDN |
| `ENGINE_RELEASES_PAT` | Create releases on public fallback repo |
| `CLI_REPO_PAT` | Create PR on CLI repo to bump version |

## Reproducible Builds (Future)

To reproduce a release binary:

- Rust version: specified in `rust-toolchain.toml`
- Build flags: `cargo build --release --target <target>`
- LTO: enabled (`lto = true` in Cargo.toml release profile)
- Strip: enabled (`strip = true` in Cargo.toml release profile)
- OS: GitHub-hosted runners (Ubuntu latest, macOS 13/14, Windows latest)
