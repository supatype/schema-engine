# Supatype Engine — Versioning & Release Process

## Versioning Policy

The engine follows strict [SemVer](https://semver.org/):

| Phase | Version Format | Example |
|-------|---------------|---------|
| Alpha | `0.x.y-alpha.N` | `0.1.0-alpha.1` |
| Beta | `0.x.y-beta.N` | `0.1.0-beta.1` |
| Stable pre-1.0 | `0.x.y` | `0.1.0` |
| GA | `1.0.0` | `1.0.0` |
| Post-GA | `x.y.z` | `1.2.3` |

**Version bump rules:**

- **Major** (1.0 → 2.0): Breaking changes to the schema AST format or CLI-engine protocol. The CLI checks major version compatibility — mismatched major versions are refused.
- **Minor** (0.1 → 0.2): New features, new subcommands, new generation targets. Backwards-compatible.
- **Patch** (0.1.0 → 0.1.1): Bug fixes, performance improvements. No behaviour changes.

## Version Pinning

The `@supatype/cli` package pins an **exact** engine version in its `package.json`:

```json
{
  "engineVersion": "0.1.0-alpha.1"
}
```

The CLI always downloads and uses this exact version. This ensures CLI and engine are always compatible and that two developers on the same project get identical behaviour.

## Release Checklist

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md` with release notes
3. Commit: `git commit -m "release: v0.1.0-alpha.1"`
4. Tag: `git tag v0.1.0-alpha.1`
5. Push: `git push origin main --tags`
6. CI automatically:
   - Runs full test suite on all platforms
   - Builds binaries for linux-x64, linux-arm64, darwin-x64, darwin-arm64, win-x64
   - Strips debug symbols (preserves them as CI artifacts)
   - Checks binary sizes (warns if > 20MB)
   - Generates `checksums.sha256` with SHA256 hashes of all binaries
   - Signs `checksums.sha256` with minisign
   - Uploads to Hetzner Object Storage CDN (`releases.supatype.io`)
   - Updates `latest.json` and `versions.json`
   - Creates GitHub Release on this repository
   - Creates GitHub Release on `supatype/engine-releases` (public fallback)
7. Update `@supatype/cli` `engineVersion` and publish to npm

## Binary Naming Convention

```
supatype-engine-{version}-{os}-{arch}{ext}
```

| Platform | Binary Name |
|----------|-------------|
| Linux x64 | `supatype-engine-0.1.0-alpha.1-linux-x64` |
| Linux ARM64 | `supatype-engine-0.1.0-alpha.1-linux-arm64` |
| macOS Intel | `supatype-engine-0.1.0-alpha.1-darwin-x64` |
| macOS Apple Silicon | `supatype-engine-0.1.0-alpha.1-darwin-arm64` |
| Windows x64 | `supatype-engine-0.1.0-alpha.1-win-x64.exe` |

## CDN Structure

```
https://releases.supatype.io/engine/
├── v{version}/
│   ├── supatype-engine-{version}-{os}-{arch}{ext}  (5 binaries)
│   ├── checksums.sha256
│   ├── checksums.sha256.minisig
│   └── CHANGELOG-v{version}.md
├── latest.json          ← current version, no-cache
└── versions.json        ← all versions, no-cache
```

Versioned paths use `Cache-Control: public, max-age=31536000, immutable`.
Manifest files use `Cache-Control: no-cache`.

## Security: Checksum & Signature Verification

The CLI performs two-step verification before executing any engine binary:

1. **Signature verification** — `checksums.sha256.minisig` is verified against the minisign public key embedded in the CLI source code. This ensures the checksum file was produced by Supatype's CI, not an attacker.

2. **Checksum verification** — The SHA256 hash of the downloaded binary is compared against the signed checksum file. This ensures the binary was not tampered with or corrupted.

Both checks are mandatory. If either fails, the binary is deleted and the CLI shows a clear error.

## Minisign Key Management

### Generating a new key pair

```sh
minisign -G -s minisign.key -p minisign.pub
```

### Storage

| Key | Location |
|-----|----------|
| Private key | GitHub Actions secret `MINISIGN_PRIVATE_KEY` |
| Private key password | GitHub Actions secret `MINISIGN_PASSWORD` |
| Private key backup | Offline encrypted storage (USB/paper, in a safe) |
| Public key | Embedded in CLI source: `cli/engine/verify.ts` |

### Key Rotation (in case of compromise)

1. Generate a new key pair: `minisign -G`
2. Update `MINISIGN_PRIVATE_KEY` and `MINISIGN_PASSWORD` in GitHub Actions secrets
3. Update `MINISIGN_PUBLIC_KEY` in `cli/engine/verify.ts`
4. Publish a new CLI version with the updated public key
5. Sign a transition notice with both old and new keys
6. Previous engine versions remain verifiable only with older CLI versions

## CI Secrets Required

| Secret | Purpose |
|--------|---------|
| `MINISIGN_PRIVATE_KEY` | Minisign private key for signing checksums |
| `MINISIGN_PASSWORD` | Password for the minisign private key |
| `HETZNER_S3_ACCESS_KEY` | Hetzner Object Storage access key |
| `HETZNER_S3_SECRET_KEY` | Hetzner Object Storage secret key |
| `HETZNER_S3_ENDPOINT` | Hetzner S3 endpoint URL |
| `HETZNER_S3_BUCKET` | Hetzner S3 bucket name |
| `ENGINE_RELEASES_TOKEN` | GitHub PAT for `supatype/engine-releases` repo |

## Reproducible Builds (Future)

For full reproducibility, document:
- Rust toolchain version (from `rust-toolchain.toml`)
- OS version of build runners
- Compilation flags (from `Cargo.toml` `[profile.release]`)
- `cross` version for Linux builds

This allows anyone with source access to reproduce the exact binary hash.
