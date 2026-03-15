# Changelog

All notable changes to the Supatype Engine will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Release pipeline: automated binary builds for linux-x64, linux-arm64, darwin-x64, darwin-arm64, win-x64
- SHA256 checksum generation and minisign signature verification
- CDN distribution via releases.supatype.io with Cloudflare edge caching
- GitHub Releases fallback distribution via supatype/engine-releases
- CLI engine management module: download, verify, cache, version commands
- Binary size monitoring in CI (warns if > 20MB)
- Debug symbol preservation as CI artifacts
- Release manifests: latest.json and versions.json
- CLI version coordination: automatic PR to update pinned engine version
