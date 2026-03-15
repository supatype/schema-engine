/**
 * Supatype Engine Manager
 *
 * This module handles downloading, verifying, caching, and executing the
 * Supatype engine binary. It is used by @supatype/cli to transparently
 * manage the engine lifecycle.
 *
 * Usage:
 *   import { ensureEngine } from './engine/index.js';
 *
 *   const enginePath = await ensureEngine({
 *     version: '0.1.0-alpha.1',
 *     onProgress: (downloaded, total) => { ... }
 *   });
 *
 *   // Execute the engine
 *   const result = execFileSync(enginePath, ['parse'], { input: schemaJson });
 */

export { detectPlatform, binaryName, cdnUrl, githubFallbackUrl } from "./platform.js";
export type { PlatformInfo } from "./platform.js";

export { sha256File, verifySignature, verifyChecksum, parseChecksums, MINISIGN_PUBLIC_KEY } from "./verify.js";

export {
  cachedBinaryPath,
  isCached,
  ensureCacheDir,
  listCachedVersions,
  pruneCache,
  shouldCheckForUpdates,
  recordUpdateCheck,
  formatBytes,
} from "./cache.js";

export { ensureEngine } from "./download.js";
export type { DownloadOptions } from "./download.js";

export {
  parseSemVer,
  isCompatible,
  incompatibleVersionMessage,
  fetchLatestVersion,
  fetchVersions,
  checkForUpdates,
  getVersionInfo,
  formatVersionInfo,
} from "./version.js";
export type { LatestVersionInfo, VersionEntry } from "./version.js";
