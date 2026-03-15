/**
 * Engine version management: pinning, compatibility checking, update detection.
 */

import { readFile } from "node:fs/promises";
import {
  shouldCheckForUpdates,
  recordUpdateCheck,
  isCached,
  listCachedVersions,
} from "./cache.js";
import { detectPlatform } from "./platform.js";

export interface LatestVersionInfo {
  version: string;
  date: string;
  checksums_url: string;
}

export interface VersionEntry {
  version: string;
  date: string;
  binaries: Record<string, string>;
  checksums_url: string;
  signature_url: string;
  changelog_url: string;
}

const LATEST_URL = "https://releases.supatype.io/engine/latest.json";
const VERSIONS_URL = "https://releases.supatype.io/engine/versions.json";

/**
 * Parse a SemVer version string into its components.
 */
export function parseSemVer(version: string): {
  major: number;
  minor: number;
  patch: number;
  prerelease: string | null;
} {
  const match = version.match(
    /^(\d+)\.(\d+)\.(\d+)(?:-(.+))?$/
  );
  if (!match) throw new Error(`Invalid version: ${version}`);
  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
    patch: parseInt(match[3], 10),
    prerelease: match[4] || null,
  };
}

/**
 * Check if a cached engine version is compatible with the expected version.
 *
 * Compatibility rules:
 *   - Major versions must match exactly
 *   - If they don't match, the CLI refuses to run
 */
export function isCompatible(
  cachedVersion: string,
  expectedVersion: string
): boolean {
  const cached = parseSemVer(cachedVersion);
  const expected = parseSemVer(expectedVersion);
  return cached.major === expected.major;
}

/**
 * Get the version compatibility error message.
 */
export function incompatibleVersionMessage(
  cachedVersion: string,
  expectedVersion: string
): string {
  return (
    `Engine version ${cachedVersion} is not compatible with CLI ` +
    `expecting ${expectedVersion}. Run \`npm update @supatype/cli\` ` +
    `to get a compatible version.`
  );
}

/**
 * Fetch the latest available version from the CDN.
 */
export async function fetchLatestVersion(): Promise<LatestVersionInfo | null> {
  try {
    const response = await fetch(LATEST_URL);
    if (!response.ok) return null;
    return (await response.json()) as LatestVersionInfo;
  } catch {
    return null;
  }
}

/**
 * Fetch all available versions from the CDN.
 */
export async function fetchVersions(): Promise<VersionEntry[]> {
  try {
    const response = await fetch(VERSIONS_URL);
    if (!response.ok) return [];
    return (await response.json()) as VersionEntry[];
  } catch {
    return [];
  }
}

/**
 * Check for updates and return a message if an update is available.
 * Only checks once per 24 hours, skips in CI.
 */
export async function checkForUpdates(
  pinnedVersion: string
): Promise<string | null> {
  if (!(await shouldCheckForUpdates())) return null;

  const latest = await fetchLatestVersion();
  await recordUpdateCheck();

  if (!latest) return null;
  if (latest.version === pinnedVersion) return null;

  return (
    `Supatype engine v${latest.version} is available. ` +
    `Run \`npm update @supatype/cli\` to upgrade.`
  );
}

/**
 * Display engine version information.
 */
export async function getVersionInfo(pinnedVersion: string): Promise<{
  pinned: string;
  cached: string | null;
  latest: string | null;
  updateAvailable: boolean;
}> {
  const platform = detectPlatform();
  const cached = isCached(pinnedVersion, platform.ext) ? pinnedVersion : null;

  // Also check for other cached versions
  const allCached = await listCachedVersions();

  const latest = await fetchLatestVersion();

  return {
    pinned: pinnedVersion,
    cached: cached || (allCached.length > 0 ? allCached[0] : null),
    latest: latest?.version || null,
    updateAvailable: latest ? latest.version !== pinnedVersion : false,
  };
}

/**
 * Format version info for display.
 */
export function formatVersionInfo(info: {
  pinned: string;
  cached: string | null;
  latest: string | null;
  updateAvailable: boolean;
}): string {
  const parts: string[] = [];
  parts.push(`Engine: v${info.pinned} (pinned)`);

  if (info.cached) {
    const match = info.cached === info.pinned ? " ✓" : ` (expected v${info.pinned})`;
    parts.push(`Cache: v${info.cached}${match}`);
  } else {
    parts.push("Cache: not downloaded");
  }

  if (info.latest) {
    if (info.updateAvailable) {
      parts.push(
        `Latest: v${info.latest} — update available, run \`npm update @supatype/cli\``
      );
    } else {
      parts.push(`Latest: v${info.latest} (up to date)`);
    }
  }

  return parts.join(" · ");
}
