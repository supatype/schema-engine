/**
 * Local engine binary cache management.
 *
 * Cache layout:
 *   ~/.supatype/engine/{version}/supatype-engine     (Unix)
 *   ~/.supatype/engine/{version}/supatype-engine.exe  (Windows)
 *
 * Multiple versions can coexist — useful when switching between projects
 * that pin different CLI versions.
 */

import { existsSync } from "node:fs";
import {
  mkdir,
  readdir,
  rm,
  stat,
  readFile,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

const SUPATYPE_DIR = join(homedir(), ".supatype");
const ENGINE_CACHE_DIR = join(SUPATYPE_DIR, "engine");
const UPDATE_CHECK_FILE = join(SUPATYPE_DIR, "update-check.json");

/**
 * Get the path to a cached engine binary.
 */
export function cachedBinaryPath(version: string, ext: string): string {
  return join(ENGINE_CACHE_DIR, version, `supatype-engine${ext}`);
}

/**
 * Check if a cached binary exists.
 */
export function isCached(version: string, ext: string): boolean {
  return existsSync(cachedBinaryPath(version, ext));
}

/**
 * Get the cache directory for a specific version, creating it if needed.
 */
export async function ensureCacheDir(version: string): Promise<string> {
  const dir = join(ENGINE_CACHE_DIR, version);
  await mkdir(dir, { recursive: true });
  return dir;
}

/**
 * List all cached engine versions.
 */
export async function listCachedVersions(): Promise<string[]> {
  if (!existsSync(ENGINE_CACHE_DIR)) return [];
  const entries = await readdir(ENGINE_CACHE_DIR, { withFileTypes: true });
  return entries.filter((e) => e.isDirectory()).map((e) => e.name);
}

/**
 * Remove cached engine versions, keeping the specified version.
 *
 * @param keepVersion - The version to keep (typically the pinned version)
 * @returns Object with count of removed versions and bytes reclaimed
 */
export async function pruneCache(
  keepVersion: string
): Promise<{ removed: number; bytesReclaimed: number }> {
  const versions = await listCachedVersions();
  let removed = 0;
  let bytesReclaimed = 0;

  for (const version of versions) {
    if (version === keepVersion) continue;

    const versionDir = join(ENGINE_CACHE_DIR, version);
    const dirStat = await getDirSize(versionDir);
    await rm(versionDir, { recursive: true, force: true });
    removed++;
    bytesReclaimed += dirStat;
  }

  return { removed, bytesReclaimed };
}

async function getDirSize(dirPath: string): Promise<number> {
  let size = 0;
  const entries = await readdir(dirPath, { withFileTypes: true });
  for (const entry of entries) {
    const entryPath = join(dirPath, entry.name);
    if (entry.isFile()) {
      const s = await stat(entryPath);
      size += s.size;
    }
  }
  return size;
}

/**
 * Check if enough time has passed since the last update check.
 * Returns true if we should check for updates (>24h since last check).
 * Always returns false in CI environments.
 */
export async function shouldCheckForUpdates(): Promise<boolean> {
  // Skip in CI environments
  if (process.env.CI === "true" || process.env.CI === "1") return false;

  try {
    const content = await readFile(UPDATE_CHECK_FILE, "utf-8");
    const data = JSON.parse(content);
    const lastCheck = new Date(data.lastCheck).getTime();
    const now = Date.now();
    const ONE_DAY_MS = 24 * 60 * 60 * 1000;
    return now - lastCheck > ONE_DAY_MS;
  } catch {
    // File doesn't exist or is corrupt — check now
    return true;
  }
}

/**
 * Record that an update check was performed.
 */
export async function recordUpdateCheck(): Promise<void> {
  await mkdir(SUPATYPE_DIR, { recursive: true });
  await writeFile(
    UPDATE_CHECK_FILE,
    JSON.stringify({ lastCheck: new Date().toISOString() }),
    "utf-8"
  );
}

/**
 * Format bytes as a human-readable string.
 */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}
