/**
 * CLI commands for engine management.
 *
 * Commands:
 *   npx supatype engine version     — show version info
 *   npx supatype engine update-check — check for updates
 *   npx supatype engine prune        — remove unused cached versions
 */

import {
  getVersionInfo,
  formatVersionInfo,
  fetchLatestVersion,
  fetchVersions,
  pruneCache,
  listCachedVersions,
  formatBytes,
  recordUpdateCheck,
} from "./index.js";

/**
 * `npx supatype engine version`
 *
 * Shows the pinned engine version, cached version, and latest available.
 */
export async function engineVersionCommand(
  pinnedVersion: string
): Promise<void> {
  const info = await getVersionInfo(pinnedVersion);
  console.log(formatVersionInfo(info));
}

/**
 * `npx supatype engine update-check`
 *
 * Checks latest.json and reports if a newer engine version is available.
 */
export async function engineUpdateCheckCommand(
  pinnedVersion: string
): Promise<void> {
  const latest = await fetchLatestVersion();
  await recordUpdateCheck();

  if (!latest) {
    console.log("Could not check for updates. Are you online?");
    return;
  }

  if (latest.version === pinnedVersion) {
    console.log(`Engine v${pinnedVersion} is up to date.`);
  } else {
    console.log(
      `Supatype engine v${latest.version} is available (current: v${pinnedVersion}). ` +
        `Run \`npm update @supatype/cli\` to upgrade.`
    );
  }
}

/**
 * `npx supatype engine prune`
 *
 * Removes all cached engine versions except the one pinned by the current CLI.
 */
export async function enginePruneCommand(
  pinnedVersion: string
): Promise<void> {
  const versions = await listCachedVersions();

  if (versions.length === 0) {
    console.log("No cached engine versions found.");
    return;
  }

  const { removed, bytesReclaimed } = await pruneCache(pinnedVersion);

  if (removed === 0) {
    console.log(
      `No unused versions to remove. Only v${pinnedVersion} (pinned) is cached.`
    );
  } else {
    console.log(
      `Removed ${removed} cached version${removed > 1 ? "s" : ""}. ` +
        `Reclaimed ${formatBytes(bytesReclaimed)}.`
    );
  }
}

/**
 * `npx supatype engine versions`
 *
 * Lists all released engine versions.
 */
export async function engineVersionsCommand(): Promise<void> {
  const versions = await fetchVersions();

  if (versions.length === 0) {
    console.log("Could not fetch version list. Are you online?");
    return;
  }

  console.log("Available engine versions:\n");
  for (const v of versions) {
    console.log(`  v${v.version}  (${v.date})`);
  }
}
