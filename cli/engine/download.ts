/**
 * Engine binary download with progress bar, retry, and proxy support.
 *
 * Download flow:
 *   1. Detect platform (os + arch)
 *   2. Check local cache — if valid, use cached binary
 *   3. Download binary from CDN (with fallback to GitHub Releases)
 *   4. Download checksums.sha256 and checksums.sha256.minisig
 *   5. Verify signature on checksum file (minisign)
 *   6. Verify binary checksum (SHA256)
 *   7. Save to cache, set executable permission
 */

import { createWriteStream } from "node:fs";
import { chmod, unlink, writeFile, readFile } from "node:fs/promises";
import { join } from "node:path";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";
import {
  detectPlatform,
  binaryName,
  cdnUrl,
  githubFallbackUrl,
} from "./platform.js";
import {
  verifySignature,
  verifyChecksum,
  sha256File,
} from "./verify.js";
import {
  cachedBinaryPath,
  isCached,
  ensureCacheDir,
} from "./cache.js";

export interface DownloadOptions {
  /** Engine version to download (e.g. "0.1.0-alpha.1") */
  version: string;
  /** Called with progress updates during download */
  onProgress?: (downloaded: number, total: number) => void;
}

const MAX_RETRIES = 3;
const RETRY_DELAYS = [1000, 3000, 10000]; // 1s, 3s, 10s

/**
 * Ensure the engine binary is available, downloading if necessary.
 * Returns the path to the executable binary.
 */
export async function ensureEngine(
  options: DownloadOptions
): Promise<string> {
  const { version } = options;
  const platform = detectPlatform();
  const ext = platform.ext;
  const binPath = cachedBinaryPath(version, ext);

  // Check cache first
  if (isCached(version, ext)) {
    return binPath;
  }

  // Need to download
  const filename = binaryName(version, platform);
  const cacheDir = await ensureCacheDir(version);
  const tmpBinaryPath = join(cacheDir, `${filename}.tmp`);

  try {
    // Download binary, checksum file, and signature
    const [binaryData, checksumContent, signatureContent] =
      await Promise.all([
        downloadWithRetry(version, filename, options.onProgress),
        downloadTextWithRetry(version, "checksums.sha256"),
        downloadTextWithRetry(version, "checksums.sha256.minisig"),
      ]);

    // Write binary to temp file
    await writeFile(tmpBinaryPath, binaryData);

    // Write checksum and signature files for minisign verification
    const checksumPath = join(cacheDir, "checksums.sha256");
    const signaturePath = join(cacheDir, "checksums.sha256.minisig");
    await writeFile(checksumPath, checksumContent);
    await writeFile(signaturePath, signatureContent);

    // Step 1: Verify signature on checksum file
    await verifySignature(checksumPath, signaturePath);

    // Step 2: Verify binary checksum
    await verifyChecksum(tmpBinaryPath, filename, checksumContent);

    // Verification passed — move to final location
    const { rename } = await import("node:fs/promises");
    await rename(tmpBinaryPath, binPath);

    // Set executable permission on Unix
    if (process.platform !== "win32") {
      await chmod(binPath, 0o755);
    }

    return binPath;
  } catch (error) {
    // Clean up on failure
    await unlink(tmpBinaryPath).catch(() => {});
    await unlink(binPath).catch(() => {});
    throw error;
  }
}

/**
 * Download a binary file with retry and progress reporting.
 * Tries CDN first, falls back to GitHub Releases.
 */
async function downloadWithRetry(
  version: string,
  filename: string,
  onProgress?: (downloaded: number, total: number) => void
): Promise<Buffer> {
  const urls = [
    cdnUrl(version, filename),
    githubFallbackUrl(version, filename),
  ];

  let lastError: Error | undefined;

  for (const url of urls) {
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      try {
        return await downloadFile(url, onProgress);
      } catch (error) {
        lastError = error as Error;
        if (attempt < MAX_RETRIES) {
          const delay = RETRY_DELAYS[attempt];
          process.stderr.write(
            `Download failed. Retrying (${attempt + 1}/${MAX_RETRIES})...\n`
          );
          await sleep(delay);
        }
      }
    }
  }

  throw new Error(
    `Cannot download Supatype engine. Check your internet connection.\n` +
      `Last error: ${lastError?.message}`
  );
}

/**
 * Download a text file (checksums, signature) with retry and CDN/GitHub fallback.
 */
async function downloadTextWithRetry(
  version: string,
  filename: string
): Promise<string> {
  const urls = [
    cdnUrl(version, filename),
    githubFallbackUrl(version, filename),
  ];

  let lastError: Error | undefined;

  for (const url of urls) {
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      try {
        const buffer = await downloadFile(url);
        return buffer.toString("utf-8");
      } catch (error) {
        lastError = error as Error;
        if (attempt < MAX_RETRIES) {
          await sleep(RETRY_DELAYS[attempt]);
        }
      }
    }
  }

  if (filename.endsWith(".minisig")) {
    throw new Error(
      "Cannot download engine checksum signature file. " +
        "The release may be incomplete. " +
        "Refusing to proceed without signature verification."
    );
  }

  throw new Error(
    `Cannot download ${filename}. Check your internet connection.\n` +
      `Last error: ${lastError?.message}`
  );
}

/**
 * Download a file from a URL, returning its contents as a Buffer.
 */
async function downloadFile(
  url: string,
  onProgress?: (downloaded: number, total: number) => void
): Promise<Buffer> {
  const response = await fetch(url);

  if (!response.ok) {
    if (response.status === 403 || response.status === 429) {
      throw new Error(
        `GitHub download rate limited. Try again in a few minutes, ` +
          `or set GITHUB_TOKEN for authenticated access (5,000 requests/hour).`
      );
    }
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  const contentLength = Number(response.headers.get("content-length") || 0);
  const reader = response.body?.getReader();

  if (!reader) {
    throw new Error("No response body");
  }

  const chunks: Uint8Array[] = [];
  let downloaded = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    downloaded += value.length;
    if (onProgress && contentLength > 0) {
      onProgress(downloaded, contentLength);
    }
  }

  return Buffer.concat(chunks);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
