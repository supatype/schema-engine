/**
 * Binary verification: SHA256 checksum and minisign signature verification.
 *
 * Two-step verification:
 *   1. Verify the minisign signature on checksums.sha256 using the embedded
 *      public key — ensures the checksum file was produced by Supatype's CI.
 *   2. Verify the SHA256 hash of the downloaded binary against the signed
 *      checksum file — ensures the binary was not tampered with.
 *
 * Both checks are mandatory. The CLI never executes an unverified binary.
 */

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

/**
 * Supatype's minisign public key.
 *
 * This key is used to verify that checksums.sha256 was signed by Supatype's
 * CI pipeline. The corresponding private key is stored as a GitHub Actions
 * secret and never leaves CI.
 *
 * Key rotation procedure:
 *   1. Generate a new key pair: minisign -G
 *   2. Store the new private key in GitHub Actions secrets
 *   3. Update this constant with the new public key
 *   4. Publish a new CLI version with the updated key
 *   5. Sign a transition notice with both old and new keys
 *   6. Previous engine versions remain verifiable with the old CLI version
 *
 * TODO: Replace with actual public key after running: minisign -G
 */
export const MINISIGN_PUBLIC_KEY =
  "RWQ_REPLACE_WITH_ACTUAL_MINISIGN_PUBLIC_KEY_AFTER_GENERATION";

/**
 * Compute SHA256 hash of a file.
 */
export async function sha256File(filePath: string): Promise<string> {
  const content = await readFile(filePath);
  return createHash("sha256").update(content).digest("hex");
}

/**
 * Parse a checksums.sha256 file and return a map of filename → hash.
 * Format: `<hash>  <filename>` (two spaces, matching sha256sum output).
 */
export function parseChecksums(
  checksumContent: string
): Map<string, string> {
  const checksums = new Map<string, string>();
  for (const line of checksumContent.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    // sha256sum format: hash<two spaces>filename
    const match = trimmed.match(/^([a-f0-9]{64})\s{2}(.+)$/);
    if (match) {
      checksums.set(match[2], match[1]);
    }
  }
  return checksums;
}

/**
 * Verify the minisign signature on the checksum file.
 *
 * Requires `minisign` to be available on PATH, or bundled with the CLI.
 * Uses the embedded public key to verify the signature.
 *
 * @param checksumPath - Path to the checksums.sha256 file
 * @param signaturePath - Path to the checksums.sha256.minisig file
 * @param publicKey - The minisign public key (defaults to MINISIGN_PUBLIC_KEY)
 * @returns true if signature is valid
 * @throws Error if signature verification fails
 */
export async function verifySignature(
  checksumPath: string,
  signaturePath: string,
  publicKey: string = MINISIGN_PUBLIC_KEY
): Promise<boolean> {
  try {
    await execFileAsync("minisign", [
      "-V",
      "-P",
      publicKey,
      "-m",
      checksumPath,
      "-x",
      signaturePath,
    ]);
    return true;
  } catch (error) {
    throw new Error(
      "Engine checksum signature verification failed. " +
        "The checksum file may have been tampered with."
    );
  }
}

/**
 * Verify the SHA256 checksum of a binary against the signed checksum file.
 *
 * @param binaryPath - Path to the downloaded binary
 * @param binaryName - Filename of the binary (as listed in checksums.sha256)
 * @param checksumContent - Contents of the checksums.sha256 file
 * @returns true if checksum matches
 * @throws Error if checksum does not match
 */
export async function verifyChecksum(
  binaryPath: string,
  binaryName: string,
  checksumContent: string
): Promise<boolean> {
  const checksums = parseChecksums(checksumContent);
  const expectedHash = checksums.get(binaryName);

  if (!expectedHash) {
    throw new Error(
      `No checksum found for ${binaryName} in checksums.sha256. ` +
        `Available files: ${[...checksums.keys()].join(", ")}`
    );
  }

  const actualHash = await sha256File(binaryPath);

  if (actualHash !== expectedHash) {
    throw new Error(
      "Engine binary checksum mismatch. " +
        "This could indicate a corrupt download or a tampered binary. " +
        "Try again or report at github.com/supatype/supatype/issues"
    );
  }

  return true;
}
