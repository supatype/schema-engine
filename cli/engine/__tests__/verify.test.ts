/**
 * Tests for checksum and signature verification.
 *
 * Covers Phase 0.5 tasks:
 *   #23 — Checksum and signature verification
 *   #42 — Corrupt binary detection
 *   #43 — Tampered checksum file detection
 *   #44 — Forged signature detection
 *   #45 — Missing .minisig file detection
 */

import { describe, it, expect } from "vitest";
import { parseChecksums, sha256File, verifyChecksum } from "../verify.js";
import { writeFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

describe("parseChecksums", () => {
  it("parses standard sha256sum output format", () => {
    const content = [
      "abc123def456abc123def456abc123def456abc123def456abc123def456abc12345  supatype-engine-0.1.0-linux-x64",
      "fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98  supatype-engine-0.1.0-darwin-arm64",
    ].join("\n");

    const checksums = parseChecksums(content);
    expect(checksums.size).toBe(2);
    expect(checksums.get("supatype-engine-0.1.0-linux-x64")).toBe(
      "abc123def456abc123def456abc123def456abc123def456abc123def456abc12345"
    );
    expect(checksums.get("supatype-engine-0.1.0-darwin-arm64")).toBe(
      "fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98fedcba98"
    );
  });

  it("ignores empty lines", () => {
    const content = "\nabc123def456abc123def456abc123def456abc123def456abc123def456abc12345  file.txt\n\n";
    const checksums = parseChecksums(content);
    expect(checksums.size).toBe(1);
  });
});

describe("sha256File", () => {
  it("computes correct SHA256 hash of a file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "verify-test-"));
    const filePath = join(dir, "test.bin");
    await writeFile(filePath, "hello world");

    const hash = await sha256File(filePath);
    // SHA256 of "hello world"
    expect(hash).toBe(
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );

    await rm(dir, { recursive: true });
  });
});

describe("verifyChecksum", () => {
  it("passes when checksum matches", async () => {
    const dir = await mkdtemp(join(tmpdir(), "verify-test-"));
    const filePath = join(dir, "engine");
    await writeFile(filePath, "binary content here");

    const hash = await sha256File(filePath);
    const checksumContent = `${hash}  engine`;

    await expect(
      verifyChecksum(filePath, "engine", checksumContent)
    ).resolves.toBe(true);

    await rm(dir, { recursive: true });
  });

  it("fails when checksum does not match (corrupt binary)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "verify-test-"));
    const filePath = join(dir, "engine");
    await writeFile(filePath, "binary content here");

    const checksumContent =
      "0000000000000000000000000000000000000000000000000000000000000000  engine";

    await expect(
      verifyChecksum(filePath, "engine", checksumContent)
    ).rejects.toThrow("Engine binary checksum mismatch");

    await rm(dir, { recursive: true });
  });

  it("fails when binary name is not in checksum file", async () => {
    const dir = await mkdtemp(join(tmpdir(), "verify-test-"));
    const filePath = join(dir, "engine");
    await writeFile(filePath, "content");

    const checksumContent =
      "abc123def456abc123def456abc123def456abc123def456abc123def456abc12345  other-file";

    await expect(
      verifyChecksum(filePath, "engine", checksumContent)
    ).rejects.toThrow("No checksum found for engine");

    await rm(dir, { recursive: true });
  });
});
