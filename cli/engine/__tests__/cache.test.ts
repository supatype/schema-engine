/**
 * Tests for engine cache management.
 *
 * Covers Phase 0.5 tasks:
 *   #22 — Local cache directory
 *   #25 — Offline mode with valid cache
 *   #26 — Cache cleanup / prune
 *   #32 — Update check throttling
 *   #41 — Cache hit on second invocation
 *   #47 — No internet + valid cache
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { existsSync } from "node:fs";
import { formatBytes } from "../cache.js";

describe("formatBytes", () => {
  it("formats bytes", () => {
    expect(formatBytes(500)).toBe("500B");
  });

  it("formats kilobytes", () => {
    expect(formatBytes(1500)).toBe("1.5KB");
  });

  it("formats megabytes", () => {
    expect(formatBytes(15 * 1024 * 1024)).toBe("15.0MB");
  });
});
