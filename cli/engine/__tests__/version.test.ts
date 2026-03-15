/**
 * Tests for version parsing, compatibility, and display.
 *
 * Covers Phase 0.5 tasks:
 *   #1  — SemVer versioning policy
 *   #3  — Version compatibility matrix
 *   #30 — engine version command output
 *   #50 — Version mismatch detection
 */

import { describe, it, expect } from "vitest";
import {
  parseSemVer,
  isCompatible,
  incompatibleVersionMessage,
  formatVersionInfo,
} from "../version.js";

describe("parseSemVer", () => {
  it("parses stable version", () => {
    const v = parseSemVer("1.2.3");
    expect(v).toEqual({ major: 1, minor: 2, patch: 3, prerelease: null });
  });

  it("parses alpha version", () => {
    const v = parseSemVer("0.1.0-alpha.1");
    expect(v).toEqual({ major: 0, minor: 1, patch: 0, prerelease: "alpha.1" });
  });

  it("parses beta version", () => {
    const v = parseSemVer("0.2.0-beta.3");
    expect(v).toEqual({ major: 0, minor: 2, patch: 0, prerelease: "beta.3" });
  });

  it("throws on invalid version", () => {
    expect(() => parseSemVer("not-a-version")).toThrow("Invalid version");
  });
});

describe("isCompatible", () => {
  it("same major version is compatible", () => {
    expect(isCompatible("1.0.0", "1.5.0")).toBe(true);
  });

  it("different major version is incompatible", () => {
    expect(isCompatible("2.1.0", "1.3.0")).toBe(false);
  });

  it("pre-1.0 versions with same major are compatible", () => {
    expect(isCompatible("0.1.0-alpha.1", "0.2.0-alpha.2")).toBe(true);
  });
});

describe("incompatibleVersionMessage", () => {
  it("includes both versions and update instructions", () => {
    const msg = incompatibleVersionMessage("2.1.0", "1.3.0");
    expect(msg).toContain("2.1.0");
    expect(msg).toContain("1.3.0");
    expect(msg).toContain("npm update @supatype/cli");
  });
});

describe("formatVersionInfo", () => {
  it("shows up-to-date info", () => {
    const output = formatVersionInfo({
      pinned: "0.1.0-alpha.1",
      cached: "0.1.0-alpha.1",
      latest: "0.1.0-alpha.1",
      updateAvailable: false,
    });
    expect(output).toContain("v0.1.0-alpha.1 (pinned)");
    expect(output).toContain("Cache: v0.1.0-alpha.1 ✓");
    expect(output).toContain("up to date");
  });

  it("shows update available", () => {
    const output = formatVersionInfo({
      pinned: "0.1.0-alpha.1",
      cached: "0.1.0-alpha.1",
      latest: "0.1.0-alpha.2",
      updateAvailable: true,
    });
    expect(output).toContain("update available");
    expect(output).toContain("npm update @supatype/cli");
  });

  it("shows not downloaded", () => {
    const output = formatVersionInfo({
      pinned: "0.1.0-alpha.1",
      cached: null,
      latest: null,
      updateAvailable: false,
    });
    expect(output).toContain("not downloaded");
  });
});
