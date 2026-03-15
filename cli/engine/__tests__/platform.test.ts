/**
 * Tests for platform detection and binary naming.
 *
 * Covers Phase 0.5 tasks:
 *   #27 — Platform detection
 *   #49 — Unsupported platform error
 */

import { describe, it, expect } from "vitest";
import { detectPlatform, binaryName, cdnUrl, githubFallbackUrl } from "../platform.js";

describe("binaryName", () => {
  it("generates correct name for linux-x64", () => {
    expect(binaryName("0.1.0-alpha.1", { os: "linux", arch: "x64", ext: "" }))
      .toBe("supatype-engine-0.1.0-alpha.1-linux-x64");
  });

  it("generates correct name for darwin-arm64", () => {
    expect(binaryName("0.1.0-alpha.1", { os: "darwin", arch: "arm64", ext: "" }))
      .toBe("supatype-engine-0.1.0-alpha.1-darwin-arm64");
  });

  it("generates correct name for win-x64 with .exe extension", () => {
    expect(binaryName("0.1.0-alpha.1", { os: "win", arch: "x64", ext: ".exe" }))
      .toBe("supatype-engine-0.1.0-alpha.1-win-x64.exe");
  });

  it("generates correct name for stable version", () => {
    expect(binaryName("1.2.3", { os: "linux", arch: "arm64", ext: "" }))
      .toBe("supatype-engine-1.2.3-linux-arm64");
  });
});

describe("cdnUrl", () => {
  it("generates correct CDN URL", () => {
    expect(cdnUrl("0.1.0-alpha.1", "supatype-engine-0.1.0-alpha.1-linux-x64"))
      .toBe("https://releases.supatype.io/engine/v0.1.0-alpha.1/supatype-engine-0.1.0-alpha.1-linux-x64");
  });
});

describe("githubFallbackUrl", () => {
  it("generates correct GitHub fallback URL", () => {
    expect(githubFallbackUrl("0.1.0-alpha.1", "supatype-engine-0.1.0-alpha.1-linux-x64"))
      .toBe("https://github.com/supatype/engine-releases/releases/download/v0.1.0-alpha.1/supatype-engine-0.1.0-alpha.1-linux-x64");
  });
});

describe("detectPlatform", () => {
  it("returns a valid platform for the current system", () => {
    const platform = detectPlatform();
    expect(["linux", "darwin", "win"]).toContain(platform.os);
    expect(["x64", "arm64"]).toContain(platform.arch);
    if (platform.os === "win") {
      expect(platform.ext).toBe(".exe");
    } else {
      expect(platform.ext).toBe("");
    }
  });
});
