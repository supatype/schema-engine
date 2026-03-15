/**
 * Platform detection for engine binary downloads.
 *
 * Maps Node.js process.platform and process.arch to the binary naming
 * convention used by the release pipeline:
 *   supatype-engine-{version}-{os}-{arch}{ext}
 */

export interface PlatformInfo {
  /** Platform identifier used in binary names: linux, darwin, win */
  os: string;
  /** Architecture identifier: x64, arm64 */
  arch: string;
  /** File extension: empty string on Unix, .exe on Windows */
  ext: string;
}

const SUPPORTED_PLATFORMS: Record<string, string> = {
  linux: "linux",
  darwin: "darwin",
  win32: "win",
};

const SUPPORTED_ARCHS: Record<string, string> = {
  x64: "x64",
  arm64: "arm64",
};

/**
 * Detect the current platform and architecture.
 * Throws with a clear error message if the platform is unsupported.
 */
export function detectPlatform(): PlatformInfo {
  const os = SUPPORTED_PLATFORMS[process.platform];
  const arch = SUPPORTED_ARCHS[process.arch];

  if (!os || !arch) {
    const supported = Object.keys(SUPPORTED_PLATFORMS)
      .flatMap((p) =>
        Object.keys(SUPPORTED_ARCHS).map(
          (a) => `${SUPPORTED_PLATFORMS[p]}-${SUPPORTED_ARCHS[a]}`
        )
      )
      .join(", ");

    throw new Error(
      `Supatype engine is not available for ${process.platform}-${process.arch}. ` +
        `Supported platforms: ${supported}`
    );
  }

  const ext = process.platform === "win32" ? ".exe" : "";
  return { os, arch, ext };
}

/**
 * Build the binary filename for a given version and platform.
 */
export function binaryName(version: string, platform: PlatformInfo): string {
  return `supatype-engine-${version}-${platform.os}-${platform.arch}${platform.ext}`;
}

/**
 * Build the CDN URL for a given version and filename.
 */
export function cdnUrl(version: string, filename: string): string {
  return `https://releases.supatype.io/engine/v${version}/${filename}`;
}

/**
 * Build the fallback GitHub Releases URL for a given version and filename.
 */
export function githubFallbackUrl(
  version: string,
  filename: string
): string {
  return `https://github.com/supatype/engine-releases/releases/download/v${version}/${filename}`;
}
