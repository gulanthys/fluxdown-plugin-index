// The admission rules are the published fluxdown-plugin-sdk's zero-dependency validator
// (`dist/manifest.mjs`), vendored verbatim. Its first line names the exact SDK release.
// This module must not import the vendored file (or anything that does): it replaces it.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";

const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const isVersion = (value) => typeof value === "string" && SEMVER.test(value);
const compareVersions = (a, b) => {
  const [x, y] = [a, b].map((v) => SEMVER.exec(v).slice(1).map(Number));
  return x[0] - y[0] || x[1] - y[1] || x[2] - y[2];
};

export const SDK_PACKAGE = "fluxdown-plugin-sdk";
export const VALIDATOR_PATH = "vendor/fluxdown-plugin-manifest.mjs";
const TARBALL_ENTRY = "package/dist/manifest.mjs";
const BANNER = /^\/\/ fluxdown-plugin-sdk@(\S+) manifest validator\b/;

/** SDK version stamped on a validator bundle, or null when the banner is missing. */
export function validatorVersion(text) {
  const version = BANNER.exec(text)?.[1];
  return version !== undefined && isVersion(version) ? version : null;
}

/** Version of the validator currently vendored under `root`. */
export function vendoredValidatorVersion(root = new URL("..", import.meta.url).pathname) {
  return validatorVersion(readFileSync(`${root}/${VALIDATOR_PATH}`, "utf8")) ?? "unknown";
}

/** npm `dist.integrity` (`sha512-<base64>`) check. */
export function verifyIntegrity(bytes, integrity) {
  const match = /^sha512-(.+)$/.exec(integrity ?? "");
  if (!match) throw new Error(`不支持的 integrity: ${integrity}`);
  const actual = createHash("sha512").update(bytes).digest("base64");
  if (actual !== match[1]) throw new Error("tarball integrity 不匹配");
}

/** Reads one regular file out of a gzipped ustar archive (npm tarball). */
export function extractTarEntry(gzipped, wanted) {
  const tar = gunzipSync(gzipped);
  for (let offset = 0; offset + 512 <= tar.length;) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const field = (start, length) => header.subarray(start, start + length).toString("utf8").replace(/\0.*$/s, "");
    const prefix = field(345, 155);
    const name = prefix ? `${prefix}/${field(0, 100)}` : field(0, 100);
    const size = Number.parseInt(field(124, 12).trim() || "0", 8);
    const type = field(156, 1);
    const start = offset + 512;
    if (name === wanted && (type === "0" || type === "")) return tar.subarray(start, start + size);
    offset = start + Math.ceil(size / 512) * 512;
  }
  throw new Error(`tarball 中没有 ${wanted}`);
}

/**
 * Picks the release to vendor. `latest` never moves backwards; an explicit version may (rollback).
 * Returns null when `current` is already that release.
 */
export function chooseRelease(packument, requested, current) {
  const version = requested === "latest" ? packument["dist-tags"]?.latest : requested;
  const release = packument.versions?.[version];
  if (!release) throw new Error(`${SDK_PACKAGE}@${version} 不存在`);
  if (current === version) return null;
  if (requested === "latest" && isVersion(current) && compareVersions(version, current) < 0) {
    throw new Error(`npm latest ${version} 低于已同步的 ${current}；回退须显式 --version`);
  }
  return { version, tarball: release.dist.tarball, integrity: release.dist.integrity };
}

/** Downloads, verifies and unpacks the validator of one SDK release. */
export async function fetchValidator(release, fetchBytes) {
  const tarball = new URL(release.tarball);
  if (tarball.protocol !== "https:" || tarball.host !== "registry.npmjs.org") {
    throw new Error(`拒绝非 npm registry 的 tarball 地址 ${release.tarball}`);
  }
  const bytes = await fetchBytes(tarball.href);
  verifyIntegrity(bytes, release.integrity);
  const text = extractTarEntry(bytes, TARBALL_ENTRY).toString("utf8");
  const stamped = validatorVersion(text);
  if (stamped !== release.version) throw new Error(`validator 版本标记 ${stamped} 与 ${release.version} 不符`);
  return text;
}
