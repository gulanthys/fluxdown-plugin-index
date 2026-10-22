// Zero-dependency .fxplug reader + admission. Every rule lives in the vendored SDK validator
// (vendor/fluxdown-plugin-manifest.mjs, synced from the published fluxdown-plugin-sdk by
// scripts/sync-validator.mjs), which mirrors FluxDown native/engine/src/plugin/{install,manifest}.rs:
// a package admitted here installs on the client. This file only unpacks the zip safely.
import { inflateRawSync } from "node:zlib";
import {
  PACKAGE_MAX_ENTRIES,
  PACKAGE_MAX_UNCOMPRESSED_BYTES,
  isSafeRelativePath,
  validatePackage,
} from "../vendor/fluxdown-plugin-manifest.mjs";

const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

const CRC_TABLE = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

export function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

/** Three-part semver comparison; both sides must already match SEMVER. */
export function compareVersions(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  return 0;
}

export const isVersion = (value) => typeof value === "string" && SEMVER.test(value);


function findEndOfCentralDirectory(bytes) {
  const lowest = Math.max(0, bytes.length - 0xffff - 22);
  for (let i = bytes.length - 22; i >= lowest; i--) {
    if (bytes.readUInt32LE(i) === 0x06054b50) return i;
  }
  throw new Error("不是有效 zip：缺少中央目录结尾");
}

/**
 * Reads every file of a .fxplug into memory with the client's install limits.
 * Returns `Map<relativePath, Buffer>` rooted at the directory holding manifest.json
 * (a single wrapper directory is stripped, as the client does).
 */
export function readPackage(bytes) {
  const eocd = findEndOfCentralDirectory(bytes);
  const count = bytes.readUInt16LE(eocd + 10);
  const directorySize = bytes.readUInt32LE(eocd + 12);
  const directoryOffset = bytes.readUInt32LE(eocd + 16);
  if (count === 0xffff || directoryOffset === 0xffffffff) throw new Error("不支持 ZIP64 插件包");
  if (count > PACKAGE_MAX_ENTRIES) throw new Error(`zip 条目数 ${count} 超过上限 ${PACKAGE_MAX_ENTRIES}`);
  if (directoryOffset + directorySize > eocd) throw new Error("zip 中央目录越界");

  const raw = new Map();
  let total = 0;
  let cursor = directoryOffset;
  for (let i = 0; i < count; i++) {
    if (bytes.readUInt32LE(cursor) !== 0x02014b50) throw new Error("zip 中央目录条目损坏");
    const flags = bytes.readUInt16LE(cursor + 8);
    const method = bytes.readUInt16LE(cursor + 10);
    const crc = bytes.readUInt32LE(cursor + 16);
    const compressedSize = bytes.readUInt32LE(cursor + 20);
    const size = bytes.readUInt32LE(cursor + 24);
    const nameLength = bytes.readUInt16LE(cursor + 28);
    const extraLength = bytes.readUInt16LE(cursor + 30);
    const commentLength = bytes.readUInt16LE(cursor + 32);
    const mode = bytes.readUInt32LE(cursor + 38) >>> 16;
    const localOffset = bytes.readUInt32LE(cursor + 42);
    const name = bytes.subarray(cursor + 46, cursor + 46 + nameLength).toString("utf8");
    cursor += 46 + nameLength + extraLength + commentLength;

    if (flags & 1) throw new Error(`${name}: 不允许加密条目`);
    if ((mode & 0o170000) === 0o120000) throw new Error(`${name}: 不允许符号链接`);
    if (name.includes("\\")) throw new Error(`${name}: zip 路径分隔符必须为 /`);
    const isDirectory = name.endsWith("/");
    const path = isDirectory ? name.slice(0, -1) : name;
    if (!isSafeRelativePath(path)) throw new Error(`${name}: zip 含非法路径（zip-slip）`);
    if (isDirectory) continue;
    if (raw.has(path)) throw new Error(`${name}: zip 条目重复`);

    if (bytes.readUInt32LE(localOffset) !== 0x04034b50) throw new Error(`${name}: 本地文件头损坏`);
    const dataStart = localOffset + 30 + bytes.readUInt16LE(localOffset + 26) + bytes.readUInt16LE(localOffset + 28);
    const data = bytes.subarray(dataStart, dataStart + compressedSize);
    if (data.length !== compressedSize) throw new Error(`${name}: 条目数据越界`);
    const remaining = PACKAGE_MAX_UNCOMPRESSED_BYTES - total;
    let content;
    if (method === 0) content = Buffer.from(data);
    else if (method === 8) {
      try {
        content = inflateRawSync(data, { maxOutputLength: remaining + 1 });
      } catch (err) {
        if (err instanceof RangeError || err.code === "ERR_BUFFER_TOO_LARGE") {
          throw new Error(`解压总量超过 ${PACKAGE_MAX_UNCOMPRESSED_BYTES} 字节上限（疑压缩炸弹）`);
        }
        throw new Error(`${name}: 解压失败: ${err.message}`);
      }
    } else throw new Error(`${name}: 不支持的压缩方式 ${method}（仅 stored/deflate）`);
    total += content.length;
    if (total > PACKAGE_MAX_UNCOMPRESSED_BYTES) throw new Error(`解压总量超过 ${PACKAGE_MAX_UNCOMPRESSED_BYTES} 字节上限（疑压缩炸弹）`);
    if (content.length !== size || crc32(content) !== crc) throw new Error(`${name}: CRC/长度校验失败`);
    raw.set(path, content);
  }

  if (raw.has("manifest.json")) return raw;
  const tops = new Set([...raw.keys()].map((path) => path.split("/")[0]));
  const [top] = tops;
  if (tops.size === 1 && raw.has(`${top}/manifest.json`)) {
    return new Map([...raw].map(([path, content]) => [path.slice(top.length + 1), content]));
  }
  throw new Error("zip 内未找到根 manifest.json");
}

/** Parses + admits a .fxplug with the SDK's `validatePackage`; throws with every admission error joined. */
export function inspectPackage(bytes) {
  const files = readPackage(bytes);
  let manifest;
  try {
    manifest = JSON.parse(files.get("manifest.json").toString("utf8"));
  } catch (err) {
    throw new Error(`manifest.json 解析失败: ${err.message}`);
  }
  const { errors } = validatePackage(manifest, files);
  if (errors.length) throw new Error(errors.join("；"));
  return { manifest, files };
}
