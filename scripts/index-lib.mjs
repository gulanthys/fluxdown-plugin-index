import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { join, basename } from "node:path";
import { isDeepStrictEqual } from "node:util";

export const MAX_PACKAGE_BYTES = 10 * 1024 * 1024;
const hash = (bytes) => "sha256:" + createHash("sha256").update(bytes).digest("hex");
const positiveSequence = (n) => Number.isSafeInteger(n) && n > 0;
const parse = (bytes, path) => {
  try {
    return JSON.parse(bytes.toString());
  } catch (err) {
    throw new Error(`${path}: JSON 解析失败: ${err.message}`);
  }
};

function files(root, directory) {
  const dir = join(root, directory);
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name, "en")).flatMap((item) => {
    const path = `${directory}/${item.name}`;
    if (item.isDirectory()) return files(root, path);
    if (!item.isFile()) throw new Error(`${path}: 只允许普通文件/目录`);
    return [path];
  });
}

export function loadCatalog(root) {
  const shards = new Map(files(root, "plugins").filter((p) => p.endsWith(".json"))
    .map((path) => [path, parse(readFileSync(join(root, path)), path)]));
  const payloads = new Map(files(root, "dist").map((path) => {
    const size = statSync(join(root, path)).size;
    if (size > MAX_PACKAGE_BYTES) throw new Error(`${path}: 插件包超过 10 MiB 上限`);
    return [path, hash(readFileSync(join(root, path)))];
  }));
  const state = parse(readFileSync(join(root, "STATE")), "STATE");
  const index = existsSync(join(root, "index.json")) ? parse(readFileSync(join(root, "index.json")), "index.json") : null;
  // Snapshots published before the author registry existed have no registry.json: nothing is registered there.
  const registry = existsSync(join(root, REGISTRY_PATH))
    ? parse(readFileSync(join(root, REGISTRY_PATH)), REGISTRY_PATH) : { plugins: [] };
  return { shards, payloads, state, index, registry };
}

export const REGISTRY_PATH = "registry.json";
const REPO = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/;
const TAG = /^[a-z0-9][a-z0-9-]{0,31}$/;

/** Author registry: one plugin identity per GitHub repository, both unique. */
export function validateRegistry(registry) {
  const errors = [];
  if (!registry || typeof registry !== "object" || Array.isArray(registry) || !Array.isArray(registry.plugins)) {
    return [`${REGISTRY_PATH}: 须为 { "plugins": [...] }`];
  }
  for (const key of Object.keys(registry)) if (key !== "plugins") errors.push(`${REGISTRY_PATH}: 未知字段 ${key}`);
  const ids = new Set();
  const repos = new Set();
  for (const [i, plugin] of registry.plugins.entries()) {
    const where = `${REGISTRY_PATH}: plugins[${i}]`;
    if (!plugin || typeof plugin !== "object" || Array.isArray(plugin)) {
      errors.push(`${where} 须为对象`);
      continue;
    }
    for (const key of Object.keys(plugin)) if (!["id", "repo", "tags"].includes(key)) errors.push(`${where}: 未知字段 ${key}`);
    if (!/^[a-z0-9_-]+@[a-z0-9_-]+$/.test(plugin.id || "")) errors.push(`${where}: id 须匹配 author@name`);
    if (!REPO.test(plugin.repo || "")) errors.push(`${where}: repo 须为 GitHub owner/repo`);
    if (ids.has(plugin.id)) errors.push(`${where}: id ${plugin.id} 重复登记`);
    const repoKey = String(plugin.repo).toLowerCase();
    if (repos.has(repoKey)) errors.push(`${where}: repo ${plugin.repo} 已登记其他插件（一个仓库只发布一个插件）`);
    ids.add(plugin.id);
    repos.add(repoKey);
    if (plugin.tags !== undefined && (!Array.isArray(plugin.tags) || plugin.tags.length > 10
      || !plugin.tags.every((tag) => TAG.test(tag)) || new Set(plugin.tags).size !== plugin.tags.length)) {
      errors.push(`${where}: tags 须为 ≤10 个不重复的小写短标签`);
    }
  }
  return errors;
}

export const registeredRepo = (registry, pluginId) => (Array.isArray(registry?.plugins)
  ? registry.plugins.find((plugin) => plugin?.id === pluginId)?.repo : undefined);

/** `https://github.com/<repo>/releases/download/<tag>/<asset>.fxplug` of the registered repository. */
export function isRegisteredRelease(registry, pluginId, value) {
  const repo = registeredRepo(registry, pluginId);
  if (!repo) return false;
  try {
    const url = new URL(value);
    const [owner, name, releases, download, tag, asset, ...rest] = url.pathname.slice(1).split("/");
    return url.protocol === "https:" && url.host === "github.com" && !url.search && !url.hash && !rest.length
      && `${owner}/${name}`.toLowerCase() === repo.toLowerCase() && releases === "releases" && download === "download"
      && !!tag && /^[^/]+\.fxplug$/.test(decodeURIComponent(asset || ""));
  } catch {
    return false;
  }
}

export function mirrorURL(value) {
  if (typeof value !== "string") throw new Error("mirror URL 须为字符串");
  const url = new URL(value);
  if (url.protocol !== "https:") throw new Error("mirror 必须 HTTPS（包括重定向）");
  const host = url.hostname.toLowerCase();
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(":") || host === "localhost"
    || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || !host.includes(".")) {
    throw new Error("mirror 禁止 IP/内网/元数据主机");
  }
  if (url.username || url.password) throw new Error("mirror 禁止 URL 凭据");
  if (host === "raw.githubusercontent.com" && !/^\/[^/]+\/[^/]+\/[0-9a-f]{40}\//i.test(url.pathname)) {
    throw new Error("GitHub Raw mirror 必须固定到完整 commit SHA");
  }
  if (host === "cdn.jsdelivr.net" && url.pathname.startsWith("/gh/")
    && !/^\/gh\/[^/]+\/[^/@]+@[0-9a-f]{40}\//i.test(url.pathname)) {
    throw new Error("jsDelivr Git mirror 必须固定到完整 commit SHA");
  }
  return url;
}

export function safeMirror(value) {
  try {
    const url = new URL(value);
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    return "<invalid mirror>";
  }
}

export function generatedDocuments(catalog) {
  const entries = [...catalog.shards.values()].sort((a, b) => a.sequence - b.sequence);
  const sequence = entries.reduce((max, entry) => Math.max(max, entry.sequence), 0);
  const updated = entries.map((e) => e.publishTime).filter((t) => typeof t === "string" && t).sort().pop()
    || "1970-01-01T00:00:00.000Z";
  return {
    state: { ...catalog.state, sequence, updated },
    index: { indexId: catalog.state.indexId, sequence, updated, entries },
  };
}

export function validateCatalog(catalog, { checkIndex = true } = {}) {
  const errors = validateRegistry(catalog.registry);
  const seen = new Set();
  for (const [path, entry] of catalog.shards) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      errors.push(`${path}: 分片须为对象`);
      continue;
    }
    if (!/^[a-z0-9_-]+@[a-z0-9_-]+$/.test(entry.pluginId || "")) errors.push(`${path}: pluginId 非法`);
    if (!/^\d+\.\d+\.\d+$/.test(entry.version || "")) errors.push(`${path}: version 非 semver`);
    if (path !== `plugins/${entry.pluginId}/${entry.version}.json`) errors.push(`${path}: 路径与 identity/version 不符`);
    if (!/^sha256:[0-9a-f]{64}$/.test(entry.contentHash || "")) errors.push(`${path}: contentHash 格式非法`);
    if (!positiveSequence(entry.sequence)) errors.push(`${path}: sequence 须为正安全整数`);
    if (seen.has(entry.sequence)) errors.push(`${path}: sequence ${entry.sequence} 重复`);
    seen.add(entry.sequence);
    if (!Array.isArray(entry.mirrors) || !entry.mirrors.length) {
      errors.push(`${path}: mirrors 不可为空`);
      continue;
    }
    for (const value of entry.mirrors) {
      try {
        mirrorURL(value);
      } catch (err) {
        errors.push(`${path}: ${safeMirror(value)}: ${err.message}`);
      }
    }
    // Registered authors host bytes on their own GitHub Release (Stage ingested and hashed them;
    // check-mirrors re-GETs online). Everything else keeps the local dist/ payload rule.
    if (isRegisteredRelease(catalog.registry, entry.pluginId, entry.mirrors[0])) continue;
    try {
      const name = decodeURIComponent(basename(new URL(entry.mirrors[0]).pathname));
      if (!/^[a-zA-Z0-9._-]+\.fxplug$/.test(name)) throw new Error("首镜像文件名不是安全的 .fxplug 名称");
      const actual = catalog.payloads.get(`dist/${name}`);
      if (!actual) throw new Error(`dist/${name} 不存在（且首镜像不是已登记仓库的 Release 附件）`);
      if (actual !== entry.contentHash) throw new Error(`contentHash 不符（期望 ${entry.contentHash}，实际 ${actual}）`);
    } catch (err) {
      errors.push(`${path}: ${err.message}`);
    }
  }
  if (!catalog.state || typeof catalog.state !== "object" || Array.isArray(catalog.state)) {
    errors.push("STATE 须为对象");
    return errors;
  }
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(catalog.state.indexId || "")) {
    errors.push("STATE.indexId 须为 UUID");
  }
  if (!positiveSequence(catalog.state.sequence)) errors.push("STATE.sequence 须为正安全整数");
  if (errors.length) return errors;
  const generated = generatedDocuments(catalog);
  if (catalog.state.sequence > generated.state.sequence) errors.push("分片高水位低于 STATE，禁止回退");
  if (catalog.index && (!positiveSequence(catalog.index.sequence) || catalog.index.sequence > generated.state.sequence)) {
    errors.push("index.json 高水位非法或高于分片，禁止回退");
  }
  if (checkIndex && !isDeepStrictEqual(catalog.state, generated.state)) errors.push("STATE 与分片高水位/updated 不一致");
  if (checkIndex && !isDeepStrictEqual(catalog.index, generated.index)) errors.push("index.json 与分片 flatten 内容不一致");
  return errors;
}

// A restored historical version may retain its old sequence only when the exact
// published identity/hash/sequence is recoverable from the full base history.
// Do not silently delete, rewrite, or resurrect any other historical version.
export function loadBaseline(root, catalog) {
  const baseline = loadCatalog(root);
  baseline.highWater = Math.max(baseline.state.sequence || 0, baseline.index?.sequence || 0,
    ...[...baseline.shards.values()].map((e) => e.sequence || 0));
  const restored = new Set([...catalog.shards.keys()].filter((path) => !baseline.shards.has(path)));
  if (!existsSync(join(root, ".git"))) return baseline; // Deterministic directory fixtures / exported snapshots.
  const git = (...args) => execFileSync("git", ["-C", root, ...args], { maxBuffer: 50 * 1024 * 1024 });
  if (git("rev-parse", "--is-shallow-repository").toString().trim() !== "false") {
    throw new Error("历史基线必须为完整 Git checkout（fetch-depth: 0），不能跳过已删除版本");
  }
  const commits = git("log", "--topo-order", "--format=%H", "--", "plugins", "STATE", "index.json").toString().trim().split("\n").filter(Boolean);
  for (const commit of commits) {
    const tree = git("ls-tree", "-rz", commit, "--", "plugins", "STATE", "index.json").toString().split("\0").filter(Boolean);
    for (const row of tree) {
      const separator = row.indexOf("\t");
      const path = row.slice(separator + 1);
      if (!row.slice(0, separator).includes(" blob ")) throw new Error(`${commit}: ${path}: 非普通 Git blob`);
      if (path === "STATE" || path === "index.json") {
        const document = parse(git("show", `${commit}:${path}`), `${commit}:${path}`);
        baseline.highWater = Math.max(baseline.highWater, document.sequence || 0);
      } else if (restored.has(path) && !baseline.shards.has(path)) {
        const entry = parse(git("show", `${commit}:${path}`), `${commit}:${path}`);
        baseline.shards.set(path, entry);
        baseline.highWater = Math.max(baseline.highWater, entry.sequence || 0);
      }
    }
  }
  return baseline;
}

export function validateHistory(catalog, baseline) {
  const errors = [];
  const highWater = baseline.highWater ?? Math.max(baseline.state.sequence || 0, baseline.index?.sequence || 0,
    ...[...baseline.shards.values()].map((e) => e.sequence || 0));
  if (catalog.state.indexId !== baseline.state.indexId) errors.push("STATE.indexId 不得改写已发布索引身份");
  if (catalog.state.sequence < highWater || !catalog.index || catalog.index.sequence < highWater) {
    errors.push(`STATE/index.json 高水位低于历史基线 ${highWater}`);
  }
  const groups = new Map();
  for (const [path, entry] of baseline.shards) {
    const paths = groups.get(entry.sequence) || [];
    paths.push(path);
    groups.set(entry.sequence, paths);
  }
  for (const [path, before] of baseline.shards) {
    const after = catalog.shards.get(path);
    if (!after) {
      errors.push(`${path}: 已发布分片不可删除（含历史误删版本）`);
      continue;
    }
    for (const key of ["pluginId", "version", "contentHash"]) {
      if (after[key] !== before[key]) errors.push(`${path}: 已发布 ${key} 不可改写`);
    }
    if (after.sequence !== before.sequence) {
      const conflicts = groups.get(before.sequence);
      const retained = conflicts.some((other) => other !== path && catalog.shards.get(other)?.sequence === before.sequence);
      if (conflicts.length < 2 || !retained || !positiveSequence(after.sequence) || after.sequence <= highWater) {
        errors.push(`${path}: 历史 sequence 仅可修复已有冲突，且新号须高于 ${highWater}、另一项保留旧号`);
      }
    }
  }
  for (const [path, entry] of catalog.shards) {
    if (!baseline.shards.has(path) && entry.sequence <= highWater) errors.push(`${path}: 新增 sequence 须高于历史高水位 ${highWater}`);
  }
  for (const [path, before] of baseline.payloads) {
    const after = catalog.payloads.get(path);
    if (!after) errors.push(`${path}: 已发布包不可删除（含历史误删包）`);
    else if (after !== before) errors.push(`${path}: 已发布 payload 字节不可改写`);
  }
  return errors;
}
