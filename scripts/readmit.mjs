// Re-admits the newest listed version of every plugin with the vendored rules. Run after the
// validator changes: a rejection means clients enforcing the same rules can no longer install
// that listing. Published bytes are immutable, so this only reports (the author must release).
//   node scripts/readmit.mjs [--summary <markdown file>]   exit 1 when any listing is rejected
import { appendFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { loadCatalog, safeMirror } from "./index-lib.mjs";
import { mirrorBytes } from "./check-mirrors.mjs";
import { compareVersions, inspectPackage } from "./package-lib.mjs";
import { vendoredValidatorVersion } from "./validator-lib.mjs";

/** Newest non-yanked shard per plugin. */
export function latestListings(catalog) {
  const latest = new Map();
  for (const entry of catalog.shards.values()) {
    if (entry.yanked !== "none") continue;
    const seen = latest.get(entry.pluginId);
    if (!seen || compareVersions(entry.version, seen.version) > 0) latest.set(entry.pluginId, entry);
  }
  return [...latest.values()].sort((a, b) => a.pluginId.localeCompare(b.pluginId, "en"));
}

/** `{ pluginId, version, ok, error? }` per listing; a download failure is reported, not treated as a rejection. */
export async function readmit(catalog, download = mirrorBytes) {
  const results = [];
  for (const entry of latestListings(catalog)) {
    let bytes;
    let fetchError;
    for (const mirror of entry.mirrors) {
      try {
        bytes = await download(mirror);
        break;
      } catch (err) {
        fetchError = `${safeMirror(mirror)}: ${err.message}`;
      }
    }
    if (bytes === undefined) {
      results.push({ pluginId: entry.pluginId, version: entry.version, ok: null, error: fetchError ?? "没有镜像" });
      continue;
    }
    try {
      inspectPackage(bytes);
      results.push({ pluginId: entry.pluginId, version: entry.version, ok: true });
    } catch (err) {
      results.push({ pluginId: entry.pluginId, version: entry.version, ok: false, error: err.message });
    }
  }
  return results;
}

async function main() {
  const args = process.argv.slice(2);
  const summaryIndex = args.indexOf("--summary");
  const root = fileURLToPath(new URL("..", import.meta.url));
  const results = await readmit(loadCatalog(root));
  const mark = { true: "✅", false: "❌", null: "⚠️ 无法下载 / unreachable" };
  const lines = [`### 现有上架版本复核 / re-admission (rules ${vendoredValidatorVersion(root)})`, "",
    ...results.map((r) => `- ${mark[r.ok]} \`${r.pluginId}@${r.version}\`${r.error ? `：${r.error}` : ""}`), ""];
  console.log(lines.join("\n"));
  if (summaryIndex >= 0) appendFileSync(args[summaryIndex + 1], lines.join("\n") + "\n");
  if (results.some((r) => r.ok === false)) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
