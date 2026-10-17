// Offline admission: local bytes/catalog plus an optional exact publication baseline.
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { loadCatalog, loadBaseline, validateCatalog, validateHistory } from "./index-lib.mjs";

try {
  let root = fileURLToPath(new URL("..", import.meta.url));
  let base;
  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--base" && args[i + 1]) base = resolve(args[++i]);
    else if (args[i] === "--root" && args[i + 1]) root = resolve(args[++i]);
    else throw new Error("用法: node scripts/validate.mjs [--base <完整基线 checkout>] [--root <目录>]");
  }
  const catalog = loadCatalog(root);
  const errors = validateCatalog(catalog);
  if (base) errors.push(...validateHistory(catalog, loadBaseline(base, catalog)));
  if (errors.length) throw new Error("索引校验失败：\n  - " + errors.join("\n  - "));
  console.log(`离线索引校验通过：${catalog.shards.size} 个条目，sequence 高水位 ${catalog.state.sequence}${base ? "，历史 append-only 通过" : ""}。`);
} catch (err) {
  console.error(err.message);
  process.exitCode = 1;
}
