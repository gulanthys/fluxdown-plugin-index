// Generate only after validation; never overwrite a regressed or conflicting catalog.
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, resolve } from "node:path";
import { loadCatalog, validateCatalog, generatedDocuments } from "./index-lib.mjs";

try {
  const args = process.argv.slice(2);
  if (args.length && (args.length !== 2 || args[0] !== "--root")) {
    throw new Error("用法: node scripts/generate.mjs [--root <目录>]");
  }
  const root = args.length ? resolve(args[1]) : fileURLToPath(new URL("..", import.meta.url));
  const catalog = loadCatalog(root);
  const errors = validateCatalog(catalog, { checkIndex: false });
  if (errors.length) throw new Error("拒绝生成索引：\n  - " + errors.join("\n  - "));
  const { state, index } = generatedDocuments(catalog);
  writeFileSync(join(root, "STATE"), JSON.stringify(state, null, 2) + "\n");
  writeFileSync(join(root, "index.json"), JSON.stringify(index, null, 2) + "\n");
  console.log(`生成 index.json：${index.entries.length} 条目，sequence=${index.sequence}，indexId=${index.indexId}`);
} catch (err) {
  console.error(err.message);
  process.exitCode = 1;
}
