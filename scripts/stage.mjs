// Stage CLI.
//   node scripts/stage.mjs [--root <dir>] [--results <file>]   stage every registered plugin, write shards + index
//   node scripts/stage.mjs --sync-issues <results file>         upsert/close stage-fail issues (after publishing)
// GITHUB_TOKEN authenticates API calls (unauthenticated works locally at 60 requests/hour).
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { loadCatalog, validateCatalog } from "./index-lib.mjs";
import { mirrorBytes } from "./check-mirrors.mjs";
import { stageAll, writeCatalog, githubClient, syncStageIssues } from "./stage-lib.mjs";

const json = (value) => JSON.stringify(value, null, 2) + "\n";

async function stage(root, resultsFile) {
  const catalog = loadCatalog(root);
  const before = validateCatalog(catalog);
  if (before.length) throw new Error("基线索引无效，拒绝 Stage：\n  - " + before.join("\n  - "));
  const github = githubClient(process.env.GITHUB_TOKEN);
  const results = await stageAll({ catalog, github, download: mirrorBytes, log: console.log });
  const changed = results.filter((r) => r.status === "published" || r.status === "mirrored");
  if (changed.length) {
    const pending = new Map();
    writeCatalog(catalog, (path, value) => pending.set(path, value));
    const errors = validateCatalog(catalog);
    if (errors.length) throw new Error("Stage 结果未通过离线校验，未写入：\n  - " + errors.join("\n  - "));
    for (const { path } of changed) pending.set(path, catalog.shards.get(path));
    for (const [path, value] of pending) {
      mkdirSync(dirname(join(root, path)), { recursive: true });
      writeFileSync(join(root, path), json(value));
    }
  }
  const summary = changed.map((r) => `${r.plugin.id} ${r.version}${r.status === "mirrored" ? " (+mirror)" : ""}`);
  const failed = results.filter((r) => r.status === "failed" || r.status === "transient");
  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `message=chore(stage): ${summary.join(", ") || "no changes"}\n`);
  }
  if (process.env.GITHUB_STEP_SUMMARY) {
    const rows = results.map((r) => `| \`${r.plugin.id}\` | ${r.plugin.repo} | ${r.status} | ${r.version ?? ""} | ${(r.error ?? "").replaceAll("|", "\\|").replaceAll("\n", " ")} |`);
    appendFileSync(process.env.GITHUB_STEP_SUMMARY,
      ["| 插件 | 仓库 | 状态 | 版本 | 错误 |", "|---|---|---|---|---|", ...rows, ""].join("\n"));
  }
  if (resultsFile) {
    writeFileSync(resultsFile, json(results.map(({ plugin, status, version, error }) => ({ plugin, status, version, error }))));
  }
  console.log(`Stage 完成：${changed.length} 项更新，${failed.length} 项失败/暂缓，共 ${results.length} 个登记插件。`);
}

async function sync(root, resultsFile) {
  const repo = process.env.GITHUB_REPOSITORY;
  if (!repo || !process.env.GITHUB_TOKEN) throw new Error("--sync-issues 需要 GITHUB_REPOSITORY 与 GITHUB_TOKEN");
  const results = JSON.parse(readFileSync(resultsFile, "utf8"));
  const { api } = githubClient(process.env.GITHUB_TOKEN);
  await syncStageIssues({ api, repo, results, registry: loadCatalog(root).registry });
  console.log("stage-fail issue 已同步。");
}

try {
  let root = fileURLToPath(new URL("..", import.meta.url));
  let resultsFile;
  let syncFile;
  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--root" && args[i + 1]) root = resolve(args[++i]);
    else if (args[i] === "--results" && args[i + 1]) resultsFile = resolve(args[++i]);
    else if (args[i] === "--sync-issues" && args[i + 1]) syncFile = resolve(args[++i]);
    else throw new Error("用法: node scripts/stage.mjs [--root <目录>] [--results <文件>] | --sync-issues <结果文件>");
  }
  if (syncFile) await sync(root, syncFile);
  else await stage(root, resultsFile);
} catch (err) {
  console.error(err.message);
  process.exitCode = 1;
}
