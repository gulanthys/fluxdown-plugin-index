// Registry PR check: dry-run Stage for every added / re-pointed registry entry.
//   node scripts/check-registry.mjs --head <PR registry.json> [--root <trusted base checkout>]
//                                   [--output <markdown file>] [--comment <PR number>]
// Runs from the trusted base checkout; the PR's registry.json is read as data only.
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { loadCatalog, validateRegistry } from "./index-lib.mjs";
import { mirrorBytes } from "./check-mirrors.mjs";
import { stagePlugin, publishedVersions, githubClient } from "./stage-lib.mjs";
import { vendoredValidatorVersion } from "./validator-lib.mjs";

const MARKER = "<!-- registry-check -->";
const code = (value) => `\`${value}\``;

/** Returns `{ ok, markdown }`; network-free when `github` / `download` are fakes. */
export async function checkRegistry({ catalog, head, github, download }) {
  const lines = [MARKER, "## 登记检查 / Registry check", ""];
  const errors = validateRegistry(head);
  if (errors.length) {
    lines.push("❌ registry.json 格式错误 / invalid registry.json:", "", ...errors.map((e) => `- ${e}`));
    return { ok: false, markdown: lines.join("\n") };
  }
  const base = new Map(catalog.registry.plugins.map((plugin) => [plugin.id, plugin]));
  const headIds = new Set(head.plugins.map((plugin) => plugin.id));
  const removed = [...base.keys()].filter((id) => !headIds.has(id));
  const formerKey = (plugin) => JSON.stringify(plugin?.formerRepos ?? []);
  const changed = head.plugins.filter((plugin) => base.get(plugin.id)?.repo !== plugin.repo
    || formerKey(base.get(plugin.id)) !== formerKey(plugin));
  const view = { ...catalog, registry: head };
  let ok = true;

  for (const plugin of changed) {
    lines.push(`### ${code(plugin.id)} ← [${plugin.repo}](https://github.com/${plugin.repo})`, "");
    const previous = base.get(plugin.id);
    const addedFormer = (plugin.formerRepos ?? []).filter((repo) => !(previous?.formerRepos ?? []).includes(repo));
    if (addedFormer.length) {
      lines.push(`⚠️ 新增 formerRepos ${addedFormer.map(code).join(", ")}：这些仓库的 Release 附件将被视为本插件已发布版本的合法镜像，请审核者确认它们是同一仓库改名前的名称。`,
        "New formerRepos: their Release assets become valid mirrors of this plugin's published versions; reviewers must confirm they are pre-rename names of the same repository.", "");
    }
    // Same-owner rename only; an owner change is still a maintainer change.
    const renamed = previous && (plugin.formerRepos ?? []).includes(previous.repo)
      && previous.repo.split("/")[0].toLowerCase() === plugin.repo.split("/")[0].toLowerCase();
    if (previous && previous.repo !== plugin.repo && !renamed) {
      lines.push(`⚠️ 维护者变更 ${code(previous.repo)} → ${code(plugin.repo)}：需原维护者在本 PR 中确认。`,
        `Maintainer change: the previous maintainer must confirm in this PR.`, "");
    }
    if (renamed) {
      lines.push(`ℹ️ 仓库改名 ${code(previous.repo)} → ${code(plugin.repo)}（旧名记入 formerRepos）。`,
        "Repository renamed (old name kept in formerRepos).", "");
    }
    const owner = plugin.repo.split("/")[0].toLowerCase();
    const authors = [...new Set(publishedVersions(catalog, plugin.id).map(([, e]) => e.author).filter(Boolean))];
    if (!previous && authors.some((author) => author.toLowerCase() !== owner)) {
      lines.push(`⚠️ 该 identity 已有其他作者发布的历史版本（${authors.map(code).join(", ")}），请审核者确认归属。`,
        "This identity already has versions published by another author; reviewers must confirm ownership.", "");
    }
    try {
      const result = await stagePlugin({ plugin, catalog: view, github, download, apply: false });
      const note = { published: "将作为新版本收录 / will be published", mirrored: "字节已收录，追加镜像 / already published, adds mirror",
        skipped: "已收录 / already staged" }[result.status];
      lines.push(`✅ ${result.review ? `${code(result.review.tag)} · ${code(result.review.asset)} · ` : ""}v${result.version}：${note}`);
      if (result.review) {
        lines.push("", `- 权限 / permissions: ${result.review.permissions.map(code).join(", ") || "无 / none"}`,
          `- 风险等级 / risk level: ${code(result.review.risk)}`,
          `- 网络主机 / network hosts: ${result.review.networkHosts.map(code).join(", ") || "无 / none"}`,
          `- 处理的下载地址 / handled download URLs: ${result.review.downloadUrls.map(code).join(", ") || "无 / none"}`,
          `- 页面脚本运行站点 / page script sites: ${result.review.pageScriptMatches.map(code).join(", ") || "无 / none"}`,
          `- 准入规则 / admission rules: ${code(vendoredValidatorVersion())}`);
      }
    } catch (err) {
      ok = false;
      lines.push(`❌ ${err.transient ? "GitHub 暂时不可用，稍后重跑 / GitHub temporarily unavailable, re-run later" : "未通过 / failed"}:`,
        "", "```", err.message, "```");
    }
    lines.push("");
  }
  if (removed.length) lines.push(`ℹ️ 移除登记（不再自动收录，已发布版本保留）/ delisted: ${removed.map(code).join(", ")}`, "");
  if (!changed.length && !removed.length) lines.push("ℹ️ 无新增或变更的登记 / no added or re-pointed entries.", "");
  lines.push(ok ? "合并后由 Stage 自动收录，之后作者发布 Release 即自动更新。"
    : "修复作者仓库的 Release 后，在本 PR 推送任意提交或请维护者重跑检查。");
  return { ok, markdown: lines.join("\n") };
}

async function upsertComment(api, repo, pr, body) {
  for (let page = 1; ; page++) {
    const comments = await api("GET", `/repos/${repo}/issues/${pr}/comments?per_page=100&page=${page}`);
    const mine = comments.find((comment) => comment.body?.startsWith(MARKER));
    if (mine) return api("PATCH", `/repos/${repo}/issues/comments/${mine.id}`, { body });
    if (comments.length < 100) break;
  }
  return api("POST", `/repos/${repo}/issues/${pr}/comments`, { body });
}

async function main() {
  let root = fileURLToPath(new URL("..", import.meta.url));
  let headFile;
  let output;
  let pr;
  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--root" && args[i + 1]) root = resolve(args[++i]);
    else if (args[i] === "--head" && args[i + 1]) headFile = resolve(args[++i]);
    else if (args[i] === "--output" && args[i + 1]) output = resolve(args[++i]);
    else if (args[i] === "--comment" && /^\d+$/.test(args[i + 1] || "")) pr = args[++i];
    else throw new Error("用法: node scripts/check-registry.mjs --head <registry.json> [--root <目录>] [--output <文件>] [--comment <PR 号>]");
  }
  if (!headFile) throw new Error("缺少 --head");
  let head;
  try {
    head = JSON.parse(readFileSync(headFile, "utf8"));
  } catch (err) {
    head = { invalid: err.message };
  }
  const github = githubClient(process.env.GITHUB_TOKEN);
  const { ok, markdown } = await checkRegistry({ catalog: loadCatalog(root), head, github, download: mirrorBytes });
  console.log(markdown);
  if (output) writeFileSync(output, markdown + "\n");
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown + "\n");
  if (pr) {
    if (!process.env.GITHUB_REPOSITORY || !process.env.GITHUB_TOKEN) throw new Error("--comment 需要 GITHUB_REPOSITORY 与 GITHUB_TOKEN");
    await upsertComment(github.api, process.env.GITHUB_REPOSITORY, pr, markdown);
  }
  if (!ok) process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err.message);
    process.exitCode = 1;
  });
}
