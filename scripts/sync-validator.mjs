// Vendors the admission rules from a published fluxdown-plugin-sdk release.
//   node scripts/sync-validator.mjs [--version <x.y.z|latest>]   # default latest; npm integrity verified
//   node scripts/sync-validator.mjs --verify   # vendored file must equal its stamped npm release
//   node scripts/sync-validator.mjs --from <path/to/dist/manifest.mjs>   # local SDK build, testing only
// Writes `changed=true|false`, `from`, `to` to $GITHUB_OUTPUT when set.
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, resolve } from "node:path";
import { SDK_PACKAGE, VALIDATOR_PATH, chooseRelease, fetchValidator, validatorVersion } from "./validator-lib.mjs";

async function fetchBytes(url) {
  const response = await fetch(url, { redirect: "error" });
  if (!response.ok) throw new Error(`GET ${url} 返回 HTTP ${response.status}`);
  return Buffer.from(await response.arrayBuffer());
}

async function main() {
  const args = process.argv.slice(2);
  const option = (name) => {
    const index = args.indexOf(name);
    return index < 0 ? undefined : args[index + 1];
  };
  const root = fileURLToPath(new URL("..", import.meta.url));
  const target = join(root, VALIDATOR_PATH);
  const vendored = readFileSync(target, "utf8");
  const current = validatorVersion(vendored);
  const loadPackument = async () =>
    JSON.parse((await fetchBytes(`https://registry.npmjs.org/${SDK_PACKAGE}`)).toString("utf8"));

  if (args.includes("--verify")) {
    if (current === null) throw new Error(`${VALIDATOR_PATH} 缺少 SDK 版本标记`);
    const release = chooseRelease(await loadPackument(), current, null);
    if ((await fetchValidator(release, fetchBytes)) !== vendored) {
      throw new Error(`${VALIDATOR_PATH} 与 npm ${SDK_PACKAGE}@${current} 不一致：禁止手改，用 sync-validator 同步已发布版本`);
    }
    console.log(`${VALIDATOR_PATH} = ${SDK_PACKAGE}@${current}`);
    return;
  }

  let text;
  const from = option("--from");
  if (from !== undefined) {
    text = readFileSync(resolve(from), "utf8");
    if (validatorVersion(text) === null) throw new Error(`${from} 不是带版本标记的 SDK validator 构建产物`);
  } else {
    const requested = option("--version") ?? "latest";
    let packument = await loadPackument();
    // Dispatched right after `npm publish`: give the registry a few minutes to list the version.
    for (let attempt = 0; requested !== "latest" && !packument.versions?.[requested] && attempt < 10; attempt++) {
      await new Promise((done) => setTimeout(done, 30_000));
      packument = await loadPackument();
    }
    const release = chooseRelease(packument, requested, current);
    if (release !== null) text = await fetchValidator(release, fetchBytes);
  }

  const changed = text !== undefined && text !== vendored;
  if (changed) writeFileSync(target, text);
  const to = changed ? validatorVersion(text) : current;
  console.log(changed ? `synced ${VALIDATOR_PATH}: ${current} -> ${to}` : `${VALIDATOR_PATH} already at ${current}`);
  if (process.env.GITHUB_OUTPUT) {
    appendFileSync(process.env.GITHUB_OUTPUT, `changed=${changed}\nfrom=${current}\nto=${to}\n`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err.message);
    process.exit(1);
  });
}
