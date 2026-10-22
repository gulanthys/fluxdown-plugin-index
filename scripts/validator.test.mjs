import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { gzipSync } from "node:zlib";
import { chooseRelease, extractTarEntry, fetchValidator, validatorVersion, VALIDATOR_PATH } from "./validator-lib.mjs";
import { latestListings, readmit } from "./readmit.mjs";

const banner = (version) => `// fluxdown-plugin-sdk@${version} manifest validator (generated; do not edit)\nexport {};\n`;

/** Minimal ustar writer (what npm pack produces for regular files). */
function tarball(files) {
  const blocks = [];
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.from(content);
    const header = Buffer.alloc(512);
    header.write(name, 0);
    header.write(data.length.toString(8).padStart(11, "0"), 124);
    header.write("0", 156);
    blocks.push(header, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

const integrity = (bytes) => "sha512-" + createHash("sha512").update(bytes).digest("base64");
const packument = {
  "dist-tags": { latest: "0.4.0" },
  versions: Object.fromEntries(["0.3.0", "0.4.0"].map((v) => [v, {
    dist: { tarball: `https://registry.npmjs.org/fluxdown-plugin-sdk/-/fluxdown-plugin-sdk-${v}.tgz`, integrity: "sha512-x" },
  }])),
};

test("the vendored validator is a stamped SDK release", () => {
  assert.match(validatorVersion(readFileSync(new URL(`../${VALIDATOR_PATH}`, import.meta.url), "utf8")) ?? "", /^\d+\.\d+\.\d+$/);
  assert.equal(validatorVersion("export const x = 1;"), null);
});

test("release choice: latest only moves forward, explicit versions may roll back", () => {
  assert.equal(chooseRelease(packument, "latest", "0.4.0"), null);
  assert.equal(chooseRelease(packument, "latest", "0.3.0").version, "0.4.0");
  assert.throws(() => chooseRelease(packument, "latest", "0.5.0"), /显式 --version/);
  assert.equal(chooseRelease(packument, "0.3.0", "0.4.0").version, "0.3.0");
  assert.throws(() => chooseRelease(packument, "9.9.9", "0.4.0"), /不存在/);
});

test("fetched validator is integrity-checked, unpacked and must carry the requested version", async () => {
  const bytes = tarball({ "package/package.json": "{}", "package/dist/manifest.mjs": banner("0.4.0") });
  const release = { version: "0.4.0", tarball: packument.versions["0.4.0"].dist.tarball, integrity: integrity(bytes) };
  assert.equal(await fetchValidator(release, async () => bytes), banner("0.4.0"));
  await assert.rejects(fetchValidator({ ...release, integrity: integrity(Buffer.from("x")) }, async () => bytes), /integrity/);
  await assert.rejects(fetchValidator({ ...release, version: "0.3.0" }, async () => bytes), /版本标记/);
  await assert.rejects(fetchValidator({ ...release, tarball: "https://evil.example/x.tgz" }, async () => bytes), /npm registry/);
  assert.throws(() => extractTarEntry(tarball({ "package/README.md": "" }), "package/dist/manifest.mjs"), /没有/);
});

test("re-admission checks the newest non-yanked listing and separates rejections from download failures", async () => {
  const shard = (pluginId, version, yanked = "none") => ({ pluginId, version, yanked, mirrors: [`https://m.example/${pluginId}/${version}`] });
  const catalog = { shards: new Map([
    ["a1", shard("a@x", "1.0.0")], ["a2", shard("a@x", "1.2.0")], ["a3", shard("a@x", "2.0.0", "malicious")],
    ["b1", shard("b@x", "1.0.0")],
  ]) };
  assert.deepEqual(latestListings(catalog).map((e) => `${e.pluginId}@${e.version}`), ["a@x@1.2.0", "b@x@1.0.0"]);
  const results = await readmit(catalog, async (url) => {
    if (url.includes("b@x")) throw new Error("HTTP 404");
    return Buffer.from("not a zip");
  });
  assert.deepEqual(results.map((r) => [r.pluginId, r.ok]), [["a@x", false], ["b@x", null]]);
});
