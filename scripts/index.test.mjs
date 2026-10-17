import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { loadCatalog, loadBaseline, validateCatalog, validateHistory, generatedDocuments, mirrorURL, MAX_PACKAGE_BYTES } from "./index-lib.mjs";

const ID = "252c2b9e-c113-42d2-b1b5-3bf8bdb01866";
const SHA = "a".repeat(40);
const digest = (bytes) => "sha256:" + createHash("sha256").update(bytes).digest("hex");
const json = (root, path, value) => {
  mkdirSync(join(root, path, ".."), { recursive: true });
  writeFileSync(join(root, path), JSON.stringify(value, null, 2) + "\n");
};
const pathOf = (entry) => `plugins/${entry.pluginId}/${entry.version}.json`;
const packageOf = (entry) => `dist/${new URL(entry.mirrors[0]).pathname.split("/").pop()}`;
function entry(name, sequence) {
  const bytes = Buffer.from(`published package ${name}`);
  return {
    pluginId: `author@${name}`, version: "1.0.0", sequence, contentHash: digest(bytes),
    mirrors: [`https://raw.githubusercontent.com/example/plugins/${SHA}/dist/${name}-1.0.0.fxplug`],
    publishTime: "2026-09-30T00:00:00.000Z",
  };
}
function snapshot(root, entries) {
  mkdirSync(root, { recursive: true });
  mkdirSync(join(root, "dist"), { recursive: true });
  for (const e of entries) {
    json(root, pathOf(e), e);
    writeFileSync(join(root, packageOf(e)), Buffer.from(`published package ${e.pluginId.split("@")[1]}`));
  }
  json(root, "STATE", { indexId: ID, sequence: Math.max(...entries.map((e) => e.sequence)), updated: "2026-09-30T00:00:00.000Z" });
  flatten(root);
}
function flatten(root) {
  const documents = generatedDocuments(loadCatalog(root));
  json(root, "STATE", documents.state);
  json(root, "index.json", documents.index);
}
function fixture(t, entries = [entry("one", 6), entry("two", 7)]) {
  const dir = mkdtempSync(join(tmpdir(), "fluxdown-index-test-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const base = join(dir, "base");
  const root = join(dir, "current");
  snapshot(base, entries);
  snapshot(root, entries);
  return { root, base, entries };
}
function history(root, base) {
  const catalog = loadCatalog(root);
  return validateHistory(catalog, loadBaseline(base, catalog));
}
const contains = (errors, text) => assert.ok(errors.some((error) => error.includes(text)), errors.join("\n"));

// Fixtures model exact published base snapshots; no GitHub request or real repo SHA is involved.
test("deleting a published shard cannot hide behind an unchanged maximum sequence", (t) => {
  const { root, base, entries } = fixture(t);
  rmSync(join(root, pathOf(entries[0])));
  flatten(root);
  assert.deepEqual(validateCatalog(loadCatalog(root)), []);
  contains(history(root, base), "已发布分片不可删除");
});

test("deleting an old package is rejected even if no current mirror points to it", (t) => {
  const { root, base } = fixture(t);
  writeFileSync(join(base, "dist/retained-0.9.0.fxplug"), "older published bytes");
  contains(history(root, base), "已发布包不可删除");
});

test("STATE and index high-water cannot regress along with removed latest version", (t) => {
  const { root, base, entries } = fixture(t);
  rmSync(join(root, pathOf(entries[1])));
  flatten(root);
  assert.deepEqual(validateCatalog(loadCatalog(root)), []);
  contains(history(root, base), "高水位低于历史基线 7");
});

test("duplicate global sequences are rejected", (t) => {
  const { root, entries } = fixture(t);
  json(root, pathOf(entries[0]), { ...entries[0], sequence: 7 });
  flatten(root);
  contains(validateCatalog(loadCatalog(root)), "sequence 7 重复");
});

test("mirror and display metadata repairs preserve published identity/hash/payload", (t) => {
  const { root, base, entries } = fixture(t);
  json(root, pathOf(entries[0]), { ...entries[0], description: "corrected display metadata",
    mirrors: [entries[0].mirrors[0].replace(SHA, "b".repeat(40))] });
  flatten(root);
  assert.deepEqual(validateCatalog(loadCatalog(root)), []);
  assert.deepEqual(history(root, base), []);
});

test("replacing payload and contentHash together cannot rewrite a published version", (t) => {
  const { root, base, entries } = fixture(t);
  const bytes = Buffer.from("different executable payload");
  writeFileSync(join(root, packageOf(entries[0])), bytes);
  json(root, pathOf(entries[0]), { ...entries[0], contentHash: digest(bytes) });
  flatten(root);
  assert.deepEqual(validateCatalog(loadCatalog(root)), []);
  contains(history(root, base), "已发布 contentHash 不可改写");
  contains(history(root, base), "已发布 payload 字节不可改写");
});

test("changing package bytes without updating contentHash fails local admission", (t) => {
  const { root, entries } = fixture(t);
  writeFileSync(join(root, packageOf(entries[0])), "tampered bytes");
  contains(validateCatalog(loadCatalog(root)), "contentHash 不符");
});

test("ordinary historical sequence changes remain forbidden even above high-water", (t) => {
  const { root, base, entries } = fixture(t);
  json(root, pathOf(entries[0]), { ...entries[0], sequence: 8 });
  flatten(root);
  contains(history(root, base), "历史 sequence 仅可修复已有冲突");
});

test("an existing duplicate may be repaired above base high-water while retaining its peer", (t) => {
  const { root, base, entries } = fixture(t, [entry("one", 7), entry("two", 7)]);
  json(root, pathOf(entries[0]), { ...entries[0], sequence: 8 });
  flatten(root);
  assert.deepEqual(validateCatalog(loadCatalog(root)), []);
  assert.deepEqual(history(root, base), []);
});

test("duplicate repair must preserve the original sequence on another published entry", (t) => {
  const { root, base, entries } = fixture(t, [entry("one", 7), entry("two", 7)]);
  json(root, pathOf(entries[0]), { ...entries[0], sequence: 8 });
  json(root, pathOf(entries[1]), { ...entries[1], sequence: 9 });
  flatten(root);
  contains(history(root, base), "另一项保留旧号");
});

test("duplicate repair cannot reuse a lower unused sequence", (t) => {
  const { root, base, entries } = fixture(t, [entry("one", 7), entry("two", 7)]);
  json(root, pathOf(entries[0]), { ...entries[0], sequence: 6 });
  flatten(root);
  assert.deepEqual(validateCatalog(loadCatalog(root)), []);
  contains(history(root, base), "新号须高于 7");
});

test("new versions cannot fill old sequence gaps without historical publication evidence", (t) => {
  const { root, base } = fixture(t, [entry("two", 7)]);
  const extra = entry("three", 6);
  json(root, pathOf(extra), extra);
  writeFileSync(join(root, packageOf(extra)), "published package three");
  flatten(root);
  assert.deepEqual(validateCatalog(loadCatalog(root)), []);
  contains(history(root, base), "新增 sequence 须高于历史高水位 7");
});

test("base STATE high-water governs additions even when shard maximum is lower", (t) => {
  const { root, base } = fixture(t, [entry("two", 7)]);
  json(base, "STATE", { ...loadCatalog(base).state, sequence: 9 });
  const extra = entry("three", 8);
  json(root, pathOf(extra), extra);
  writeFileSync(join(root, packageOf(extra)), "published package three");
  flatten(root);
  contains(history(root, base), "新增 sequence 须高于历史高水位 9");
  contains(history(root, base), "高水位低于历史基线 9");
});

test("same index entry count and maximum do not hide changed flattened content", (t) => {
  const { root } = fixture(t);
  const catalog = loadCatalog(root);
  catalog.index.entries[0].description = "manual index drift";
  json(root, "index.json", catalog.index);
  contains(validateCatalog(loadCatalog(root)), "flatten 内容不一致");
});

test("index identity and published plugin identity/version cannot be rewritten", (t) => {
  const { root, base, entries } = fixture(t);
  json(root, "STATE", { ...loadCatalog(root).state, indexId: "11111111-1111-1111-1111-111111111111" });
  json(root, pathOf(entries[0]), { ...entries[0], pluginId: "other@one", version: "2.0.0" });
  flatten(root);
  const errors = history(root, base);
  contains(errors, "索引身份");
  contains(errors, "已发布 pluginId 不可改写");
  contains(errors, "已发布 version 不可改写");
});

const generate = (root) => spawnSync(process.execPath, [fileURLToPath(new URL("./generate.mjs", import.meta.url)), "--root", root], { encoding: "utf8" });
for (const scenario of ["rollback", "duplicate"]) {
  test(`generate refuses ${scenario} before overwriting either generated file`, (t) => {
    const { root, entries } = fixture(t);
    if (scenario === "rollback") json(root, "STATE", { ...loadCatalog(root).state, sequence: 8 });
    else json(root, pathOf(entries[0]), { ...entries[0], sequence: 7 });
    const beforeState = readFileSync(join(root, "STATE"));
    const beforeIndex = readFileSync(join(root, "index.json"));
    const result = generate(root);
    assert.equal(result.status, 1, result.stderr);
    assert.match(result.stderr, scenario === "rollback" ? /禁止回退/ : /sequence 7 重复/);
    assert.deepEqual(readFileSync(join(root, "STATE")), beforeState);
    assert.deepEqual(readFileSync(join(root, "index.json")), beforeIndex);
  });
}

test("generate raises high-water for a new version and publishes its full entry", (t) => {
  const { root } = fixture(t);
  const extra = entry("three", 8);
  json(root, pathOf(extra), extra);
  writeFileSync(join(root, packageOf(extra)), "published package three");
  const result = generate(root);
  assert.equal(result.status, 0, result.stderr);
  const catalog = loadCatalog(root);
  assert.equal(catalog.state.sequence, 8);
  assert.deepEqual(catalog.index.entries.find((e) => e.pluginId === extra.pluginId), extra);
  assert.deepEqual(validateCatalog(catalog), []);
});

test("mutable Git mirrors, HTTP redirects, credentials and private addresses are rejected", () => {
  assert.throws(() => mirrorURL(`https://raw.githubusercontent.com/example/plugins/main/dist/one.fxplug`), /commit SHA/);
  assert.throws(() => mirrorURL(`https://cdn.jsdelivr.net/gh/example/plugins@main/dist/one.fxplug`), /commit SHA/);
  assert.throws(() => mirrorURL("http://example.com/one.fxplug"), /HTTPS/);
  assert.throws(() => mirrorURL("https://user:secret@example.com/one.fxplug"), /凭据/);
  assert.throws(() => mirrorURL("https://127.0.0.1/one.fxplug"), /IP/);
});

test("local package size is bounded before hashing", (t) => {
  const { root, entries } = fixture(t);
  writeFileSync(join(root, packageOf(entries[0])), Buffer.alloc(MAX_PACKAGE_BYTES + 1));
  assert.throws(() => loadCatalog(root), /超过 10 MiB/);
});
