// fluxdown-plugin-sdk@0.6.0 manifest validator (generated; do not edit)

// src/manifest.ts
var VALID_PERMISSIONS = [
  "ffmpeg",
  "ytdlp",
  "auth",
  "tasks",
  "browserRules",
  "desktop",
  "background",
  "intercept",
  "pageScripts",
  "archive"
];
var VALID_INTERCEPT_STAGES = [
  "prepare",
  "probed",
  "refresh",
  "selectVariant",
  "selectPeriod",
  "segments",
  "liveSegments",
  "finalize",
  "failed"
];
var VALID_EVENTS = ["onStart", "onError", "onDone", "onMetaProbed", "onCancel"];
var VIEW_LOCATIONS = ["activity", "settings", "taskDetail", "window", "auth"];
var WINDOW_SIZE_MIN = 240;
var WINDOW_SIZE_MAX = 4096;
var NETWORK_HOSTS_MAX = 64;
var VIEWS_MAX = 16;
var COMMANDS_MAX = 32;
var TITLE_MAX_CHARS = 40;
var SNIFF_PACK_MAX_BYTES = 256 * 1024;
var VIEW_ICON_MAX_BYTES = 16 * 1024;
var SNIFF_PACK_MAX_RULES = 500;
var SNIFF_PACK_FORMAT = "fluxdown-sniff-pack";
var PAGE_SCRIPTS_MAX = 16;
var PAGE_SCRIPT_MATCHES_MAX = 32;
var PAGE_SCRIPT_JS_MAX = 8;
var PAGE_SCRIPT_FILE_MAX_BYTES = 256 * 1024;
var PAGE_SCRIPT_MAX_BYTES = 384 * 1024;
var PACKAGE_MAX_BYTES = 10 * 1024 * 1024;
var PACKAGE_MAX_ENTRIES = 200;
var PACKAGE_MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024;
var RSS_PROVIDER_ID = "rss";
var isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
var nonEmptyString = (value) => typeof value === "string" && value.trim() !== "";
var stringArray = (value) => Array.isArray(value) && value.every((v) => typeof v === "string");
var charLength = (s) => [...s].length;
function isSafeRelativePath(path) {
  if (typeof path !== "string" || path === "") return false;
  if (path.startsWith("/") || path.startsWith("\\")) return false;
  if (/^[A-Za-z]:/.test(path)) return false;
  for (const segment of path.split(/[/\\]/)) {
    if (segment === "" || segment === "." || segment === "..") return false;
  }
  return !/[\u0000-\u001f\u007f-\u009f]/.test(path);
}
function isValidIdentity(value) {
  return typeof value === "string" && /^[a-z0-9_-]+@[a-z0-9_-]+$/.test(value);
}
var isValidContributionId = (value) => typeof value === "string" && /^[a-z][a-z0-9-]{0,31}$/.test(value);
var hasExtension = (path, exts) => {
  const lower = path.toLowerCase();
  return exts.some((e) => lower.endsWith(e));
};
function parseSemver(raw) {
  let s = raw.trim();
  if (s.startsWith("v")) s = s.slice(1);
  const core = s.split(/[-+]/)[0] ?? "";
  const parts = core.split(".");
  if (parts.length !== 3 || !parts.every((p) => /^\d+$/.test(p))) return null;
  return parts.map(Number);
}
var STRICT_SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
function isIpv4(host) {
  const parts = host.split(".");
  return parts.length === 4 && parts.every((p) => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
}
function isIpv6(host) {
  if (!host.includes(":") || !/^[0-9a-fA-F:.]+$/.test(host)) return false;
  let rest = host;
  let groupsAllowed = 8;
  const lastColon = rest.lastIndexOf(":");
  const tail = rest.slice(lastColon + 1);
  if (tail.includes(".")) {
    if (!isIpv4(tail)) return false;
    rest = rest.slice(0, lastColon + 1) + "0:0";
  }
  const doubles = rest.split("::").length - 1;
  if (doubles > 1) return false;
  const groups = rest.split(":");
  if (doubles === 1) {
    const [head = "", back = ""] = rest.split("::");
    const h = head === "" ? [] : head.split(":");
    const b = back === "" ? [] : back.split(":");
    groupsAllowed = 7;
    return h.length + b.length <= groupsAllowed && [...h, ...b].every((g) => /^[0-9a-fA-F]{1,4}$/.test(g));
  }
  return groups.length === 8 && groups.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g));
}
function isValidNetworkHost(host) {
  if (typeof host !== "string" || host === "" || host.length > 253) return false;
  if (isIpv4(host)) return true;
  if (isIpv6(host)) return host === host.toLowerCase();
  return host.split(".").every((label) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}
function isPublicHttpsUrl(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || !url.hostname || url.username || url.password || url.hash) return false;
    const host = url.hostname.toLowerCase();
    if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return false;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[") || host.includes(":")) return false;
    return true;
  } catch {
    return false;
  }
}
function unknownKeys(errors, where, value, allowed) {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) errors.push(`${where}: \u672A\u77E5\u5B57\u6BB5 ${key}`);
  }
}
function checkOptionalString(errors, where, value) {
  if (value !== void 0 && value !== null && typeof value !== "string") {
    errors.push(`${where} \u987B\u4E3A\u5B57\u7B26\u4E32`);
  }
}
function checkOptionalBool(errors, where, value) {
  if (value !== void 0 && value !== null && typeof value !== "boolean") {
    errors.push(`${where} \u987B\u4E3A\u5E03\u5C14`);
  }
}
var inPackage = (files, path) => files === null || files.has(path.replaceAll("\\", "/"));
function checkEntry(errors, where, entry, files, strict) {
  if (!isSafeRelativePath(entry)) {
    errors.push(`${where} \u8DEF\u5F84 '${String(entry)}' \u975E\u6CD5`);
  } else if (strict && !inPackage(files, entry)) {
    errors.push(`${where} \u6307\u5411\u7684 ${entry} \u4E0D\u5728\u5305\u5185`);
  }
}
function checkTimeout(errors, where, value) {
  if (value === void 0 || value === null) return;
  if (!Number.isSafeInteger(value) || value <= 0) errors.push(`${where} timeoutMs \u987B\u4E3A\u6B63\u6574\u6570`);
}
function checkMemoryLimit(errors, where, value) {
  if (value === void 0 || value === null) return;
  if (!Number.isSafeInteger(value) || value <= 0) errors.push(`${where} memoryLimitMb \u987B\u4E3A\u6B63\u6574\u6570`);
}
function checkMatch(errors, where, match) {
  if (!isObject(match)) return void errors.push(`${where} \u987B\u4E3A\u5BF9\u8C61`);
  unknownKeys(errors, where, match, ["urls"]);
  if (!Array.isArray(match.urls) || match.urls.length === 0 || !match.urls.every(nonEmptyString)) {
    errors.push(`${where}.urls \u987B\u4E3A\u975E\u7A7A\u5B57\u7B26\u4E32\u6570\u7EC4`);
  }
}
var hasPermission = (permissions, name) => Array.isArray(permissions) && permissions.includes(name);
var validTitle = (title) => typeof title === "string" && charLength(title) >= 1 && charLength(title) <= TITLE_MAX_CHARS;
function checkMain(errors, manifest, files, permissions) {
  const main = manifest.main;
  if (main === void 0 || main === null) return;
  if (!isObject(main)) return void errors.push("main \u987B\u4E3A\u5BF9\u8C61");
  unknownKeys(errors, "main", main, ["entry", "events", "background", "imageHosts"]);
  if (!isSafeRelativePath(main.entry)) {
    errors.push(`main entry \u8DEF\u5F84 '${String(main.entry)}' \u975E\u6CD5`);
  } else {
    if (!hasExtension(main.entry, [".js"])) errors.push(`main entry '${main.entry}' \u6269\u5C55\u540D\u987B\u4E3A .js`);
    if (!inPackage(files, main.entry)) errors.push(`\u5305\u5185\u7F3A\u5C11\u6587\u4EF6 '${main.entry}'`);
  }
  const events = main.events ?? [];
  if (!stringArray(events)) errors.push("main.events \u987B\u4E3A\u5B57\u7B26\u4E32\u6570\u7EC4");
  else {
    for (const ev of events) {
      if (!VALID_EVENTS.includes(ev)) {
        errors.push(`main.events \u672A\u77E5\u4E8B\u4EF6 '${ev}'\uFF0C\u5408\u6CD5\uFF1A${VALID_EVENTS.join(", ")}`);
      }
    }
  }
  if (main.background !== void 0 && main.background !== null && typeof main.background !== "boolean") {
    errors.push("main.background \u987B\u4E3A\u5E03\u5C14");
  } else if (main.background === true && !hasPermission(permissions, "background")) {
    errors.push("main.background \u4E3A true \u65F6 permissions \u5FC5\u987B\u5305\u542B background");
  }
  const imageHosts = main.imageHosts ?? [];
  if (!Array.isArray(imageHosts)) errors.push("main.imageHosts \u987B\u4E3A\u6570\u7EC4");
  else {
    if (imageHosts.length > NETWORK_HOSTS_MAX) errors.push(`main.imageHosts \u81F3\u591A ${NETWORK_HOSTS_MAX} \u9879`);
    const seen = /* @__PURE__ */ new Set();
    for (const host of imageHosts) {
      if (!isValidNetworkHost(host)) errors.push(`main.imageHosts '${String(host)}' \u975E\u6CD5`);
      else if (seen.has(host)) errors.push(`main.imageHosts '${host}' \u91CD\u590D`);
      else seen.add(host);
    }
  }
}
function checkDesktop(errors, view, desktop, files, permissions) {
  const where = `view '${String(view.id)}'`;
  if (!isObject(desktop)) return void errors.push(`${where} desktop \u987B\u4E3A\u5BF9\u8C61`);
  unknownKeys(errors, `${where} desktop`, desktop, ["entry", "networkHosts", "width", "height"]);
  if (!isSafeRelativePath(desktop.entry)) {
    errors.push(`${where} desktop entry \u8DEF\u5F84 '${String(desktop.entry)}' \u975E\u6CD5`);
  } else {
    if (!hasExtension(desktop.entry, [".js", ".mjs"])) {
      errors.push(`${where} desktop entry '${desktop.entry}' \u6269\u5C55\u540D\u987B\u4E3A .js \u6216 .mjs`);
    }
    if (!inPackage(files, desktop.entry)) errors.push(`\u5305\u5185\u7F3A\u5C11\u6587\u4EF6 '${desktop.entry}'`);
  }
  if (!hasPermission(permissions, "desktop")) {
    errors.push(`${where} \u58F0\u660E desktop \u65F6 permissions \u5FC5\u987B\u5305\u542B desktop`);
  }
  for (const key of ["width", "height"]) {
    const value = desktop[key];
    if (value === void 0 || value === null) continue;
    if (view.location !== "window") {
      errors.push(`${where} \u7684 ${key} \u4EC5\u5141\u8BB8\u7528\u4E8E location \u4E3A window \u7684 view`);
    } else if (typeof value !== "number" || !Number.isFinite(value) || value < WINDOW_SIZE_MIN || value > WINDOW_SIZE_MAX) {
      errors.push(`${where} ${key} \u987B\u4E3A [${WINDOW_SIZE_MIN}, ${WINDOW_SIZE_MAX}] \u5185\u7684\u6709\u9650\u6570`);
    }
  }
  const hosts = desktop.networkHosts ?? [];
  if (!Array.isArray(hosts)) return void errors.push(`${where} networkHosts \u987B\u4E3A\u6570\u7EC4`);
  if (hosts.length > NETWORK_HOSTS_MAX) errors.push(`${where} networkHosts \u81F3\u591A ${NETWORK_HOSTS_MAX} \u9879`);
  const seen = /* @__PURE__ */ new Set();
  for (const host of hosts) {
    if (!isValidNetworkHost(host)) errors.push(`${where} networkHosts '${String(host)}' \u975E\u6CD5`);
    else if (seen.has(host)) errors.push(`${where} networkHosts '${host}' \u91CD\u590D`);
    else seen.add(host);
  }
}
var PAGE_SCRIPT_RUN_AT = ["document_start", "document_end", "document_idle"];
var PAGE_SCRIPT_WORLDS = ["isolated", "main"];
function isValidMatchPattern(pattern) {
  if (typeof pattern !== "string") return false;
  const sep = pattern.indexOf("://");
  if (sep < 0) return false;
  const scheme = pattern.slice(0, sep);
  if (scheme !== "http" && scheme !== "https" && scheme !== "*") return false;
  const rest = pattern.slice(sep + 3);
  const slash = rest.indexOf("/");
  if (slash < 0) return false;
  const host = rest.slice(0, slash);
  const path = rest.slice(slash);
  if (/[\u0000-\u001f\u007f-\u009f\s]/.test(path)) return false;
  const domain = host.startsWith("*.") ? host.slice(2) : host;
  return domain !== "" && domain.includes(".") && /^[a-z0-9.-]+$/.test(domain) && !/^[.-]/.test(domain) && !/[.-]$/.test(domain) && !domain.includes("..");
}
var isValidPageScriptId = (value) => typeof value === "string" && /^[a-z0-9][a-z0-9_-]{0,31}$/.test(value);
function checkPageScripts(errors, value, files, permissions) {
  if (value === void 0 || value === null) return;
  if (!Array.isArray(value)) return void errors.push("contributes.pageScripts \u987B\u4E3A\u6570\u7EC4");
  if (value.length === 0) return;
  if (value.length > PAGE_SCRIPTS_MAX) errors.push(`contributes.pageScripts \u81F3\u591A ${PAGE_SCRIPTS_MAX} \u9879`);
  if (!hasPermission(permissions, "pageScripts")) {
    errors.push("\u58F0\u660E pageScripts \u65F6 permissions \u5FC5\u987B\u5305\u542B pageScripts");
  }
  const seen = /* @__PURE__ */ new Set();
  for (const script of value) {
    if (!isObject(script)) {
      errors.push("pageScript \u987B\u4E3A\u5BF9\u8C61");
      continue;
    }
    unknownKeys(errors, "pageScript", script, [
      "id",
      "title",
      "matches",
      "excludeMatches",
      "js",
      "runAt",
      "world",
      "allFrames"
    ]);
    const where = `pageScript '${String(script.id)}'`;
    if (!isValidPageScriptId(script.id)) {
      errors.push(`pageScript id '${String(script.id)}' \u975E\u6CD5\uFF1A\u987B\u5339\u914D ^[a-z0-9][a-z0-9_-]{0,31}$`);
    } else if (seen.has(script.id)) {
      errors.push(`pageScript id '${script.id}' \u91CD\u590D`);
    } else seen.add(script.id);
    if (!validTitle(script.title)) errors.push(`${where} title \u987B\u4E3A 1\u2013${TITLE_MAX_CHARS} \u4E2A\u5B57\u7B26`);
    const matches = script.matches;
    if (!Array.isArray(matches) || matches.length < 1 || matches.length > PAGE_SCRIPT_MATCHES_MAX) {
      errors.push(`${where} matches \u987B\u4E3A 1\u2013${PAGE_SCRIPT_MATCHES_MAX} \u9879`);
    }
    const excludes = script.excludeMatches ?? [];
    if (!Array.isArray(excludes) || excludes.length > PAGE_SCRIPT_MATCHES_MAX) {
      errors.push(`${where} excludeMatches \u81F3\u591A ${PAGE_SCRIPT_MATCHES_MAX} \u9879`);
    }
    for (const [field, list] of [["matches", matches], ["excludeMatches", excludes]]) {
      if (!Array.isArray(list)) continue;
      for (const pattern of list) {
        if (!isValidMatchPattern(pattern)) errors.push(`${where} ${field} '${String(pattern)}' \u975E\u6CD5 match pattern`);
      }
    }
    const js = script.js;
    if (!Array.isArray(js) || js.length < 1 || js.length > PAGE_SCRIPT_JS_MAX) {
      errors.push(`${where} js \u987B\u4E3A 1\u2013${PAGE_SCRIPT_JS_MAX} \u9879`);
    } else {
      const jsSeen = /* @__PURE__ */ new Set();
      for (const file of js) {
        if (!isSafeRelativePath(file)) {
          errors.push(`${where} js \u8DEF\u5F84 '${String(file)}' \u975E\u6CD5`);
          continue;
        }
        if (!hasExtension(file, [".js"])) errors.push(`${where} js '${file}' \u6269\u5C55\u540D\u987B\u4E3A .js`);
        if (jsSeen.has(file)) errors.push(`${where} js '${file}' \u91CD\u590D`);
        else jsSeen.add(file);
        if (!inPackage(files, file)) errors.push(`\u5305\u5185\u7F3A\u5C11\u6587\u4EF6 '${file}'`);
      }
    }
    if (script.runAt !== void 0 && !PAGE_SCRIPT_RUN_AT.includes(script.runAt)) {
      errors.push(`${where} runAt \u975E\u6CD5\uFF0C\u5408\u6CD5\uFF1A${PAGE_SCRIPT_RUN_AT.join(", ")}`);
    }
    if (script.world !== void 0 && !PAGE_SCRIPT_WORLDS.includes(script.world)) {
      errors.push(`${where} world \u975E\u6CD5\uFF0C\u5408\u6CD5\uFF1A${PAGE_SCRIPT_WORLDS.join(", ")}`);
    }
    checkOptionalBool(errors, `${where} allFrames`, script.allFrames);
  }
}
function checkContributes(errors, manifest, files, permissions) {
  const contributes = manifest.contributes;
  if (contributes === void 0 || contributes === null) return;
  if (!isObject(contributes)) return void errors.push("contributes \u987B\u4E3A\u5BF9\u8C61");
  unknownKeys(errors, "contributes", contributes, ["views", "commands", "sniffRules", "pageScripts", "archive", "archiveRules"]);
  const hasMain = manifest.main !== void 0 && manifest.main !== null;
  const views = contributes.views ?? [];
  if (!Array.isArray(views)) errors.push("contributes.views \u987B\u4E3A\u6570\u7EC4");
  else {
    if (views.length > VIEWS_MAX) errors.push(`contributes.views \u81F3\u591A ${VIEWS_MAX} \u9879`);
    const seen = /* @__PURE__ */ new Set();
    let settingsViews = 0;
    let authViews = 0;
    for (const view of views) {
      if (!isObject(view)) {
        errors.push("view \u987B\u4E3A\u5BF9\u8C61");
        continue;
      }
      unknownKeys(errors, "view", view, ["id", "title", "location", "desktop", "portable", "icon"]);
      if (!isValidContributionId(view.id)) {
        errors.push(`view id '${String(view.id)}' \u975E\u6CD5\uFF1A\u987B\u5339\u914D ^[a-z][a-z0-9-]{0,31}$`);
      } else if (seen.has(view.id)) {
        errors.push(`view id '${view.id}' \u91CD\u590D`);
      } else seen.add(view.id);
      if (!validTitle(view.title)) {
        errors.push(`view '${String(view.id)}' title \u987B\u4E3A 1\u2013${TITLE_MAX_CHARS} \u4E2A\u5B57\u7B26`);
      }
      if (!VIEW_LOCATIONS.includes(view.location)) {
        errors.push(`view '${String(view.id)}' location \u975E\u6CD5\uFF0C\u5408\u6CD5\uFF1A${VIEW_LOCATIONS.join(", ")}`);
      }
      if (view.location === "settings" && ++settingsViews > 1) {
        errors.push("location \u4E3A settings \u7684 view \u81F3\u591A 1 \u4E2A");
      }
      if (view.location === "auth") {
        if (++authViews > 1) errors.push("location \u4E3A auth \u7684 view \u81F3\u591A 1 \u4E2A");
        if (manifest.auth === void 0 || manifest.auth === null) {
          errors.push("location \u4E3A auth \u7684 view \u8981\u6C42\u58F0\u660E auth");
        }
      }
      const hasDesktop = view.desktop !== void 0 && view.desktop !== null;
      if (view.portable !== void 0 && typeof view.portable !== "boolean") {
        errors.push(`view '${String(view.id)}' portable \u987B\u4E3A\u5E03\u5C14\u503C`);
      }
      if (!hasDesktop) {
        if (view.portable === true) errors.push(`view '${String(view.id)}' \u7684 portable \u4EC5\u5141\u8BB8\u4E0E desktop \u540C\u65F6\u58F0\u660E`);
      } else checkDesktop(errors, view, view.desktop, files, permissions);
      if (view.icon !== void 0 && view.icon !== null) {
        if (typeof view.icon !== "string") errors.push(`view '${String(view.id)}' icon \u987B\u4E3A\u5B57\u7B26\u4E32`);
        else if (!isSafeRelativePath(view.icon)) errors.push(`view '${String(view.id)}' icon \u8DEF\u5F84 '${view.icon}' \u975E\u6CD5`);
        else {
          if (!hasExtension(view.icon, [".svg"])) {
            errors.push(`view '${String(view.id)}' icon '${view.icon}' \u6269\u5C55\u540D\u987B\u4E3A .svg`);
          }
          if (!inPackage(files, view.icon)) errors.push(`\u5305\u5185\u7F3A\u5C11\u6587\u4EF6 '${view.icon}'`);
        }
      }
      const portable = !hasDesktop || view.portable === true;
      if (portable && !hasMain) errors.push(`view '${String(view.id)}' \u6709\u53EF\u79FB\u690D\u5B9E\u73B0\uFF0C\u5FC5\u987B\u58F0\u660E main`);
    }
  }
  const commands = contributes.commands ?? [];
  if (!Array.isArray(commands)) errors.push("contributes.commands \u987B\u4E3A\u6570\u7EC4");
  else {
    if (commands.length > COMMANDS_MAX) errors.push(`contributes.commands \u81F3\u591A ${COMMANDS_MAX} \u9879`);
    const seen = /* @__PURE__ */ new Set();
    for (const command of commands) {
      if (!isObject(command)) {
        errors.push("command \u987B\u4E3A\u5BF9\u8C61");
        continue;
      }
      unknownKeys(errors, "command", command, ["id", "title", "palette", "taskMenu"]);
      if (!isValidContributionId(command.id)) {
        errors.push(`command id '${String(command.id)}' \u975E\u6CD5\uFF1A\u987B\u5339\u914D ^[a-z][a-z0-9-]{0,31}$`);
      } else if (seen.has(command.id)) {
        errors.push(`command id '${command.id}' \u91CD\u590D`);
      } else seen.add(command.id);
      if (!validTitle(command.title)) {
        errors.push(`command '${String(command.id)}' title \u987B\u4E3A 1\u2013${TITLE_MAX_CHARS} \u4E2A\u5B57\u7B26`);
      }
      checkOptionalBool(errors, `command '${String(command.id)}' palette`, command.palette);
      checkOptionalBool(errors, `command '${String(command.id)}' taskMenu`, command.taskMenu);
    }
    if (commands.length > 0 && !hasMain) errors.push("\u58F0\u660E commands \u65F6\u5FC5\u987B\u58F0\u660E main");
  }
  const rules = contributes.sniffRules;
  if (rules !== void 0 && rules !== null) {
    if (!isSafeRelativePath(rules)) {
      errors.push(`sniffRules \u8DEF\u5F84 '${String(rules)}' \u975E\u6CD5`);
    } else {
      if (!hasExtension(rules, [".json"])) errors.push(`sniffRules '${rules}' \u6269\u5C55\u540D\u987B\u4E3A .json`);
      if (!hasPermission(permissions, "browserRules")) {
        errors.push("\u58F0\u660E sniffRules \u65F6 permissions \u5FC5\u987B\u5305\u542B browserRules");
      }
      if (!inPackage(files, rules)) errors.push(`\u5305\u5185\u7F3A\u5C11\u6587\u4EF6 '${rules}'`);
    }
  }
  const archive = contributes.archive;
  if (archive !== void 0 && archive !== null) {
    if (typeof archive !== "string" || !isSafeRelativePath(archive)) {
      errors.push(`archive \u8DEF\u5F84 '${String(archive)}' \u975E\u6CD5`);
    } else {
      if (!hasExtension(archive, [".js"])) errors.push(`archive '${archive}' \u6269\u5C55\u540D\u987B\u4E3A .js`);
      if (!hasPermission(permissions, "archive")) errors.push("\u58F0\u660E archive \u65F6 permissions \u5FC5\u987B\u5305\u542B archive");
      if (!inPackage(files, archive)) errors.push(`\u5305\u5185\u7F3A\u5C11\u6587\u4EF6 '${archive}'`);
    }
  }
  const archiveRules = contributes.archiveRules;
  if (archiveRules !== void 0 && archiveRules !== null) {
    if (!isObject(archiveRules)) {
      errors.push("archiveRules \u987B\u4E3A\u5BF9\u8C61");
    } else {
      unknownKeys(errors, "archiveRules", archiveRules, ["entry", "publicKey", "updateUrl"]);
      const entry = archiveRules.entry;
      if (typeof entry !== "string" || !isSafeRelativePath(entry)) {
        errors.push(`archiveRules entry \u8DEF\u5F84 '${String(entry)}' \u975E\u6CD5`);
      } else {
        if (!hasExtension(entry, [".json"])) errors.push("archiveRules entry \u6269\u5C55\u540D\u987B\u4E3A .json");
        if (!inPackage(files, entry)) errors.push(`\u5305\u5185\u7F3A\u5C11\u6587\u4EF6 '${entry}'`);
      }
      if (typeof archiveRules.publicKey !== "string" || !/^[0-9a-fA-F]{64}$/.test(archiveRules.publicKey)) {
        errors.push("archiveRules publicKey \u987B\u4E3A 64 \u4F4D\u5341\u516D\u8FDB\u5236 Ed25519 \u516C\u94A5");
      }
      if (!hasPermission(permissions, "archive")) errors.push("\u58F0\u660E archiveRules \u65F6 permissions \u5FC5\u987B\u5305\u542B archive");
      if (archiveRules.updateUrl !== void 0 && archiveRules.updateUrl !== null && (typeof archiveRules.updateUrl !== "string" || !isPublicHttpsUrl(archiveRules.updateUrl))) {
        errors.push("archiveRules updateUrl \u987B\u4E3A\u65E0\u51ED\u636E\u3001\u65E0\u7247\u6BB5\u7684\u516C\u5F00 HTTPS URL");
      }
    }
  }
  checkPageScripts(errors, contributes.pageScripts, files, permissions);
}
function checkSetting(errors, field, seen) {
  if (!isObject(field)) return void errors.push("settings \u6761\u76EE\u987B\u4E3A\u5BF9\u8C61");
  const key = field.key;
  const where = `setting '${String(key)}'`;
  unknownKeys(errors, where, field, [
    "key",
    "title",
    "description",
    "type",
    "widget",
    "options",
    "default",
    "required",
    "min",
    "max",
    "pattern",
    "helperScript",
    "helperLabel",
    "localizations"
  ]);
  checkSettingLocalizations(errors, field, where);
  if (!nonEmptyString(key)) errors.push("setting key \u4E0D\u53EF\u4E3A\u7A7A");
  else if (seen.has(key)) errors.push(`setting key '${key}' \u91CD\u590D`);
  else seen.add(key);
  if (typeof field.title !== "string") errors.push(`${where}: title \u5FC5\u586B`);
  checkOptionalString(errors, `${where}: description`, field.description);
  checkOptionalBool(errors, `${where}: required`, field.required);
  const type = field.type;
  if (type !== "string" && type !== "number" && type !== "boolean") {
    return void errors.push(`${where}: type \u975E\u6CD5`);
  }
  const widgets = ["text", "password", "textarea", "select", "toggle", "number", "folder"];
  const widget = field.widget ?? { string: "text", number: "number", boolean: "toggle" }[type];
  const allowedType = {
    text: "string",
    password: "string",
    textarea: "string",
    folder: "string",
    select: "string",
    toggle: "boolean",
    number: "number"
  };
  if (typeof widget !== "string" || !widgets.includes(widget)) {
    errors.push(`${where}: widget \u975E\u6CD5`);
  } else if (allowedType[widget] !== type) {
    errors.push(`${where}: widget '${widget}' \u4E0D\u5141\u8BB8 type '${type}'`);
  }
  const optionsRaw = field.options ?? [];
  const optionsOk = Array.isArray(optionsRaw) && optionsRaw.every((o) => isObject(o) && typeof o.value === "string" && typeof o.label === "string");
  if (!optionsOk) errors.push(`${where}: options \u987B\u4E3A {value,label} \u5B57\u7B26\u4E32\u6570\u7EC4`);
  const options = optionsOk ? optionsRaw : [];
  const fallback = field.default;
  if (fallback !== void 0 && fallback !== null && typeof fallback !== "string") {
    errors.push(`${where}: default \u987B\u4E3A\u5B57\u7B26\u4E32`);
  }
  if (widget === "select") {
    if (optionsOk && options.length === 0) {
      errors.push(`${where}: select \u7684 options \u4E0D\u53EF\u4E3A\u7A7A`);
    } else if (typeof fallback === "string" && !options.some((o) => o.value === fallback)) {
      errors.push(`${where}: default '${fallback}' \u4E0D\u5728 options \u4E2D`);
    }
  }
  for (const bound of ["min", "max"]) {
    const value = field[bound];
    if (value === void 0 || value === null) continue;
    if (type !== "number") errors.push(`${where}: min/max \u4EC5 number \u6709\u6548`);
    else if (typeof value !== "number" || !Number.isFinite(value)) errors.push(`${where}: ${bound} \u975E\u6709\u9650\u6570`);
  }
  if (typeof field.min === "number" && typeof field.max === "number" && field.min > field.max) {
    errors.push(`${where}: min(${field.min}) > max(${field.max})`);
  }
  if (field.pattern !== void 0 && field.pattern !== null) {
    if (typeof field.pattern !== "string") errors.push(`${where}: pattern \u987B\u4E3A\u5B57\u7B26\u4E32`);
    else if (type !== "string") errors.push(`${where}: pattern \u4EC5 string \u6709\u6548`);
  }
  if (field.helperScript !== void 0 && field.helperScript !== null) {
    if (typeof field.helperScript !== "string") {
      errors.push(`${where}: helperScript \u987B\u4E3A\u5B57\u7B26\u4E32`);
    } else {
      if (type !== "string") errors.push(`${where}: helperScript \u4EC5 string \u6709\u6548`);
      if (field.helperScript === "" || utf8Length(field.helperScript) > 4 * 1024) {
        errors.push(`${where}: helperScript \u987B\u975E\u7A7A\u4E14 \u22644KB`);
      }
    }
  }
  if (field.helperLabel !== void 0 && field.helperLabel !== null) {
    if (typeof field.helperLabel !== "string" || charLength(field.helperLabel) > 60 || field.helperScript === void 0 || field.helperScript === null) {
      errors.push(`${where}: helperLabel \u987B \u226460 \u5B57\u7B26\u4E14\u987B\u4E0E helperScript \u540C\u65F6\u51FA\u73B0`);
    }
  }
  if (type === "number" && typeof fallback === "string") {
    const value = Number(fallback);
    if (fallback.trim() === "" || !Number.isFinite(value)) {
      errors.push(`${where}: number default '${fallback}' \u975E\u6CD5`);
    } else {
      if (typeof field.min === "number" && value < field.min) errors.push(`${where}: default ${value} < min ${field.min}`);
      if (typeof field.max === "number" && value > field.max) errors.push(`${where}: default ${value} > max ${field.max}`);
    }
  }
  if (type === "boolean" && typeof fallback === "string" && fallback !== "true" && fallback !== "false") {
    errors.push(`${where}: boolean default \u5FC5\u987B\u4E3A 'true'/'false'`);
  }
}
var SETTING_LOCALIZATION_FIELDS = ["title", "description", "helperLabel"];
function checkSettingLocalizations(errors, field, where) {
  const raw = field.localizations;
  if (raw === void 0) return;
  if (!isObject(raw)) return void errors.push(`${where}: localizations \u987B\u4E3A\u5BF9\u8C61`);
  const locales = Object.keys(raw);
  if (locales.length > 64) errors.push(`${where}: localizations \u6700\u591A 64 \u79CD\u8BED\u8A00`);
  const seen = /* @__PURE__ */ new Set();
  for (const locale of locales) {
    const value = raw[locale];
    if (!/^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$/.test(locale)) {
      errors.push(`${where}: localization locale '${locale}' \u975E\u6CD5`);
    }
    const normalized = locale.toLowerCase();
    if (seen.has(normalized)) errors.push(`${where}: localization locale '${locale}' \u91CD\u590D`);
    seen.add(normalized);
    if (!isObject(value)) {
      errors.push(`${where}: localization '${locale}' \u987B\u4E3A\u5BF9\u8C61`);
      continue;
    }
    unknownKeys(errors, `${where} localization '${locale}'`, value, [...SETTING_LOCALIZATION_FIELDS, "options"]);
    for (const key of SETTING_LOCALIZATION_FIELDS) {
      const text = value[key];
      if (text !== void 0 && text !== null && (typeof text !== "string" || charLength(text) > 4096)) {
        errors.push(`${where}: localization '${locale}' ${key} \u987B\u4E3A \u22644096 \u5B57\u7B26\u7684\u5B57\u7B26\u4E32`);
      }
    }
    if (value.helperLabel !== void 0 && value.helperLabel !== null && field.helperScript == null) {
      errors.push(`${where}: localization '${locale}' helperLabel \u987B\u4E0E helperScript \u540C\u65F6\u51FA\u73B0`);
    }
    if (value.options !== void 0) {
      if (!isObject(value.options)) errors.push(`${where}: localization '${locale}' options \u987B\u4E3A\u5BF9\u8C61`);
      else {
        const options = Array.isArray(field.options) ? field.options : [];
        const values = new Set(options.filter(isObject).map((o) => o.value));
        for (const [option, label] of Object.entries(value.options)) {
          if (!values.has(option)) errors.push(`${where}: localization '${locale}' \u672A\u77E5 option value '${option}'`);
          if (typeof label !== "string" || charLength(label) > 4096) {
            errors.push(`${where}: localization '${locale}' option '${option}' \u987B\u4E3A \u22644096 \u5B57\u7B26\u7684\u5B57\u7B26\u4E32`);
          }
        }
      }
    }
  }
}
function utf8Length(s) {
  let n = 0;
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    n += cp < 128 ? 1 : cp < 2048 ? 2 : cp < 65536 ? 3 : 4;
  }
  return n;
}
function validateManifest(manifest, files, options = {}) {
  const errors = [];
  const strict = options.strict === true;
  const fileSet = files ?? null;
  if (strict && fileSet === null) {
    return { ok: false, errors: ["strict \u6A21\u5F0F\u9700\u8981\u63D0\u4F9B\u5305\u5185\u6587\u4EF6\u96C6\u5408 files\uFF08\u7528\u4E8E\u6821\u9A8C\u5165\u53E3\u6587\u4EF6\u662F\u5426\u5B58\u5728\uFF09"] };
  }
  if (!isObject(manifest)) return { ok: false, errors: ["manifest.json \u987B\u4E3A JSON \u5BF9\u8C61"] };
  unknownKeys(errors, "manifest", manifest, [
    "identity",
    "name",
    "version",
    "description",
    "homepage",
    "icon",
    "minAppVersion",
    "resolvers",
    "subscriptions",
    "hooks",
    "interceptors",
    "auth",
    "main",
    "contributes",
    "settings",
    "permissions"
  ]);
  if (!isValidIdentity(manifest.identity)) {
    errors.push(`identity '${String(manifest.identity)}' \u975E\u6CD5\uFF1A\u987B\u5339\u914D ^[a-z0-9_-]+@[a-z0-9_-]+$`);
  }
  if (!nonEmptyString(manifest.name)) errors.push("name \u4E0D\u53EF\u4E3A\u7A7A");
  const versionOk = (v) => typeof v === "string" && (strict ? STRICT_SEMVER.test(v) : parseSemver(v) !== null);
  if (!versionOk(manifest.version)) {
    errors.push(
      strict ? `version '${String(manifest.version)}' \u987B\u4E3A\u4E09\u6BB5 MAJOR.MINOR.PATCH\uFF08\u4E0D\u6536\u9884\u53D1\u5E03/v \u524D\u7F00\uFF09` : `version '${String(manifest.version)}' \u975E\u6CD5\uFF1A\u987B\u4E3A MAJOR.MINOR.PATCH`
    );
  }
  for (const key of ["description", "homepage", "icon", "minAppVersion"]) {
    checkOptionalString(errors, key, manifest[key]);
  }
  if (typeof manifest.minAppVersion === "string" && manifest.minAppVersion !== "" && !versionOk(manifest.minAppVersion)) {
    errors.push(`minAppVersion '${manifest.minAppVersion}' \u975E\u6CD5`);
  }
  if (typeof manifest.icon === "string" && manifest.icon !== "") {
    checkEntry(errors, "icon", manifest.icon, fileSet, strict);
  }
  const resolvers = manifest.resolvers ?? [];
  if (!Array.isArray(resolvers)) errors.push("resolvers \u987B\u4E3A\u6570\u7EC4");
  else {
    if (resolvers.length > 1) errors.push("v1 \u6BCF\u63D2\u4EF6\u81F3\u591A\u4E00\u4E2A resolver");
    for (const resolver of resolvers) {
      if (!isObject(resolver)) {
        errors.push("resolver \u987B\u4E3A\u5BF9\u8C61");
        continue;
      }
      unknownKeys(errors, "resolver", resolver, ["match", "entry", "timeoutMs", "memoryLimitMb", "multi"]);
      checkMatch(errors, "resolver match", resolver.match);
      checkEntry(errors, "resolver entry", resolver.entry, fileSet, strict);
      checkTimeout(errors, "resolver", resolver.timeoutMs);
      checkMemoryLimit(errors, "resolver", resolver.memoryLimitMb);
      checkOptionalBool(errors, "resolver multi", resolver.multi);
    }
  }
  const subscriptions = manifest.subscriptions ?? [];
  if (!Array.isArray(subscriptions)) errors.push("subscriptions \u987B\u4E3A\u6570\u7EC4");
  else {
    if (subscriptions.length > 1) errors.push("v1 \u6BCF\u63D2\u4EF6\u81F3\u591A\u4E00\u4E2A subscription provider");
    for (const subscription of subscriptions) {
      if (!isObject(subscription)) {
        errors.push("subscription \u987B\u4E3A\u5BF9\u8C61");
        continue;
      }
      unknownKeys(errors, "subscription", subscription, ["providerId", "entry", "timeoutMs"]);
      const id = subscription.providerId;
      if (typeof id !== "string" || !/^[a-z0-9_-]{1,64}$/.test(id)) {
        errors.push(`subscription providerId '${String(id)}' \u975E\u6CD5`);
      } else if (id === RSS_PROVIDER_ID) {
        errors.push(`subscription providerId '${id}' \u4E3A\u5185\u7F6E provider \u4FDD\u7559\u5B57`);
      }
      checkEntry(errors, "subscription entry", subscription.entry, fileSet, strict);
      checkTimeout(errors, "subscription", subscription.timeoutMs);
    }
  }
  const permissions = manifest.permissions ?? [];
  if (!stringArray(permissions)) errors.push("permissions \u987B\u4E3A\u5B57\u7B26\u4E32\u6570\u7EC4");
  else {
    for (const permission of permissions) {
      if (!VALID_PERMISSIONS.includes(permission)) {
        errors.push(`\u672A\u77E5\u6743\u9650 '${permission}'\uFF0C\u5408\u6CD5\uFF1A${VALID_PERMISSIONS.join(", ")}`);
      }
    }
  }
  if (manifest.hooks !== void 0 && manifest.hooks !== null) {
    const hooks = manifest.hooks;
    if (!isObject(hooks)) errors.push("hooks \u987B\u4E3A\u5BF9\u8C61");
    else {
      unknownKeys(errors, "hooks", hooks, ["entry", "events", "match"]);
      checkEntry(errors, "hooks entry", hooks.entry, fileSet, strict);
      if (!stringArray(hooks.events) || hooks.events.length === 0) {
        errors.push("hooks.events \u4E0D\u53EF\u4E3A\u7A7A");
      } else {
        for (const event of hooks.events) {
          if (!VALID_EVENTS.includes(event)) {
            errors.push(`\u672A\u77E5\u4E8B\u4EF6 '${event}'\uFF0C\u5408\u6CD5\uFF1A${VALID_EVENTS.join(", ")}`);
          }
        }
      }
      if (hooks.match !== void 0 && hooks.match !== null) checkMatch(errors, "hooks match", hooks.match);
    }
  }
  if (manifest.auth !== void 0 && manifest.auth !== null) {
    const auth = manifest.auth;
    if (!isObject(auth)) errors.push("auth \u987B\u4E3A\u5BF9\u8C61");
    else {
      unknownKeys(errors, "auth", auth, ["entry", "timeoutMs"]);
      checkEntry(errors, "auth entry", auth.entry, fileSet, strict);
      if (!hasPermission(permissions, "auth")) errors.push("\u58F0\u660E auth.entry \u65F6 permissions \u5FC5\u987B\u5305\u542B auth");
      checkTimeout(errors, "auth", auth.timeoutMs);
    }
  }
  if (manifest.interceptors !== void 0 && manifest.interceptors !== null) {
    const ic = manifest.interceptors;
    if (!isObject(ic)) errors.push("interceptors \u987B\u4E3A\u5BF9\u8C61");
    else {
      unknownKeys(errors, "interceptors", ic, ["entry", "stages", "match", "timeoutMs", "onFailure"]);
      checkEntry(errors, "interceptors entry", ic.entry, fileSet, strict);
      if (!stringArray(ic.stages) || ic.stages.length === 0) {
        errors.push("interceptors.stages \u4E0D\u53EF\u4E3A\u7A7A");
      } else {
        const seenStages = /* @__PURE__ */ new Set();
        for (const stage of ic.stages) {
          if (!VALID_INTERCEPT_STAGES.includes(stage)) {
            errors.push(`\u672A\u77E5\u62E6\u622A\u9636\u6BB5 '${stage}'\uFF0C\u5408\u6CD5\uFF1A${VALID_INTERCEPT_STAGES.join(", ")}`);
          } else if (seenStages.has(stage)) {
            errors.push(`interceptors.stages \u91CD\u590D\uFF1A'${stage}'`);
          }
          seenStages.add(stage);
        }
      }
      checkMatch(errors, "interceptors match", ic.match);
      checkTimeout(errors, "interceptors", ic.timeoutMs);
      if (ic.onFailure !== void 0 && ic.onFailure !== null && ic.onFailure !== "continue" && ic.onFailure !== "fail") {
        errors.push("interceptors.onFailure \u987B\u4E3A continue \u6216 fail");
      }
      if (!hasPermission(permissions, "intercept")) {
        errors.push("\u58F0\u660E interceptors \u65F6 permissions \u5FC5\u987B\u5305\u542B intercept");
      }
    }
  }
  checkMain(errors, manifest, fileSet, permissions);
  checkContributes(errors, manifest, fileSet, permissions);
  const settings = manifest.settings ?? [];
  if (!Array.isArray(settings)) errors.push("settings \u987B\u4E3A\u6570\u7EC4");
  else {
    const seen = /* @__PURE__ */ new Set();
    for (const field of settings) checkSetting(errors, field, seen);
  }
  return { ok: errors.length === 0, errors };
}
function riskOf(manifest) {
  const permissions = manifest.permissions ?? [];
  if (permissions.includes("desktop") || permissions.includes("pageScripts")) return "full";
  const elevated = ["ffmpeg", "ytdlp", "auth", "tasks", "browserRules", "background", "intercept", "archive"];
  return permissions.some((p) => elevated.includes(p)) ? "elevated" : "standard";
}
function networkHostsOf(manifest) {
  const hosts = /* @__PURE__ */ new Set();
  for (const host of manifest.main?.imageHosts ?? []) hosts.add(host);
  for (const view of manifest.contributes?.views ?? []) {
    for (const host of view.desktop?.networkHosts ?? []) hosts.add(host);
  }
  const updateUrl = manifest.contributes?.archiveRules?.updateUrl;
  if (updateUrl) {
    try {
      hosts.add(new URL(updateUrl).hostname);
    } catch {
    }
  }
  return [...hosts].sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
}
function packageFilesOf(manifest) {
  const files = [];
  const main = manifest.main;
  if (isObject(main) && typeof main.entry === "string") files.push(main.entry);
  const contributes = manifest.contributes;
  if (isObject(contributes)) {
    if (Array.isArray(contributes.views)) {
      for (const view of contributes.views) {
        if (isObject(view) && isObject(view.desktop) && typeof view.desktop.entry === "string") {
          files.push(view.desktop.entry);
        }
      }
      for (const view of contributes.views) {
        if (isObject(view) && typeof view.icon === "string") files.push(view.icon);
      }
    }
    if (typeof contributes.sniffRules === "string") files.push(contributes.sniffRules);
    if (Array.isArray(contributes.pageScripts)) {
      for (const script of contributes.pageScripts) {
        if (isObject(script) && Array.isArray(script.js)) {
          for (const file of script.js) if (typeof file === "string") files.push(file);
        }
      }
    }
    if (typeof contributes.archive === "string") files.push(contributes.archive);
    if (isObject(contributes.archiveRules) && typeof contributes.archiveRules.entry === "string") {
      files.push(contributes.archiveRules.entry);
    }
  }
  return files;
}
function validateSniffPack(content) {
  const errors = [];
  const size = typeof content === "string" ? utf8Length(content) : content.byteLength;
  if (size > SNIFF_PACK_MAX_BYTES) {
    errors.push(`sniffRules \u6587\u4EF6\u8D85\u8FC7 ${SNIFF_PACK_MAX_BYTES} \u5B57\u8282`);
    return { ok: false, errors };
  }
  const text = typeof content === "string" ? content : new TextDecoder().decode(content);
  let pack;
  try {
    pack = JSON.parse(text);
  } catch (err) {
    errors.push(`sniffRules JSON \u89E3\u6790\u5931\u8D25: ${err.message}`);
    return { ok: false, errors };
  }
  if (!isObject(pack) || pack.format !== SNIFF_PACK_FORMAT) {
    errors.push(`sniffRules format \u987B\u4E3A ${SNIFF_PACK_FORMAT}`);
  } else if (!Array.isArray(pack.rules)) {
    errors.push("sniffRules rules \u987B\u4E3A\u6570\u7EC4");
  } else if (pack.rules.length > SNIFF_PACK_MAX_RULES) {
    errors.push(`sniffRules \u81F3\u591A ${SNIFF_PACK_MAX_RULES} \u6761\u89C4\u5219`);
  }
  return { ok: errors.length === 0, errors };
}
var ARCHIVE_RULES_MAX_BYTES = 512 * 1024;
function validateArchiveRulesPack(content) {
  const errors = [];
  const size = typeof content === "string" ? utf8Length(content) : content.byteLength;
  if (size > ARCHIVE_RULES_MAX_BYTES) return { ok: false, errors: [`archiveRules \u6587\u4EF6\u8D85\u8FC7 ${ARCHIVE_RULES_MAX_BYTES} \u5B57\u8282`] };
  let envelope;
  try {
    envelope = JSON.parse(typeof content === "string" ? content : new TextDecoder("utf-8", { fatal: true }).decode(content));
  } catch (err) {
    return { ok: false, errors: [`archiveRules JSON \u89E3\u6790\u5931\u8D25: ${err.message}`] };
  }
  if (!isObject(envelope) || Object.keys(envelope).sort().join(",") !== "payload,signature" || typeof envelope.payload !== "string" || typeof envelope.signature !== "string" || !/^[0-9a-fA-F]{128}$/.test(envelope.signature)) {
    return { ok: false, errors: ["archiveRules \u987B\u4E3A\u5305\u542B payload \u4E0E 128 \u4F4D\u5341\u516D\u8FDB\u5236 signature \u7684 JSON envelope"] };
  }
  let payload;
  try {
    payload = JSON.parse(envelope.payload);
  } catch (err) {
    return { ok: false, errors: [`archiveRules payload JSON \u89E3\u6790\u5931\u8D25: ${err.message}`] };
  }
  if (!isObject(payload)) return { ok: false, errors: ["archiveRules payload \u987B\u4E3A\u5BF9\u8C61"] };
  unknownKeys(errors, "archiveRules payload", payload, ["format", "schemaVersion", "sequence", "rules"]);
  if (payload.format !== "fluxdown-archive-rules" || payload.schemaVersion !== 1 || !Number.isSafeInteger(payload.sequence) || payload.sequence < 1 || !Array.isArray(payload.rules) || payload.rules.length < 1 || payload.rules.length > 500) {
    errors.push("archiveRules payload \u683C\u5F0F\u3001schemaVersion\u3001sequence \u6216 rules \u65E0\u6548");
  } else {
    const seen = /* @__PURE__ */ new Set();
    for (const rule of payload.rules) {
      if (!isObject(rule)) {
        errors.push("archiveRules rule \u987B\u4E3A\u5BF9\u8C61");
        continue;
      }
      unknownKeys(errors, "archiveRules rule", rule, ["id", "folderName", "match"]);
      if (typeof rule.id !== "string" || !/^[a-z0-9_-]{1,64}$/.test(rule.id) || seen.has(rule.id)) errors.push("archiveRules rule id \u65E0\u6548\u6216\u91CD\u590D");
      if (typeof rule.id === "string") seen.add(rule.id);
      if (typeof rule.folderName !== "string" || rule.folderName.length < 1 || utf8Length(rule.folderName) > 180 || /[\/\\:\u0000-\u001f\u007f]/.test(rule.folderName) || rule.folderName === "." || rule.folderName === "..") {
        errors.push("archiveRules folderName \u975E\u6CD5");
      }
      if (!isObject(rule.match)) {
        errors.push("archiveRules match \u987B\u4E3A\u5BF9\u8C61");
        continue;
      }
      const matcher = rule.match;
      unknownKeys(errors, "archiveRules match", matcher, ["fileName", "extensions", "metadata", "headerHex"]);
      if (Object.keys(matcher).length === 0) errors.push("archiveRules match \u81F3\u5C11\u9700\u8981\u4E00\u4E2A\u6761\u4EF6");
      if (matcher.fileName !== void 0 && (typeof matcher.fileName !== "string" || !/^[\x00-\x7f]{1,256}$/.test(matcher.fileName))) errors.push("archiveRules fileName glob \u65E0\u6548");
      if (matcher.extensions !== void 0 && (!Array.isArray(matcher.extensions) || matcher.extensions.length < 1 || matcher.extensions.length > 64 || matcher.extensions.some((ext) => typeof ext !== "string" || !/^[a-zA-Z0-9]{1,32}$/.test(ext)))) errors.push("archiveRules extensions \u65E0\u6548");
      if (matcher.headerHex !== void 0 && (typeof matcher.headerHex !== "string" || !/^(?:[0-9a-fA-F]{2}){1,4096}$/.test(matcher.headerHex))) errors.push("archiveRules headerHex \u65E0\u6548");
      if (matcher.metadata !== void 0) {
        const allowed = ["platform", "mediaKind", "creatorId", "creatorName", "seriesId", "seriesTitle", "collectionId", "collectionTitle"];
        if (!isObject(matcher.metadata)) errors.push("archiveRules metadata \u987B\u4E3A\u5BF9\u8C61");
        else {
          unknownKeys(errors, "archiveRules metadata", matcher.metadata, allowed);
          if (Object.keys(matcher.metadata).length === 0 || Object.values(matcher.metadata).some((v) => typeof v !== "string" || v.length === 0 || utf8Length(v) > 256)) errors.push("archiveRules metadata predicates \u65E0\u6548");
        }
      }
    }
  }
  return { ok: errors.length === 0, errors };
}
function validateViewIcon(viewId, content) {
  const size = typeof content === "string" ? utf8Length(content) : content.byteLength;
  if (size > VIEW_ICON_MAX_BYTES) {
    return { ok: false, errors: [`view '${viewId}' icon \u8D85\u8FC7 ${VIEW_ICON_MAX_BYTES} \u5B57\u8282`] };
  }
  let text;
  if (typeof content === "string") text = content;
  else {
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(content);
    } catch {
      return { ok: false, errors: [`view '${viewId}' icon \u4E0D\u662F\u5408\u6CD5 UTF-8`] };
    }
  }
  const head = text.replace(/^\uFEFF/, "").trim().toLowerCase();
  if (!((head.startsWith("<svg") || head.startsWith("<?xml")) && head.includes("<svg"))) {
    return { ok: false, errors: [`view '${viewId}' icon \u4E0D\u662F SVG \u6587\u6863`] };
  }
  return { ok: true, errors: [] };
}
function validatePageScriptFiles(script, read) {
  const errors = [];
  const id = String(script.id);
  const js = Array.isArray(script.js) ? script.js : [];
  let code = "";
  let total = 0;
  for (let i = 0; i < js.length; i++) {
    const file = js[i];
    if (typeof file !== "string") return { ok: false, errors: [`pageScript '${id}' js \u8DEF\u5F84\u975E\u6CD5`] };
    const content = read(file);
    if (content === void 0) {
      errors.push(`pageScript '${id}' \u8BFB\u53D6 '${file}' \u5931\u8D25`);
      return { ok: false, errors };
    }
    const size = typeof content === "string" ? utf8Length(content) : content.byteLength;
    if (size > PAGE_SCRIPT_FILE_MAX_BYTES) {
      errors.push(`pageScript '${id}' \u6587\u4EF6 '${file}' \u8D85\u8FC7 ${PAGE_SCRIPT_FILE_MAX_BYTES} \u5B57\u8282`);
      return { ok: false, errors };
    }
    let text;
    if (typeof content === "string") text = content;
    else {
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(content);
      } catch {
        errors.push(`pageScript '${id}' \u6587\u4EF6 '${file}' \u4E0D\u662F\u5408\u6CD5 UTF-8`);
        return { ok: false, errors };
      }
    }
    if (i > 0) {
      code += "\n;\n";
      total += 3;
    }
    code += text;
    total += size;
    if (total > PAGE_SCRIPT_MAX_BYTES) {
      errors.push(`pageScript '${id}' \u62FC\u63A5\u540E\u8D85\u8FC7 ${PAGE_SCRIPT_MAX_BYTES} \u5B57\u8282`);
      return { ok: false, errors };
    }
  }
  return { ok: true, errors, code };
}
function validatePackage(manifest, files) {
  const errors = [...validateManifest(manifest, new Set(files.keys()), { strict: true }).errors];
  if (files.size > PACKAGE_MAX_ENTRIES) errors.push(`\u5305\u5185\u6587\u4EF6\u6570 ${files.size} \u8D85\u8FC7\u4E0A\u9650 ${PACKAGE_MAX_ENTRIES}`);
  let total = 0;
  for (const content of files.values()) total += typeof content === "string" ? utf8Length(content) : content.byteLength;
  if (total > PACKAGE_MAX_UNCOMPRESSED_BYTES) errors.push(`\u5305\u89E3\u538B\u603B\u91CF ${total} \u5B57\u8282\u8D85\u8FC7\u4E0A\u9650 ${PACKAGE_MAX_UNCOMPRESSED_BYTES}`);
  const read = (path) => files.get(path.replaceAll("\\", "/"));
  const contributes = isObject(manifest) && isObject(manifest.contributes) ? manifest.contributes : null;
  if (contributes === null) return { ok: errors.length === 0, errors };
  const rules = typeof contributes.sniffRules === "string" ? read(contributes.sniffRules) : void 0;
  if (rules !== void 0) errors.push(...validateSniffPack(rules).errors);
  const archiveRules = isObject(contributes.archiveRules) && typeof contributes.archiveRules.entry === "string" ? read(contributes.archiveRules.entry) : void 0;
  if (archiveRules !== void 0) errors.push(...validateArchiveRulesPack(archiveRules).errors);
  for (const view of Array.isArray(contributes.views) ? contributes.views : []) {
    const icon = isObject(view) && typeof view.icon === "string" ? read(view.icon) : void 0;
    if (icon !== void 0) errors.push(...validateViewIcon(String(view.id), icon).errors);
  }
  for (const script of Array.isArray(contributes.pageScripts) ? contributes.pageScripts : []) {
    if (!isObject(script) || !Array.isArray(script.js)) continue;
    if (!script.js.every((file) => typeof file === "string" && read(file) !== void 0)) continue;
    errors.push(...validatePageScriptFiles(script, read).errors);
  }
  return { ok: errors.length === 0, errors };
}
var sortedUnique = (values) => [...new Set(values)].sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
var matchUrls = (decl) => isObject(decl) && isObject(decl.match) && stringArray(decl.match.urls) ? decl.match.urls : [];
function reviewOf(manifest) {
  const contributes = isObject(manifest.contributes) ? manifest.contributes : {};
  const resolvers = Array.isArray(manifest.resolvers) ? manifest.resolvers : [];
  const pageScripts = Array.isArray(contributes.pageScripts) ? contributes.pageScripts : [];
  return {
    permissions: stringArray(manifest.permissions) ? [...manifest.permissions] : [],
    risk: riskOf(manifest),
    archiveEntry: typeof contributes.archive === "string" ? contributes.archive : null,
    networkHosts: networkHostsOf(manifest),
    downloadUrls: sortedUnique([...resolvers.flatMap(matchUrls), ...matchUrls(manifest.hooks), ...matchUrls(manifest.interceptors)]),
    pageScriptMatches: sortedUnique(pageScripts.flatMap((s) => isObject(s) && stringArray(s.matches) ? s.matches : []))
  };
}
export {
  COMMANDS_MAX,
  NETWORK_HOSTS_MAX,
  PACKAGE_MAX_BYTES,
  PACKAGE_MAX_ENTRIES,
  PACKAGE_MAX_UNCOMPRESSED_BYTES,
  PAGE_SCRIPTS_MAX,
  PAGE_SCRIPT_FILE_MAX_BYTES,
  PAGE_SCRIPT_JS_MAX,
  PAGE_SCRIPT_MATCHES_MAX,
  PAGE_SCRIPT_MAX_BYTES,
  SNIFF_PACK_FORMAT,
  SNIFF_PACK_MAX_BYTES,
  SNIFF_PACK_MAX_RULES,
  TITLE_MAX_CHARS,
  VALID_EVENTS,
  VALID_INTERCEPT_STAGES,
  VALID_PERMISSIONS,
  VIEWS_MAX,
  VIEW_ICON_MAX_BYTES,
  VIEW_LOCATIONS,
  WINDOW_SIZE_MAX,
  WINDOW_SIZE_MIN,
  isSafeRelativePath,
  isValidIdentity,
  isValidMatchPattern,
  isValidNetworkHost,
  networkHostsOf,
  packageFilesOf,
  reviewOf,
  riskOf,
  validateArchiveRulesPack,
  validateManifest,
  validatePackage,
  validatePageScriptFiles,
  validateSniffPack,
  validateViewIcon
};
