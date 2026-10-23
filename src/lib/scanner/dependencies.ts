import type { PackageRef, Severity } from "../types";
import { errorMessage, snippetOf, splitLines, type Archive, type RawFinding, type ScannerResult, type SourceFile } from "./archive";

/**
 * Software composition analysis: manifests en lockfiles parsen naar PackageRef[],
 * daarna kwetsbaarheden opvragen bij OSV.dev (querybatch + details per advisory).
 */

type Ecosystem = PackageRef["ecosystem"];

const OSV = "https://api.osv.dev/v1";
/** OSV staat max. 1000 queries per querybatch toe. */
const BATCH_SIZE = 500;
/** Max. aantal vervolgpagina's (next_page_token) per batch. */
const MAX_PAGES = 5;
const MAX_DETAILS = 200;
const CONCURRENCY = 16;
const BATCH_TIMEOUT = 15000;
const VULN_TIMEOUT = 8000;
const BUDGET_MS = 30000;

const isRecord = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);
const str = (x: unknown): string | undefined => (typeof x === "string" ? x : undefined);

export function normalisePyName(name: string): string {
  return name.trim().toLowerCase().replace(/[-_.]+/g, "-");
}

const EXACT = /^\d+(?:\.\d+)*(?:[-+.]?[0-9A-Za-z.-]+)?$/;

/* ------------------------------------------------------------------ parsers */

interface Collector {
  add(ecosystem: Ecosystem, name: string, version: string, source: string, approximate?: boolean): void;
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function parsePackageLock(f: SourceFile, c: Collector) {
  const lock = parseJson(f.text ?? "");
  if (!isRecord(lock)) return;
  if (isRecord(lock.packages)) {
    for (const [key, entry] of Object.entries(lock.packages)) {
      if (key === "" || !isRecord(entry) || entry.link === true) continue;
      const i = key.lastIndexOf("node_modules/");
      // Sleutels zonder node_modules/ zijn workspace-pakketten van het project zelf, niet uit de registry
      if (i < 0) continue;
      const name = str(entry.name) ?? key.slice(i + "node_modules/".length);
      const version = str(entry.version);
      if (version && EXACT.test(version)) c.add("npm", name, version, f.path);
    }
    return;
  }
  const walk = (deps: unknown) => {
    if (!isRecord(deps)) return;
    for (const [name, entry] of Object.entries(deps)) {
      if (!isRecord(entry)) continue;
      const version = str(entry.version);
      if (version && EXACT.test(version)) c.add("npm", name, version, f.path);
      walk(entry.dependencies);
    }
  };
  walk(lock.dependencies);
}

/** Minimale versie uit een npm-range halen (^1.2.3 → 1.2.3). */
function rangeFloor(range: string): string | undefined {
  const r = range.trim();
  if (!r || /^(?:workspace:|file:|link:|git|https?:|github:|npm:|portal:|catalog:|\*|latest|next|x$)/i.test(r)) return undefined;
  const alt = r.split("||")[0].trim();
  // "<2.0.0" / "<=1.4" hebben geen ondergrens: de bovengrens is géén bruikbare versie om op te vragen
  if (alt.startsWith("<")) return undefined;
  const first = alt.replace(/^[\^~>=v\s]+/, "").split(/\s+/)[0];
  const m = /^(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?(-[0-9A-Za-z.-]+)?$/.exec(first);
  if (!m) return undefined;
  const num = (s: string | undefined) => (s === undefined || s === "x" || s === "*" ? "0" : s);
  return `${m[1]}.${num(m[2])}.${num(m[3])}${m[4] ?? ""}`;
}

function parsePackageJson(f: SourceFile, c: Collector) {
  const pkg = parseJson(f.text ?? "");
  if (!isRecord(pkg)) return;
  for (const field of ["dependencies", "devDependencies", "optionalDependencies"]) {
    const deps = pkg[field];
    if (!isRecord(deps)) continue;
    for (const [name, spec] of Object.entries(deps)) {
      const v = typeof spec === "string" ? rangeFloor(spec) : undefined;
      if (v) c.add("npm", name, v, f.path, true);
    }
  }
}

/**
 * Pakketnaam uit een yarn-descriptor ("@scope/pkg@^1.0.0", Berry: "pkg@npm:^1.0.0", alias "x@npm:real@^1").
 * Workspace-, patch-, link- en git-descriptors leveren geen registry-pakket op.
 */
function yarnName(descriptor: string): string | undefined {
  const s = descriptor.trim().replace(/^"|"$/g, "");
  const at = s.indexOf("@", 1);
  if (at <= 0) return undefined;
  const name = s.slice(0, at);
  const range = s.slice(at + 1);
  if (/^(?:workspace|patch|link|portal|file|git|git\+\w+|github|https?|exec):/i.test(range)) return undefined;
  const alias = /^npm:((?:@[^/@\s]+\/)?[^@\s]+)@/.exec(range);
  return alias ? alias[1] : name;
}

function parseYarnLock(f: SourceFile, c: Collector) {
  let names: string[] = [];
  for (const line of splitLines(f.text ?? "")) {
    if (/^\S.*:\s*$/.test(line) && !line.startsWith("#")) {
      names = line
        .replace(/:\s*$/, "")
        .split(",")
        .map(yarnName)
        .filter((s): s is string => s !== undefined && s !== "" && !s.includes(" "));
      continue;
    }
    const m = /^\s+version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (m && names.length) {
      for (const n of Array.from(new Set(names))) if (EXACT.test(m[1])) c.add("npm", n, m[1], f.path);
      names = [];
    }
  }
}

function parsePnpmLock(f: SourceFile, c: Collector) {
  let inPackages = false;
  for (const line of splitLines(f.text ?? "")) {
    if (/^\S/.test(line)) inPackages = /^(?:packages|snapshots):\s*$/.test(line);
    if (!inPackages) continue;
    // v5: /name/1.2.3_peer@x, v6: /name@1.2.3(peer@x), v9: 'name@1.2.3'
    const m = /^ {2}['"]?\/?((?:@[^/\s'"]+\/)?[^@/\s'"(]+)[@/](\d[^:'"\s(_]*)/.exec(line);
    if (m && EXACT.test(m[2])) c.add("npm", m[1], m[2], f.path);
  }
}

/** bun.lock (tekst, JSONC): "pkg": ["pkg@1.2.3", "", {...}, "sha512-…"]. */
function parseBunLock(f: SourceFile, c: Collector) {
  for (const m of (f.text ?? "").matchAll(/^\s*"[^"]+":\s*\[\s*"((?:@[^@"/\s]+\/)?[^@"\s]+)@([^"\s]+)"/gm)) {
    if (EXACT.test(m[2])) c.add("npm", m[1], m[2], f.path);
  }
}

function parseRequirements(f: SourceFile, c: Collector, unpinned: Map<string, string[]>) {
  const loose: string[] = [];
  for (const raw of splitLines(f.text ?? "")) {
    const line = raw.replace(/\s+#.*$/, "").split(";")[0].trim();
    if (!line || line.startsWith("#") || line.startsWith("-") || /^(?:git\+|https?:|file:|\.|\/)/.test(line) || line.includes(" @ ")) continue;
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(===?|~=|>=|<=|!=|>|<)?\s*([^\s,]+)?/.exec(line);
    if (!m) continue;
    const name = normalisePyName(m[1]);
    if ((m[2] === "==" || m[2] === "===") && m[3] && !m[3].includes("*")) c.add("PyPI", name, m[3], f.path);
    else loose.push(name);
  }
  if (loose.length) unpinned.set(f.path, loose);
}

function parsePipfileLock(f: SourceFile, c: Collector) {
  const lock = parseJson(f.text ?? "");
  if (!isRecord(lock)) return;
  for (const section of ["default", "develop"]) {
    const deps = lock[section];
    if (!isRecord(deps)) continue;
    for (const [name, entry] of Object.entries(deps)) {
      const v = isRecord(entry) ? str(entry.version) : undefined;
      if (v && v.startsWith("==")) c.add("PyPI", normalisePyName(name), v.slice(2), f.path);
    }
  }
}

/** [[package]]-blokken van poetry.lock / Cargo.lock / uv.lock. */
function parseTomlPackages(f: SourceFile, c: Collector, ecosystem: Ecosystem) {
  let cur: { name?: string; version?: string; source?: string; local?: boolean } | null = null;
  const flush = () => {
    if (!cur || !cur.name || !cur.version || cur.local) return;
    if (ecosystem === "crates.io" && !(cur.source ?? "").startsWith("registry+")) return; // lokale crates
    c.add(ecosystem, ecosystem === "PyPI" ? normalisePyName(cur.name) : cur.name, cur.version, f.path);
  };
  // 0 = buiten een pakket, 1 = in [[package]], 2 = in [package.source] (poetry)
  let section = 0;
  for (const line of splitLines(f.text ?? "")) {
    if (/^\[\[package\]\]\s*$/.test(line)) {
      flush();
      cur = {};
      section = 1;
      continue;
    }
    if (/^\[package\.source\]\s*$/.test(line)) {
      section = cur ? 2 : 0;
      continue;
    }
    if (/^\[/.test(line)) {
      section = 0;
      continue;
    }
    if (!section || !cur) continue;
    if (section === 2) {
      // poetry: lokale mappen/bestanden zijn het eigen project, geen PyPI-pakket
      const t = /^type\s*=\s*"([^"]*)"/.exec(line);
      if (t && /^(?:directory|file)$/.test(t[1])) cur.local = true;
      continue;
    }
    // uv.lock: source = { editable = "." } / { virtual = "." } / { path = "…" } is het eigen project
    if (/^source\s*=\s*\{[^}]*\b(?:editable|virtual|path|directory)\s*=/.test(line)) cur.local = true;
    const m = /^(name|version|source)\s*=\s*"([^"]*)"/.exec(line);
    if (m) {
      if (m[1] === "name") cur.name = m[2];
      else if (m[1] === "version") cur.version = m[2];
      else cur.source = m[2];
    }
  }
  flush();
}

/** Strings uit een TOML-array na `key = [` (houdt rekening met ] binnen strings, bijv. extras). */
function tomlArray(text: string, key: RegExp): string[] {
  const m = key.exec(text);
  if (!m) return [];
  const out: string[] = [];
  let quote = "";
  let buf = "";
  for (let i = m.index + m[0].length; i < text.length; i++) {
    const ch = text[i];
    if (quote) {
      if (ch === quote) {
        out.push(buf);
        buf = "";
        quote = "";
      } else buf += ch;
    } else if (ch === '"' || ch === "'") quote = ch;
    else if (ch === "]") break;
  }
  return out;
}

function parsePyproject(f: SourceFile, c: Collector) {
  for (const dep of tomlArray(f.text ?? "", /^dependencies\s*=\s*\[/m)) {
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s,;]+)/.exec(dep.trim());
    if (m && !m[2].includes("*")) c.add("PyPI", normalisePyName(m[1]), m[2], f.path);
  }
}

function parseGoMod(f: SourceFile, c: Collector) {
  let block = false;
  for (const raw of splitLines(f.text ?? "")) {
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (/^require\s*\($/.test(line)) {
      block = true;
      continue;
    }
    if (block && line === ")") {
      block = false;
      continue;
    }
    const m = (block ? /^(\S+)\s+v(\S+)$/ : /^require\s+(\S+)\s+v(\S+)$/).exec(line);
    if (m) c.add("Go", m[1], m[2].replace(/\+incompatible$/, ""), f.path);
  }
}

function xmlTag(block: string, tag: string): string | undefined {
  const m = new RegExp(`<${tag}>\\s*([^<\\s]+)\\s*</${tag}>`).exec(block);
  return m ? m[1] : undefined;
}

function parsePom(f: SourceFile, c: Collector) {
  const text = (f.text ?? "").replace(/<!--[\s\S]*?-->/g, "");
  // ${spring.version}-achtige versies oplossen via <properties> in dezelfde pom
  const props = new Map<string, string>();
  for (const block of text.matchAll(/<properties>([\s\S]*?)<\/properties>/g)) {
    for (const p of block[1].matchAll(/<([\w.-]+)>\s*([^<\s]+)\s*<\/\1>/g)) props.set(p[1], p[2]);
  }
  for (const m of text.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const g = xmlTag(m[1], "groupId");
    const a = xmlTag(m[1], "artifactId");
    const raw = xmlTag(m[1], "version");
    const v = raw?.replace(/^\$\{([^}]+)\}$/, (whole: string, key: string) => props.get(key) ?? whole);
    if (g && a && v && !v.includes("${") && /^\d/.test(v)) c.add("Maven", `${g}:${a}`, v, f.path);
  }
}

/** gradle.lockfile: group:artifact:version=configurations. */
function parseGradleLock(f: SourceFile, c: Collector) {
  for (const line of splitLines(f.text ?? "")) {
    const m = /^([\w.-]+):([\w.-]+):([^=\s]+)=/.exec(line.trim());
    if (m && /^\d/.test(m[3])) c.add("Maven", `${m[1]}:${m[2]}`, m[3], f.path);
  }
}

/** Letterlijke coördinaten in build.gradle(.kts): implementation("group:artifact:1.2.3"). */
function parseGradleBuild(f: SourceFile, c: Collector) {
  const re = /\b(?:implementation|api|compile|compileOnly|runtimeOnly|testImplementation|annotationProcessor|kapt|classpath)\s*\(?\s*["']([\w.-]+):([\w.-]+):([^"'\s:@]+)["']/g;
  for (const m of (f.text ?? "").matchAll(re)) {
    const v = m[3];
    if (/^\d/.test(v) && !/[+$\[\]()]/.test(v)) c.add("Maven", `${m[1]}:${m[2]}`, v, f.path);
  }
}

/** NuGet packages.lock.json: dependencies → framework → pakket → resolved. */
function parseNugetLock(f: SourceFile, c: Collector) {
  const lock = parseJson(f.text ?? "");
  if (!isRecord(lock) || !isRecord(lock.dependencies)) return;
  for (const framework of Object.values(lock.dependencies)) {
    if (!isRecord(framework)) continue;
    for (const [name, entry] of Object.entries(framework)) {
      if (!isRecord(entry) || entry.type === "Project") continue;
      const v = str(entry.resolved);
      if (v && /^\d+(?:\.\d+)+[-.\w]*$/.test(v)) c.add("NuGet", name, v, f.path);
    }
  }
}

function parseNuget(f: SourceFile, c: Collector) {
  const text = f.text ?? "";
  for (const m of text.matchAll(/<(?:PackageReference|PackageVersion|package)\b([^>]*?)(\/>|>([\s\S]*?)<\/(?:PackageReference|PackageVersion|package)>)/gi)) {
    const attrs = m[1];
    const name = /\b(?:Include|id)\s*=\s*"([^"]+)"/i.exec(attrs);
    const ver = /\bVersion\s*=\s*"([^"]+)"/i.exec(attrs) ?? (m[3] ? /<Version>\s*([^<\s]+)\s*<\/Version>/i.exec(m[3]) : null);
    if (name && ver && /^\d+(?:\.\d+)+[-.\w]*$/.test(ver[1])) c.add("NuGet", name[1], ver[1], f.path);
  }
}

/* --------------------------------------------------------------- OSV-client */

interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}
interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  ranges?: { type?: string; events?: OsvEvent[] }[];
  ecosystem_specific?: { severity?: unknown };
  database_specific?: { severity?: unknown };
}
interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: { type?: string; score?: string }[];
  affected?: OsvAffected[];
  database_specific?: { severity?: unknown; cwe_ids?: unknown };
}
interface OsvBatch {
  results?: unknown[];
}

class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const TIME_LIMIT = "scan time limit reached";
const STOPPED_EARLY = "The dependency check stopped early because the scan time limit was reached; results may be incomplete.";

/** fetch met eigen timeout; `outer` (de scan-deadline) breekt lopende requests ook af. */
async function fetchJson<T>(url: string, init: RequestInit, ms: number, outer?: AbortSignal): Promise<T> {
  if (ms < 200 || outer?.aborted) throw new Error(TIME_LIMIT);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  const onAbort = () => ctrl.abort();
  outer?.addEventListener("abort", onAbort);
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal, headers: { "content-type": "application/json", accept: "application/json" } });
    if (!res.ok) throw new HttpError(res.status, `HTTP ${res.status} from ${new URL(url).host}`);
    return (await res.json()) as T;
  } catch (e) {
    if (outer?.aborted) throw new Error(TIME_LIMIT);
    if (ctrl.signal.aborted) throw new Error(`no response within ${Math.round(ms / 1000)} s`);
    throw e;
  } finally {
    clearTimeout(timer);
    outer?.removeEventListener("abort", onAbort);
  }
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/** fetchJson met retries bij rate limiting (429), 5xx en netwerkfouten, binnen de deadline. */
async function fetchJsonRetry<T>(url: string, init: RequestInit, timeout: number, deadline: number, outer?: AbortSignal, attempts = 3): Promise<T> {
  let last: unknown = new Error(TIME_LIMIT);
  for (let a = 0; a < attempts; a++) {
    if (a > 0) {
      const wait = Math.min(1000 * 2 ** (a - 1), deadline - Date.now() - 2000);
      if (wait < 0 || outer?.aborted) break;
      await sleep(wait);
    }
    try {
      return await fetchJson<T>(url, init, Math.min(timeout, deadline - Date.now()), outer);
    } catch (e) {
      last = e;
      if (e instanceof HttpError && e.status !== 429 && e.status < 500) break;
    }
  }
  throw last instanceof Error ? last : new Error(String(last));
}

/* ------------------------------------------------------------- versies/CVSS */

function tokens(v: string): (number | string)[] {
  const parts: string[] = v.replace(/^v/i, "").match(/\d+|[A-Za-z]+/g) ?? [];
  return parts.map((t) => (/^\d+$/.test(t) ? Number(t) : t.toLowerCase()));
}

/** Tolerante versievergelijking (semver, PEP 440, Maven) — goed genoeg om een fix-versie te kiezen. */
export function compareVersions(a: string, b: string): number {
  const x = tokens(a);
  const y = tokens(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const p = x[i];
    const q = y[i];
    if (p === q) continue;
    if (p === undefined) return typeof q === "string" ? 1 : q === 0 ? 0 : -1;
    if (q === undefined) return typeof p === "string" ? -1 : p === 0 ? 0 : 1;
    if (typeof p === "number" && typeof q === "number") return p - q;
    if (typeof p === "number") return 1;
    if (typeof q === "number") return -1;
    return p < q ? -1 : 1;
  }
  return 0;
}

const roundUp = (x: number) => {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
};

/** CVSS 3.x base score volgens de officiële 3.1-formule. v4-vectoren worden benaderd met dezelfde formule. */
export function cvssBaseScore(vector: string): number | undefined {
  const parts = new Map<string, string>();
  for (const p of vector.split("/")) {
    const [k, v] = p.split(":");
    if (k && v) parts.set(k, v);
  }
  const v4 = vector.startsWith("CVSS:4");
  const get = (k: string) => parts.get(k);
  const scope = v4 ? "U" : get("S");
  const changed = scope === "C";
  const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const AC: Record<string, number> = { L: 0.77, H: 0.44 };
  const PR: Record<string, number> = changed ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 };
  const UI: Record<string, number> = { N: 0.85, R: 0.62, P: 0.62, A: 0.62 };
  const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };
  const av = AV[get("AV") ?? ""];
  const ac = AC[get("AC") ?? ""];
  const pr = PR[get("PR") ?? ""];
  const ui = UI[get("UI") ?? ""];
  const c = CIA[get(v4 ? "VC" : "C") ?? ""];
  const i = CIA[get(v4 ? "VI" : "I") ?? ""];
  const a = CIA[get(v4 ? "VA" : "A") ?? ""];
  if ([av, ac, pr, ui, c, i, a].some((n) => n === undefined)) return undefined;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploitability = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  return changed ? roundUp(Math.min(1.08 * (impact + exploitability), 10)) : roundUp(Math.min(impact + exploitability, 10));
}

function severityFromLabel(x: unknown): Severity | undefined {
  if (typeof x !== "string") return undefined;
  switch (x.toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MODERATE":
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return undefined;
  }
}

function severityFromScore(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

function vulnSeverity(v: OsvVuln): Severity | undefined {
  const label = severityFromLabel(v.database_specific?.severity);
  if (label) return label;
  let best: number | undefined;
  for (const s of v.severity ?? []) {
    const raw = (s.score ?? "").trim();
    const n = /^\d+(?:\.\d+)?$/.test(raw) ? Number(raw) : raw.startsWith("CVSS:3") || raw.startsWith("CVSS:4") ? cvssBaseScore(raw) : undefined;
    if (n !== undefined && (best === undefined || n > best || (s.type ?? "").startsWith("CVSS_V3"))) best = n;
  }
  if (best !== undefined) return severityFromScore(best);
  for (const a of v.affected ?? []) {
    const s = severityFromLabel(a.ecosystem_specific?.severity) ?? severityFromLabel(a.database_specific?.severity);
    if (s) return s;
  }
  return undefined;
}

function samePackage(pkg: PackageRef, a: OsvAffected): boolean {
  const name = a.package?.name;
  if (!name || a.package?.ecosystem !== pkg.ecosystem) return false;
  return pkg.ecosystem === "PyPI" ? normalisePyName(name) === pkg.name : name.toLowerCase() === pkg.name.toLowerCase();
}

/** Laagste fix-versie van de range waarin de gebruikte versie valt. */
function fixedVersion(v: OsvVuln, pkg: PackageRef): string | undefined {
  const inRange: string[] = [];
  const all: string[] = [];
  for (const a of v.affected ?? []) {
    if (!samePackage(pkg, a)) continue;
    for (const r of a.ranges ?? []) {
      if (r.type === "GIT") continue;
      let introduced: string | undefined;
      for (const ev of r.events ?? []) {
        if (ev.introduced !== undefined) introduced = ev.introduced;
        else if (ev.fixed !== undefined) {
          all.push(ev.fixed);
          const after = !introduced || introduced === "0" || compareVersions(pkg.version, introduced) >= 0;
          if (after && compareVersions(pkg.version, ev.fixed) < 0) inRange.push(ev.fixed);
        }
      }
    }
  }
  const pick = inRange.length ? inRange : all.filter((f) => compareVersions(f, pkg.version) > 0);
  return pick.sort(compareVersions)[0];
}

const ID_PRIORITY = ["GHSA-", "CVE-", "PYSEC-", "GO-", "RUSTSEC-", "OSV-"];
const idRank = (id: string) => {
  const i = ID_PRIORITY.findIndex((p) => id.startsWith(p));
  return i < 0 ? ID_PRIORITY.length : i;
};

function cleanText(md: string): string {
  return md
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/[#*_`>]+/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function clip(s: string, n: number): string {
  if (s.length <= n) return s;
  const cut = s.slice(0, n);
  const dot = cut.lastIndexOf(". ");
  return dot > n * 0.6 ? cut.slice(0, dot + 1) : `${cut.trimEnd()}…`;
}

function lineOf(file: SourceFile | undefined, pkg: PackageRef): number | undefined {
  if (!file?.text) return undefined;
  const needle = (file.name === "package-lock.json" ? `"node_modules/${pkg.name}"` : pkg.ecosystem === "Maven" ? (pkg.name.split(":")[1] ?? pkg.name) : pkg.name).toLowerCase();
  const lines = splitLines(file.text);
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i].toLowerCase();
    if (pkg.ecosystem === "PyPI" ? normalisePyName(l.split(/[=<>~!\s\[;]/)[0] ?? "") === pkg.name : l.includes(needle)) return i + 1;
  }
  return undefined;
}

/* --------------------------------------------------------------------- scan */

export interface DependencyResult extends ScannerResult {
  packages: PackageRef[];
}

/** npm-lockfiles die we kunnen parsen; bun.lockb is binair en telt alleen als "er is een lockfile". */
const LOCK_NPM_PARSED = new Set(["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"]);
const LOCK_NPM = new Set([...Array.from(LOCK_NPM_PARSED), "bun.lockb"]);
const LOCK_PY = new Set(["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock"]);
const ALL_LOCKS = new Set([...Array.from(LOCK_NPM), ...Array.from(LOCK_PY), "Cargo.lock", "packages.lock.json", "gradle.lockfile"]);

/** Ecosysteem-specifieke upgrade-instructie die een niet-security-ontwikkelaar direct kan uitvoeren. */
function upgradeAdvice(pkg: PackageRef, fixed: string): string {
  const n = pkg.name;
  switch (pkg.ecosystem) {
    case "npm":
      return `Upgrade ${n} to ${fixed} or later: run npm install ${n}@^${fixed} if it is a direct dependency. If it is pulled in by another package, upgrade that parent package, or force the version with "overrides" (npm) / "resolutions" (yarn) / "pnpm.overrides" in package.json. Then commit the updated lockfile.`;
    case "PyPI":
      return `Upgrade ${n} to ${fixed} or later: change the requirement to ${n}>=${fixed} (or ${n}==${fixed} when pinning) in requirements.txt / pyproject.toml, regenerate the lockfile (pip-compile, poetry lock or uv lock) and reinstall.`;
    case "Maven": {
      const artifact = n.split(":")[1] ?? n;
      return `Upgrade ${n} to ${fixed} or later: set <version>${fixed}</version> for ${artifact} in pom.xml (or build.gradle). If it is a transitive dependency, pin the version in <dependencyManagement> (Gradle: a constraints block).`;
    }
    case "NuGet":
      return `Upgrade ${n} to ${fixed} or later: run dotnet add package ${n} --version ${fixed} (or set Version="${fixed}" on the PackageReference / PackageVersion).`;
    case "Go":
      return `Upgrade ${n} to ${fixed} or later: run go get ${n}@v${fixed.replace(/^v/, "")} followed by go mod tidy.`;
    default:
      return `Upgrade ${n} to ${fixed} or later: run cargo update -p ${n} --precise ${fixed}, or raise the version requirement in Cargo.toml.`;
  }
}

/**
 * @param deadline optionele absolute deadline (epoch ms) van de hele scan. De effectieve deadline is
 * het vroegste van deze waarde en het eigen budget; lopende requests worden dan afgebroken en het
 * resultaat krijgt status "error" met een notitie dat de controle vroegtijdig stopte.
 */
export async function scanDependencies(archive: Archive, deadline?: number): Promise<DependencyResult> {
  const started = Date.now();
  const effective = Math.min(started + BUDGET_MS, deadline ?? Infinity);
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), Math.max(0, effective - started));
  try {
    return await runDependencyScan(archive, effective, abort.signal);
  } finally {
    clearTimeout(timer);
  }
}

async function runDependencyScan(archive: Archive, deadline: number, signal: AbortSignal): Promise<DependencyResult> {
  const packages: PackageRef[] = [];
  const seen = new Map<string, PackageRef>();
  const collector: Collector = {
    add(ecosystem, name, version, source, approximate) {
      const key = `${ecosystem}|${name}|${version}`;
      if (!name || !version) return;
      const existing = seen.get(key);
      if (existing) {
        // Een exacte versie uit een lockfile wint van dezelfde versie afgeleid uit een range
        if (existing.approximate && !approximate) {
          delete existing.approximate;
          existing.source = source;
        }
        return;
      }
      const ref: PackageRef = approximate ? { ecosystem, name, version, approximate: true, source } : { ecosystem, name, version, source };
      seen.set(key, ref);
      packages.push(ref);
    },
  };

  const findings: RawFinding[] = [];
  const notes: string[] = [];
  const unpinned = new Map<string, string[]>();
  const present = new Map<string, Set<string>>();
  const readable = new Map<string, Set<string>>();
  for (const f of archive.files) {
    const all = present.get(f.dir) ?? new Set<string>();
    all.add(f.name);
    present.set(f.dir, all);
    if (f.text === undefined) continue;
    const ok = readable.get(f.dir) ?? new Set<string>();
    ok.add(f.name);
    readable.set(f.dir, ok);
  }
  const has = (dir: string, names: Set<string>, index: Map<string, Set<string>>) => Array.from(index.get(dir) ?? []).some((n) => names.has(n));
  /** Lockfile in deze map of een bovenliggende map (workspaces/monorepos hebben één lockfile in de root). */
  const hasUp = (dir: string, names: Set<string>, index: Map<string, Set<string>>) => {
    for (let d = dir; ; d = d.includes("/") ? d.slice(0, d.lastIndexOf("/")) : "") {
      if (has(d, names, index)) return true;
      if (d === "") return false;
    }
  };
  const byPath = new Map(archive.files.map((f) => [f.path, f] as [string, SourceFile]));

  // Lockfiles die wel bestaan maar niet gelezen konden worden (te groot, binair, corrupt): melden, niet stil negeren
  const unreadLocks = archive.files.filter((f) => f.text === undefined && ALL_LOCKS.has(f.name)).map((f) => f.path);
  if (unreadLocks.length) {
    notes.push(`Lockfile(s) could not be read and were not used: ${unreadLocks.slice(0, 5).join(", ")}${unreadLocks.length > 5 ? " …" : ""}${unreadLocks.some((p) => p.endsWith("bun.lockb")) ? " (bun.lockb is a binary format; run bun install --save-text-lockfile to create bun.lock)" : ""}. Versions for those projects were inferred from the manifest where possible.`);
  }

  for (const f of archive.files) {
    if (f.text === undefined) continue;
    const n = f.name;
    const lower = n.toLowerCase();
    if (n === "package-lock.json" || n === "npm-shrinkwrap.json") parsePackageLock(f, collector);
    else if (n === "yarn.lock") parseYarnLock(f, collector);
    else if (n === "pnpm-lock.yaml") parsePnpmLock(f, collector);
    else if (n === "bun.lock") parseBunLock(f, collector);
    else if (n === "package.json") {
      if (hasUp(f.dir, LOCK_NPM_PARSED, readable)) continue;
      const before = packages.length;
      parsePackageJson(f, collector);
      const declares = packages.length > before || /"(?:dev)?[dD]ependencies"\s*:\s*\{\s*"/.test(f.text);
      if (declares && !hasUp(f.dir, LOCK_NPM, present)) findings.push(noLockfile(f, "npm", "package-lock.json (npm ci)"));
    } else if (/^requirements[^/]*\.txt$/i.test(n) || (/\.txt$/i.test(n) && /(?:^|\/)requirements$/i.test(f.dir))) parseRequirements(f, collector, unpinned);
    else if (n === "Pipfile.lock") parsePipfileLock(f, collector);
    else if (n === "poetry.lock" || n === "uv.lock" || n === "pdm.lock") parseTomlPackages(f, collector, "PyPI");
    else if (n === "pyproject.toml") {
      const declares = /^\s*dependencies\s*=\s*\[\s*["']|^\[tool\.poetry\.dependencies\]/m.test(f.text);
      if (hasUp(f.dir, LOCK_PY, readable)) continue;
      parsePyproject(f, collector);
      const hasRequirements = Array.from(present.get(f.dir) ?? []).some((x) => /^requirements[^/]*\.txt$/i.test(x));
      if (declares && !hasRequirements && !hasUp(f.dir, LOCK_PY, present)) findings.push(noLockfile(f, "PyPI", "poetry.lock / uv.lock"));
    } else if (n === "go.mod") parseGoMod(f, collector);
    else if (n === "pom.xml") parsePom(f, collector);
    else if (n === "gradle.lockfile") parseGradleLock(f, collector);
    else if (n === "build.gradle" || n === "build.gradle.kts") {
      if (!has(f.dir, new Set(["gradle.lockfile"]), readable)) parseGradleBuild(f, collector);
    } else if (n === "packages.lock.json") parseNugetLock(f, collector);
    else if (lower.endsWith(".csproj") || lower.endsWith(".fsproj") || lower.endsWith(".vbproj") || n === "packages.config" || n === "Directory.Packages.props") parseNuget(f, collector);
    else if (n === "Cargo.lock") parseTomlPackages(f, collector, "crates.io");
  }

  unpinned.forEach((names, path) => {
    const shown = names.slice(0, 15).join(", ") + (names.length > 15 ? ` and ${names.length - 15} more` : "");
    findings.push({
      scanner: "dependencies",
      ruleId: "unpinned-python-dependencies",
      severity: "low",
      title: `Unpinned Python dependencies (${names.length})`,
      description: `${path} does not pin an exact version for: ${shown}. Each install may resolve a different release, so builds are not reproducible, vulnerability results for these packages cannot be determined, and a compromised new release would be pulled in automatically.`,
      remediation: "Pin exact versions (package==x.y.z), ideally generated with hashes by pip-compile --generate-hashes, uv or Poetry, and update them deliberately (e.g. with Dependabot).",
      refs: ["OWASP LLM03:2025", "CWE-1357"],
      file: path,
    });
  });

  if (!packages.length) {
    const note = unpinned.size
      ? "Python dependencies were found, but none had an exact version (==), so known vulnerabilities could not be looked up."
      : "No supported dependency manifests or lockfiles found.";
    return { findings, packages, status: "skipped", note: [...notes, note].join(" ") };
  }

  // deps.dev (licenties, deprecation) loopt parallel aan OSV; fouten worden stil genegeerd
  const depsDevPromise = queryDepsDev(packages, deadline, signal);
  const withDepsDev = async (): Promise<string | undefined> => {
    const dd = await depsDevPromise;
    findings.push(...depsDevFindings(dd));
    notes.push(depsDevNote(dd, packages.length));
    return notes.length ? notes.join(" ") : undefined;
  };

  /* --- OSV querybatch (met paginering via next_page_token) --- */
  const vulnIdsPerPkg: string[][] = packages.map(() => []);
  /** Packages waarvoor OSV geen (volledig) antwoord gaf: "niet gecontroleerd", nooit "geen kwetsbaarheden". */
  const unchecked = new Set<number>();
  let lastError = "";
  const queryChunk = async (indices: number[], firstPage: { idx: number; token?: string }[] = []): Promise<void> => {
    let pending: { idx: number; token?: string }[] = firstPage.length ? firstPage : indices.map((idx) => ({ idx }));
    for (let page = 0; pending.length; page++) {
      if (page >= MAX_PAGES) {
        for (const { idx } of pending) unchecked.add(idx);
        lastError = lastError || "too many result pages";
        return;
      }
      const body = JSON.stringify({
        queries: pending.map(({ idx, token }) => {
          const p = packages[idx];
          const q = { package: { name: p.name, ecosystem: p.ecosystem }, version: p.version };
          return token ? { ...q, page_token: token } : q;
        }),
      });
      let res: OsvBatch;
      try {
        res = await fetchJsonRetry<OsvBatch>(`${OSV}/querybatch`, { method: "POST", body }, BATCH_TIMEOUT, deadline, signal);
      } catch (e) {
        // Eén ongeldige query (rare naam/versie) laat OSV de hele batch weigeren: splitsen en apart opnieuw proberen
        if (e instanceof HttpError && e.status === 400 && pending.length > 1) {
          const half = Math.ceil(pending.length / 2);
          const parts = [pending.slice(0, half), pending.slice(half)];
          await Promise.all(parts.map((part) => queryChunk([], part)));
          return;
        }
        lastError = errorMessage(e);
        for (const { idx } of pending) unchecked.add(idx);
        return;
      }
      const results = Array.isArray(res?.results) ? res.results : [];
      const next: { idx: number; token?: string }[] = [];
      pending.forEach(({ idx }, j) => {
        if (j >= results.length) {
          unchecked.add(idx);
          return;
        }
        const r = results[j];
        if (!isRecord(r)) return;
        if (Array.isArray(r.vulns)) {
          for (const v of r.vulns) if (isRecord(v) && typeof v.id === "string") vulnIdsPerPkg[idx].push(v.id);
        }
        const token = str(r.next_page_token);
        if (token) next.push({ idx, token });
      });
      if (results.length < pending.length) lastError = lastError || "incomplete response from OSV.dev";
      pending = next;
    }
  };
  const chunks: number[][] = [];
  for (let i = 0; i < packages.length; i += BATCH_SIZE) chunks.push(packages.slice(i, i + BATCH_SIZE).map((_, j) => i + j));
  await Promise.all(chunks.map((c) => queryChunk(c)));
  vulnIdsPerPkg.forEach((ids, i) => (vulnIdsPerPkg[i] = Array.from(new Set(ids))));

  if (unchecked.size) {
    const failed = Array.from(unchecked).sort((a, b) => a - b).map((i) => packages[i]);
    const all = unchecked.size === packages.length;
    findings.push({
      scanner: "dependencies",
      ruleId: all ? "osv-unavailable" : "osv-partial",
      severity: "medium",
      title: all
        ? `Dependency vulnerabilities could not be checked (${packages.length} package${packages.length === 1 ? "" : "s"})`
        : `Vulnerability check incomplete: ${failed.length} of ${packages.length} packages not checked`,
      description: `The vulnerability database OSV.dev could not be queried (${lastError || "unknown error"}), so ${all ? "none of the dependencies" : `these packages: ${listPackages(failed)}`} could be checked for known vulnerabilities. This is not a clean result: ${all ? "they" : "these packages"} may still contain known vulnerabilities.`,
      remediation: "Re-run the scan in a few minutes. If it keeps failing, run osv-scanner, npm audit or pip-audit locally or in your pipeline and attach the report to the submission.",
      refs: ["OWASP LLM03:2025"],
    });
    notes.push(all ? `OSV.dev unreachable: ${lastError}.` : `${failed.length} of ${packages.length} package(s) could not be checked against OSV.dev (${lastError}).`);
    if (all) {
      const note = await withDepsDev();
      return { findings, packages, status: "error", note: lastError === TIME_LIMIT ? `${STOPPED_EARLY} ${note ?? ""}`.trim() : note };
    }
  }

  /* --- details per advisory --- */
  const uniqueIds = Array.from(new Set(vulnIdsPerPkg.flat()));
  const ids = uniqueIds.slice(0, MAX_DETAILS);
  const details = new Map<string, OsvVuln>();
  let next = 0;
  const worker = async () => {
    while (next < ids.length && deadline - Date.now() > 500) {
      const id = ids[next++];
      try {
        const v = await fetchJson<OsvVuln>(`${OSV}/vulns/${encodeURIComponent(id)}`, { method: "GET" }, Math.min(VULN_TIMEOUT, deadline - Date.now()), signal);
        if (v && typeof v.id === "string") details.set(id, v);
      } catch {
        /* advisory zonder details: valt terug op alleen het id */
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, ids.length) }, () => worker()));

  /* --- findings per (package, kwetsbaarheid), aliassen samengevoegd --- */
  packages.forEach((pkg, idx) => {
    const groups: Set<string>[] = [];
    for (const id of vulnIdsPerPkg[idx]) {
      const keys = new Set<string>([id, ...(details.get(id)?.aliases ?? [])]);
      const hits = groups.filter((g) => Array.from(keys).some((k) => g.has(k)));
      const merged = new Set<string>(keys);
      for (const g of hits) {
        g.forEach((k) => merged.add(k));
        groups.splice(groups.indexOf(g), 1);
      }
      groups.push(merged);
    }
    for (const group of groups) {
      const queried = vulnIdsPerPkg[idx].filter((id) => group.has(id)).sort((a, b) => idRank(a) - idRank(b));
      const primary = queried[0];
      if (!primary) continue;
      const ordered = queried.map((id) => details.get(id)).filter((v): v is OsvVuln => v !== undefined);
      const detail = ordered[0];
      let severity: Severity = "medium";
      for (const d of ordered) {
        const s = vulnSeverity(d);
        if (s) {
          severity = s;
          break;
        }
      }
      const cves = Array.from(group).filter((k) => k.startsWith("CVE-")).sort();
      const others = Array.from(group).filter((k) => k !== primary && !k.startsWith("CVE-")).sort((a, b) => idRank(a) - idRank(b));
      const cwes = new Set<string>();
      for (const d of ordered) {
        const list = d.database_specific?.cwe_ids;
        if (Array.isArray(list)) for (const c of list) if (typeof c === "string") cwes.add(c);
      }
      let fixed: string | undefined;
      for (const d of ordered) {
        fixed = fixedVersion(d, pkg);
        if (fixed) break;
      }
      const summary = clip(cleanText(detail?.summary || (detail?.details ?? "").split(/\n\s*\n/)[0] || "Known vulnerability"), 110).replace(/\.$/, "");
      const shownId = cves[0] ?? primary;
      const aliasText = [...cves, ...others].filter((k) => k !== primary);
      const body = detail?.details
        ? ` ${clip(cleanText(detail.details), 480)}`
        : detail
          ? ""
          : " Advisory details could not be retrieved within the scan time, so the severity could not be determined and defaults to medium; open the advisory for the impact.";
      const file = byPath.get(pkg.source);
      const line = lineOf(file, pkg);
      const approxText = pkg.approximate
        ? ` No lockfile was found, so ${pkg.version} is the lowest version your manifest allows; the version actually installed may be newer and not affected.`
        : "";
      let remediation: string;
      if (fixed) {
        remediation = `${upgradeAdvice(pkg, fixed)}${pkg.approximate ? ` Also raise the minimum version in the manifest to ${fixed} and commit a lockfile so the installed version can be verified.` : ""} Then re-run the scan.`;
      } else if (detail) {
        remediation = `The advisory lists no fixed release of ${pkg.name} for this version. Check whether a newer major version or an alternative package avoids it, or apply the workaround described in ${shownId}; if neither is possible, document a risk acceptance for the reviewer.`;
      } else {
        remediation = `Open ${shownId} (https://osv.dev/vulnerability/${encodeURIComponent(primary)}) to find the fixed version, upgrade ${pkg.name} to it, and re-run the scan.`;
      }
      findings.push({
        scanner: "dependencies",
        ruleId: primary,
        severity,
        title: `${pkg.name} ${pkg.version} — ${summary} (${shownId})`,
        description: `${pkg.name}@${pkg.version} (${pkg.ecosystem}) is affected by ${primary}${aliasText.length ? ` (${aliasText.slice(0, 6).join(", ")})` : ""}.${approxText}${body}`,
        remediation,
        refs: [primary, ...cves.filter((c) => c !== primary), ...others.filter((o) => o.startsWith("GHSA-") || o.startsWith("PYSEC-")).slice(0, 3), ...Array.from(cwes)],
        file: pkg.source,
        line,
        snippet: line && file?.text ? snippetOf(splitLines(file.text)[line - 1] ?? "") : undefined,
      });
    }
  });

  const missing = uniqueIds.length - details.size;
  if (missing > 0) notes.push(`Details for ${missing} advisor${missing === 1 ? "y" : "ies"} could not be retrieved; those findings use default severity (medium).`);
  const detailsCut = next < ids.length || (signal.aborted && missing > 0);
  const note = await withDepsDev();
  const stopped = detailsCut || (await depsDevPromise).stoppedEarly;
  const status = unchecked.size || stopped ? "error" : "ok";
  return { findings, packages, status, note: stopped ? `${STOPPED_EARLY} ${note ?? ""}`.trim() : note };
}

/* ------------------------------------------- deps.dev (Open Source Insights) */

const DEPS_DEV = "https://api.deps.dev/v3/systems";
const DEPS_DEV_MAX = 150;
const DEPS_DEV_CONCURRENCY = 12;
const DEPS_DEV_TIMEOUT = 6000;
const DEPS_DEV_BUDGET_MS = 12000;

const DEPS_DEV_SYSTEM: Record<Ecosystem, string> = {
  npm: "NPM",
  PyPI: "PYPI",
  Go: "GO",
  Maven: "MAVEN",
  NuGet: "NUGET",
  "crates.io": "CARGO",
};

interface DepsDevInfo {
  licenses: string[];
  deprecated: boolean;
  reason?: string;
}

interface DepsDevResult {
  info: Map<PackageRef, DepsDevInfo>;
  queried: number;
  /** Gestopt door de scan-deadline voordat alle packages bevraagd waren. */
  stoppedEarly: boolean;
}

/** Licenties en deprecation-status per package-versie bij deps.dev (lockfile-packages eerst). */
async function queryDepsDev(packages: PackageRef[], scanDeadline: number, signal: AbortSignal): Promise<DepsDevResult> {
  const deadline = Math.min(Date.now() + DEPS_DEV_BUDGET_MS, scanDeadline);
  const ordered = [...packages.filter((p) => !p.approximate), ...packages.filter((p) => p.approximate)].slice(0, DEPS_DEV_MAX);
  const info = new Map<PackageRef, DepsDevInfo>();
  let next = 0;
  const worker = async () => {
    while (next < ordered.length && deadline - Date.now() > 300) {
      const pkg = ordered[next++];
      const version = pkg.ecosystem === "Go" && !/^v/.test(pkg.version) ? `v${pkg.version}` : pkg.version;
      const url = `${DEPS_DEV}/${DEPS_DEV_SYSTEM[pkg.ecosystem]}/packages/${encodeURIComponent(pkg.name)}/versions/${encodeURIComponent(version)}`;
      try {
        const res = await fetchJson<unknown>(url, { method: "GET" }, Math.min(DEPS_DEV_TIMEOUT, deadline - Date.now()), signal);
        if (!isRecord(res)) continue;
        const raw: unknown = res.licenses;
        const licenses = Array.isArray(raw) ? raw.filter((l): l is string => typeof l === "string" && l.trim() !== "").map((l) => l.trim()) : [];
        const reason = str(res.deprecatedReason)?.trim();
        info.set(pkg, { licenses, deprecated: res.isDeprecated === true, reason: reason ? reason : undefined });
        pkg.licenses = licenses;
      } catch {
        /* deps.dev is best-effort: onbekende packages (404), timeouts en netwerkfouten negeren */
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(DEPS_DEV_CONCURRENCY, ordered.length) }, () => worker()));
  return { info, queried: ordered.length, stoppedEarly: signal.aborted || (next < ordered.length && Date.now() >= scanDeadline - 300) };
}

/** Sterke copyleft (GPL, AGPL, SSPL, EUPL, OSL); LGPL valt hier bewust buiten. */
const COPYLEFT_ID = /^(AGPL|GPL|SSPL|EUPL|OSL)-(\d+(?:\.\d+)*)/i;
const NON_COMMERCIAL = /-NC\b|-NC-|non-?commercial/i;

function licenceIds(expr: string): string[] {
  return expr.split(/[\s()]+/).filter((t) => t !== "" && !/^(?:AND|OR|WITH)$/i.test(t));
}

/** Copyleft-families ("GPL-3.0") van een SPDX-expressie; leeg als een OR-alternatief geen copyleft is. */
function copyleftFamilies(expr: string): string[] {
  const families: string[] = [];
  for (const alt of expr.split(/\s+OR\s+/i)) {
    const found: string[] = [];
    for (const id of licenceIds(alt)) {
      const m = COPYLEFT_ID.exec(id);
      if (m) found.push(`${m[1].toUpperCase()}-${m[2]}`);
    }
    if (!found.length) return [];
    families.push(...found);
  }
  return families;
}

const pkgLabel = (p: PackageRef) => `${p.name}@${p.version}`;

function listPackages(pkgs: PackageRef[], max = 20): string {
  const shown = pkgs.slice(0, max).map(pkgLabel).join(", ");
  return pkgs.length > max ? `${shown} and ${pkgs.length - max} more` : shown;
}

/** Eén bronbestand als alle packages uit hetzelfde manifest komen. */
function commonSource(pkgs: PackageRef[]): string | undefined {
  const first = pkgs[0]?.source;
  return first !== undefined && pkgs.every((p) => p.source === first) ? first : undefined;
}

function depsDevFindings(dd: DepsDevResult): RawFinding[] {
  const out: RawFinding[] = [];
  const copyleft = new Map<string, PackageRef[]>();
  const unrecognised: { pkg: PackageRef; why: string }[] = [];
  const deprecated: { pkg: PackageRef; reason?: string }[] = [];

  dd.info.forEach((info, pkg) => {
    const families = new Set<string>();
    for (const l of info.licenses) for (const f of copyleftFamilies(l)) families.add(f);
    families.forEach((f) => {
      const list = copyleft.get(f) ?? [];
      list.push(pkg);
      copyleft.set(f, list);
    });
    const usable = info.licenses.filter((l) => l.toLowerCase() !== "non-standard" && !NON_COMMERCIAL.test(l));
    if (!usable.length) {
      const nc = info.licenses.filter((l) => NON_COMMERCIAL.test(l));
      const why = !info.licenses.length ? "no licence found" : nc.length ? `non-commercial licence (${nc.join(", ")})` : "non-standard licence";
      unrecognised.push({ pkg, why });
    }
    if (info.deprecated) deprecated.push({ pkg, reason: info.reason });
  });

  Array.from(copyleft.keys())
    .sort()
    .forEach((family) => {
      const pkgs = copyleft.get(family) ?? [];
      const network = /^(?:AGPL|SSPL)-/.test(family);
      out.push({
        scanner: "dependencies",
        ruleId: "license-copyleft",
        severity: "medium",
        title: `Copyleft licences: ${family} (${pkgs.length} package${pkgs.length === 1 ? "" : "s"})`,
        description: `Copyleft licence — review before redistribution. According to deps.dev (Open Source Insights), ${listPackages(pkgs)} ${pkgs.length === 1 ? "is" : "are"} licensed under ${family}. Strong copyleft licences require derivative works that are distributed${network ? " — or, for AGPL/SSPL, offered to users over a network —" : ""} to be released under the same licence, including source code, which can conflict with publishing the asset in the Capgemini catalogue or delivering it to clients.`,
        remediation: `Have the licence reviewed (Legal / Open Source Programme Office) before the asset is redistributed. Replace the package with a permissively licensed alternative, isolate it so the asset is not a derivative work, or document how the ${family} obligations are met.`,
        refs: ["OWASP LLM03:2025", `SPDX ${family}`],
        file: commonSource(pkgs),
      });
    });

  if (unrecognised.length) {
    const pkgs = unrecognised.map((u) => u.pkg);
    const detail = unrecognised
      .slice(0, 20)
      .map((u) => `${pkgLabel(u.pkg)} (${u.why})`)
      .join(", ");
    out.push({
      scanner: "dependencies",
      ruleId: "license-unknown",
      severity: "low",
      title: `Packages without a recognised licence (${unrecognised.length})`,
      description: `deps.dev (Open Source Insights) reports no standard SPDX licence for: ${detail}${unrecognised.length > 20 ? ` and ${unrecognised.length - 20} more` : ""}. Without a recognised open-source licence (or with a non-commercial one) there is no clear right to use or redistribute the code commercially.`,
      remediation: "Check the licence terms of each package in its repository. Replace packages that have no licence or a non-commercial licence, or obtain written permission from the copyright holder before publishing the asset.",
      refs: ["OWASP LLM03:2025"],
      file: commonSource(pkgs),
    });
  }

  for (const { pkg, reason } of deprecated.slice(0, 30)) {
    out.push({
      scanner: "dependencies",
      ruleId: "deprecated-package",
      severity: "low",
      title: `Deprecated: ${pkg.name} ${pkg.version}`,
      description: `${pkgLabel(pkg)} (${pkg.ecosystem}) is marked as deprecated by its registry${reason ? `: "${clip(reason.replace(/\s+/g, " "), 200)}"` : ""}. Deprecated packages no longer receive fixes, so future vulnerabilities will not be patched.`,
      remediation: `Upgrade ${pkg.name} to a supported release or migrate to the replacement recommended by its maintainers.`,
      refs: ["OWASP LLM03:2025", "CWE-1104"],
      file: pkg.source,
    });
  }
  return out;
}

function depsDevNote(dd: DepsDevResult, total: number): string {
  const capped = total > dd.queried ? ` (first ${dd.queried} of ${total} packages queried)` : "";
  if (!dd.info.size) return `Licence and deprecation data from deps.dev was unavailable${capped}; licence checks were skipped.`;
  return `Licence and deprecation data from deps.dev retrieved for ${dd.info.size} of ${dd.queried} package(s)${capped}.`;
}

function noLockfile(f: SourceFile, ecosystem: string, lock: string): RawFinding {
  return {
    scanner: "dependencies",
    ruleId: "no-lockfile",
    severity: "low",
    title: `No lockfile for ${f.path}`,
    description: `${f.path} declares ${ecosystem} dependencies with version ranges but no lockfile is committed next to it. Builds resolve different transitive versions over time, so the scanned dependency set is approximate and a compromised release can enter the build unnoticed.`,
    remediation: `Commit a lockfile (${lock}) and install from it in CI so builds are reproducible and auditable.`,
    refs: ["OWASP LLM03:2025", "CWE-1357"],
    file: f.path,
  };
}
