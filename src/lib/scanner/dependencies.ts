import type { PackageRef, Severity } from "../types";
import { errorMessage, snippetOf, splitLines, type Archive, type RawFinding, type ScannerResult, type SourceFile } from "./archive";

/**
 * Software composition analysis: manifests en lockfiles parsen naar PackageRef[],
 * daarna kwetsbaarheden opvragen bij OSV.dev (querybatch + details per advisory).
 */

type Ecosystem = PackageRef["ecosystem"];

const OSV = "https://api.osv.dev/v1";
const BATCH_SIZE = 500;
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
      const name = str(entry.name) ?? (i >= 0 ? key.slice(i + "node_modules/".length) : key);
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
  if (!r || /^(?:workspace:|file:|link:|git|https?:|github:|npm:|portal:|\*|latest|next|x$)/i.test(r)) return undefined;
  const first = r.split("||")[0].trim().replace(/^[\^~>=<v\s]+/, "").split(/\s+/)[0];
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

function parseYarnLock(f: SourceFile, c: Collector) {
  let names: string[] = [];
  for (const line of splitLines(f.text ?? "")) {
    if (/^\S.*:\s*$/.test(line) && !line.startsWith("#")) {
      names = line
        .replace(/:\s*$/, "")
        .split(",")
        .map((s) => s.trim().replace(/^"|"$/g, ""))
        .map((s) => {
          const at = s.lastIndexOf("@");
          return at > 0 ? s.slice(0, at) : s;
        })
        .filter((s) => s && !s.includes(" "));
      continue;
    }
    const m = /^\s+version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (m && names.length) {
      for (const n of Array.from(new Set(names))) if (EXACT.test(m[1])) c.add("npm", n.replace(/@npm$/, ""), m[1], f.path);
      names = [];
    }
  }
}

function parsePnpmLock(f: SourceFile, c: Collector) {
  let inPackages = false;
  for (const line of splitLines(f.text ?? "")) {
    if (/^\S/.test(line)) inPackages = /^packages:\s*$/.test(line);
    if (!inPackages) continue;
    const m = /^ {2}['"]?\/?((?:@[^/\s'"]+\/)?[^@/\s'"(]+)[@/](\d[^:'"\s(]*)/.exec(line);
    if (m && EXACT.test(m[2])) c.add("npm", m[1], m[2], f.path);
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
  let cur: { name?: string; version?: string; source?: string } | null = null;
  const flush = () => {
    if (!cur || !cur.name || !cur.version) return;
    if (ecosystem === "crates.io" && !(cur.source ?? "").startsWith("registry+")) return; // lokale crates
    c.add(ecosystem, ecosystem === "PyPI" ? normalisePyName(cur.name) : cur.name, cur.version, f.path);
  };
  let inHeader = false;
  for (const line of splitLines(f.text ?? "")) {
    if (/^\[\[package\]\]\s*$/.test(line)) {
      flush();
      cur = {};
      inHeader = true;
      continue;
    }
    if (/^\[/.test(line)) {
      inHeader = false;
      continue;
    }
    if (!inHeader || !cur) continue;
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
  for (const m of (f.text ?? "").matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const g = xmlTag(m[1], "groupId");
    const a = xmlTag(m[1], "artifactId");
    const v = xmlTag(m[1], "version");
    if (g && a && v && !v.includes("${") && /^\d/.test(v)) c.add("Maven", `${g}:${a}`, v, f.path);
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
  results?: { vulns?: { id: string }[] }[];
}

async function fetchJson<T>(url: string, init: RequestInit, ms: number): Promise<T> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), Math.max(1, ms));
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal, headers: { "content-type": "application/json", accept: "application/json" } });
    if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
    return (await res.json()) as T;
  } catch (e) {
    if (ctrl.signal.aborted) throw new Error(`timeout after ${ms} ms`);
    throw e;
  } finally {
    clearTimeout(timer);
  }
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

const LOCK_NPM = new Set(["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"]);
const LOCK_PY = new Set(["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock"]);

export async function scanDependencies(archive: Archive): Promise<DependencyResult> {
  const started = Date.now();
  const deadline = started + BUDGET_MS;
  const packages: PackageRef[] = [];
  const seen = new Set<string>();
  const collector: Collector = {
    add(ecosystem, name, version, source, approximate) {
      const key = `${ecosystem}|${name}|${version}`;
      if (!name || seen.has(key)) return;
      seen.add(key);
      packages.push(approximate ? { ecosystem, name, version, approximate: true, source } : { ecosystem, name, version, source });
    },
  };

  const findings: RawFinding[] = [];
  const unpinned = new Map<string, string[]>();
  const namesByDir = new Map<string, Set<string>>();
  for (const f of archive.files) {
    const set = namesByDir.get(f.dir) ?? new Set<string>();
    set.add(f.name);
    namesByDir.set(f.dir, set);
  }
  const has = (dir: string, names: Set<string>) => Array.from(namesByDir.get(dir) ?? []).some((n) => names.has(n));
  const byPath = new Map(archive.files.map((f) => [f.path, f] as [string, SourceFile]));

  for (const f of archive.files) {
    if (f.text === undefined) continue;
    const n = f.name;
    const lower = n.toLowerCase();
    if (n === "package-lock.json" || n === "npm-shrinkwrap.json") parsePackageLock(f, collector);
    else if (n === "yarn.lock") parseYarnLock(f, collector);
    else if (n === "pnpm-lock.yaml") parsePnpmLock(f, collector);
    else if (n === "package.json") {
      if (has(f.dir, LOCK_NPM)) continue;
      const before = packages.length;
      parsePackageJson(f, collector);
      if (packages.length > before || /"(?:dev)?[dD]ependencies"\s*:\s*\{\s*"/.test(f.text)) findings.push(noLockfile(f, "npm", "package-lock.json (npm ci)"));
    } else if (/^requirements[^/]*\.txt$/i.test(n) || (/\.txt$/i.test(n) && /(?:^|\/)requirements$/i.test(f.dir))) parseRequirements(f, collector, unpinned);
    else if (n === "Pipfile.lock") parsePipfileLock(f, collector);
    else if (n === "poetry.lock" || n === "uv.lock" || n === "pdm.lock") parseTomlPackages(f, collector, "PyPI");
    else if (n === "pyproject.toml") {
      const declares = /^\s*dependencies\s*=\s*\[\s*["']|^\[tool\.poetry\.dependencies\]/m.test(f.text);
      if (has(f.dir, LOCK_PY)) continue;
      parsePyproject(f, collector);
      const hasPinnedRequirements = Array.from(namesByDir.get(f.dir) ?? []).some((x) => /^requirements[^/]*\.txt$/i.test(x));
      if (declares && !hasPinnedRequirements) findings.push(noLockfile(f, "PyPI", "poetry.lock / uv.lock"));
    } else if (n === "go.mod") parseGoMod(f, collector);
    else if (n === "pom.xml") parsePom(f, collector);
    else if (lower.endsWith(".csproj") || lower.endsWith(".fsproj") || n === "packages.config" || n === "Directory.Packages.props") parseNuget(f, collector);
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
    return { findings, packages, status: "skipped", note: "No supported dependency manifests or lockfiles found." };
  }

  // deps.dev (licenties, deprecation) loopt parallel aan OSV; fouten worden stil genegeerd
  const depsDevPromise = queryDepsDev(packages);
  const withDepsDev = async (notes: string[]): Promise<string | undefined> => {
    const dd = await depsDevPromise;
    findings.push(...depsDevFindings(dd));
    notes.push(depsDevNote(dd, packages.length));
    return notes.length ? notes.join(" ") : undefined;
  };

  /* --- OSV querybatch --- */
  const vulnIdsPerPkg: string[][] = packages.map(() => []);
  let failedChunks = 0;
  let lastError = "";
  const chunks: number[] = [];
  for (let i = 0; i < packages.length; i += BATCH_SIZE) chunks.push(i);
  await Promise.all(
    chunks.map(async (start) => {
      const slice = packages.slice(start, start + BATCH_SIZE);
      try {
        const body = JSON.stringify({ queries: slice.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) });
        const res = await fetchJson<OsvBatch>(`${OSV}/querybatch`, { method: "POST", body }, Math.min(BATCH_TIMEOUT, deadline - Date.now()));
        (res.results ?? []).forEach((r, j) => {
          const ids = (r?.vulns ?? []).map((v) => v.id).filter((id): id is string => typeof id === "string");
          if (start + j < vulnIdsPerPkg.length) vulnIdsPerPkg[start + j] = ids;
        });
      } catch (e) {
        failedChunks++;
        lastError = errorMessage(e);
      }
    }),
  );

  if (failedChunks === chunks.length) {
    findings.push({
      scanner: "dependencies",
      ruleId: "osv-unavailable",
      severity: "info",
      title: "Dependency vulnerability lookup unavailable",
      description: `${packages.length} package(s) were inventoried, but OSV.dev could not be reached (${lastError}). Known vulnerabilities in dependencies were therefore not assessed.`,
      remediation: "Re-run the scan later, or run osv-scanner / pip-audit / npm audit in the build pipeline and attach the result.",
      refs: ["OWASP LLM03:2025"],
    });
    return { findings, packages, status: "error", note: await withDepsDev([`OSV.dev unreachable: ${lastError}`]) };
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
        const v = await fetchJson<OsvVuln>(`${OSV}/vulns/${encodeURIComponent(id)}`, { method: "GET" }, Math.min(VULN_TIMEOUT, deadline - Date.now()));
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
      const body = detail?.details ? ` ${clip(cleanText(detail.details), 480)}` : detail ? "" : " Advisory details could not be retrieved within the scan budget; see the advisory for impact.";
      const file = byPath.get(pkg.source);
      const line = lineOf(file, pkg);
      findings.push({
        scanner: "dependencies",
        ruleId: primary,
        severity,
        title: `${pkg.name} ${pkg.version} — ${summary} (${shownId})`,
        description: `${pkg.name}@${pkg.version} (${pkg.ecosystem}${pkg.approximate ? ", version inferred from a range in the manifest" : ""}) is affected by ${primary}${aliasText.length ? ` (${aliasText.slice(0, 6).join(", ")})` : ""}.${body}`,
        remediation: fixed
          ? `Upgrade ${pkg.name} to ${fixed} or later${pkg.approximate ? " and commit a lockfile so the resolved version is known" : ""}, then re-run the scan.`
          : "No fixed version has been published; replace the package or apply the mitigations described in the advisory.",
        refs: [primary, ...cves.filter((c) => c !== primary), ...others.filter((o) => o.startsWith("GHSA-") || o.startsWith("PYSEC-")).slice(0, 3), ...Array.from(cwes)],
        file: pkg.source,
        line,
        snippet: line && file?.text ? snippetOf(splitLines(file.text)[line - 1] ?? "") : undefined,
      });
    }
  });

  const notes: string[] = [];
  if (failedChunks) notes.push(`${failedChunks} of ${chunks.length} OSV batch request(s) failed (${lastError}).`);
  const missing = uniqueIds.length - details.size;
  if (missing > 0) notes.push(`Details for ${missing} advisor${missing === 1 ? "y" : "ies"} could not be retrieved; those findings use default severity.`);
  return { findings, packages, status: failedChunks ? "error" : "ok", note: await withDepsDev(notes) };
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
}

/** Licenties en deprecation-status per package-versie bij deps.dev (lockfile-packages eerst). */
async function queryDepsDev(packages: PackageRef[]): Promise<DepsDevResult> {
  const deadline = Date.now() + DEPS_DEV_BUDGET_MS;
  const ordered = [...packages.filter((p) => !p.approximate), ...packages.filter((p) => p.approximate)].slice(0, DEPS_DEV_MAX);
  const info = new Map<PackageRef, DepsDevInfo>();
  let next = 0;
  const worker = async () => {
    while (next < ordered.length && deadline - Date.now() > 300) {
      const pkg = ordered[next++];
      const version = pkg.ecosystem === "Go" && !/^v/.test(pkg.version) ? `v${pkg.version}` : pkg.version;
      const url = `${DEPS_DEV}/${DEPS_DEV_SYSTEM[pkg.ecosystem]}/packages/${encodeURIComponent(pkg.name)}/versions/${encodeURIComponent(version)}`;
      try {
        const res = await fetchJson<unknown>(url, { method: "GET" }, Math.min(DEPS_DEV_TIMEOUT, deadline - Date.now()));
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
  return { info, queried: ordered.length };
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
