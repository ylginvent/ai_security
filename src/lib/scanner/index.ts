import { createHash } from "node:crypto";
import type { Finding, PackageRef, ScanStats, ScannerId, ScannerRun, SkillReview } from "../types";
import { SCAN_EMPTY_RULE, SCAN_INCOMPLETE_RULE, SEVERITIES } from "../types";
import { errorMessage, LIMITS, readArchive, type Archive, type RawFinding, type ScannerResult } from "./archive";
import { scanAi, scanSast } from "./code";
import { scanConfig } from "./config";
import { scanDependencies } from "./dependencies";
import { scanModels } from "./models";
import { JS, PY } from "./rules";
import { scanSecrets } from "./secrets";
import { scanSkills } from "./skills";
import { applySuppressions } from "./suppress";

export interface ScanOutput {
  findings: Finding[];
  scanners: ScannerRun[];
  stats: ScanStats;
  packages: PackageRef[];
  /** Eén review per SKILL.md in het archief (leeg als het geen Agent Skill bevat). */
  skills: SkillReview[];
}

export const ENGINE_VERSION = "2026.10.1";

type ScannerKey = Exclude<ScannerId, "questionnaire" | "consistency">;

interface ScannerDef {
  id: ScannerKey;
  name: string;
  engine: string;
  /** Wat er niet gecontroleerd is als deze scanner faalt (in gewone taal, voor de gebruiker). */
  covers: string;
}

/** Volgorde = volgorde in het rapport. */
const SCANNERS: ScannerDef[] = [
  { id: "secrets", name: "Secret detection", engine: "Gitleaks-derived ruleset", covers: "hard-coded passwords, API keys and tokens" },
  {
    id: "dependencies",
    name: "Dependency vulnerabilities (SCA)",
    engine: "OSV.dev (open-source vulnerability database)",
    covers: "known vulnerabilities and licences of your dependencies",
  },
  {
    id: "sast",
    name: "Static code analysis",
    engine: "Semgrep & Bandit-derived rules",
    covers: "common code vulnerabilities (injection, unsafe deserialisation, disabled TLS …)",
  },
  {
    id: "ai",
    name: "AI / LLM security",
    engine: "OWASP Top 10 for LLM Applications 2025",
    covers: "AI-specific risks (prompt injection, unsafe output handling, excessive agency …)",
  },
  { id: "model", name: "Model artefact scanning", engine: "ModelScan-style pickle opcode analysis", covers: "model files that could run code when they are loaded" },
  { id: "config", name: "Configuration & IaC", engine: "Hadolint & Checkov-derived rules", covers: "Dockerfiles, infrastructure-as-code and CI/CD configuration" },
  { id: "skill", name: "Agent skill review", engine: "Agent Skills spec + skill security rules", covers: "the structure and security of the Agent Skill" },
];

/** Netwerk-gebonden SCA mag de hele scan niet laten vastlopen (de serverless functie heeft 60 s). */
const DEPS_TIMEOUT_MS = 45000;
/** Tijd die na de scanners nodig is voor uitzonderingen, beoordeling en opslaan. */
const FINISH_MARGIN_MS = 3000;

export interface ScanOptions {
  /**
   * Absoluut tijdstip (ms sinds epoch, zoals Date.now()) waarop de scan klaar moet zijn. Netwerk-lookups die dan
   * nog lopen worden niet meer afgewacht: de dependency-check wordt als onvolledig gemeld, niet als schoon.
   */
  deadline?: number;
}

/** Talen waarvoor de SAST- en AI-regels niet gelden (die dekken alleen Python en JavaScript/TypeScript). */
const UNANALYSED_LANGUAGES = new Set(["Java", "Kotlin", "Scala", "C#", "F#", "Go", "Rust", "Ruby", "PHP", "C", "C++", "Swift", "R", "Julia"]);
const ANALYSED_EXTS = new Set([...PY, ...JS]);

interface Timed {
  result: ScannerResult;
  durationMs: number;
  error?: string;
}

async function timed(fn: () => ScannerResult | Promise<ScannerResult>): Promise<Timed> {
  const start = Date.now();
  try {
    const result = await fn();
    return { result, durationMs: Date.now() - start };
  } catch (e) {
    return { result: { findings: [] }, durationMs: Date.now() - start, error: errorMessage(e) };
  }
}

/** Levert na `ms` een fout-resultaat op als de scanner dan nog niet klaar is. */
function withTimeout(p: Promise<Timed>, ms: number, message: string): Promise<Timed> {
  return new Promise<Timed>((resolve) => {
    const timer = setTimeout(() => resolve({ result: { findings: [] }, durationMs: ms, error: message }), ms);
    p.then(
      (t) => {
        clearTimeout(timer);
        resolve(t);
      },
      (e: unknown) => {
        clearTimeout(timer);
        resolve({ result: { findings: [] }, durationMs: 0, error: errorMessage(e) });
      },
    );
  });
}

const RANK = new Map(SEVERITIES.map((s, i) => [s, i] as [string, number]));

function compareFindings(a: RawFinding, b: RawFinding): number {
  const s = (RANK.get(a.severity) ?? 9) - (RANK.get(b.severity) ?? 9);
  if (s) return s;
  if (a.file !== b.file) {
    if (a.file === undefined) return 1;
    if (b.file === undefined) return -1;
    return a.file < b.file ? -1 : 1;
  }
  const l = (a.line ?? 0) - (b.line ?? 0);
  if (l) return l;
  return a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0;
}

/** Exacte duplicaten (zelfde scanner, regel, locatie en tekst) maar één keer tonen. */
function dedupe(findings: RawFinding[]): RawFinding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = [f.scanner, f.ruleId, f.file ?? "", f.line ?? "", f.title, f.description].join("\u0000");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Stabiel id: hash van scanner, regel, locatie en titel (met volgnummer bij botsingen). */
function withIds(findings: RawFinding[]): Finding[] {
  const used = new Map<string, number>();
  return findings.map((f) => {
    const base = createHash("sha1")
      .update([f.scanner, f.ruleId, f.file ?? "", f.line ?? "", f.title].join("\u0000"))
      .digest("hex")
      .slice(0, 12);
    const n = (used.get(base) ?? 0) + 1;
    used.set(base, n);
    return { id: n === 1 ? base : `${base}-${n}`, ...f };
  });
}

function clip(s: string, max = 240): string {
  const t = s.replace(/\s+/g, " ").trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

function incomplete(scanner: ScannerKey, title: string, description: string, remediation: string): RawFinding {
  return { scanner, ruleId: SCAN_INCOMPLETE_RULE, severity: "medium", title, description, remediation, refs: [] };
}

/**
 * Meldt als bevinding wat níet gecontroleerd is: gefaalde scanners, een upload zonder scanbare inhoud,
 * afgekapte archieven en code in talen zonder regels. Zo levert een onvolledige scan nooit stil "Approved" op.
 */
function coverage(archive: Archive, results: Map<ScannerKey, Timed>): { findings: RawFinding[]; sastNote?: string } {
  const out: RawFinding[] = [];
  const { stats, notes } = archive;

  for (const def of SCANNERS) {
    const t = results.get(def.id);
    if (!t || (t.error === undefined && t.result.status !== "error")) continue;
    const reason = clip(t.error ?? t.result.note ?? "unknown error");
    out.push(
      incomplete(
        def.id,
        `${def.name} did not complete`,
        `This check failed while scanning your upload (${reason}), so ${def.covers} were not fully checked. Because part of the scan is missing, the result cannot be approved automatically.`,
        def.id === "dependencies"
          ? "Submit again in a few minutes: the vulnerability database may have been temporarily unreachable. If it keeps failing, run osv-scanner, npm audit or pip-audit in your build pipeline and give the output to the reviewer."
          : "Submit again. If this check keeps failing, contact the AI Asset Gate team and include the submission ID, so the scanner can be fixed.",
      ),
    );
  }

  if (stats.filesScanned === 0) {
    out.push({
      ...incomplete(
        "sast",
        "Nothing in the upload could be scanned",
        `${stats.filesTotal ? `None of the ${stats.filesTotal} file(s) in the upload` : "The upload contains no files, so nothing"} could be read by the scanners: no security check has actually run.${notes.length ? ` ${notes.join(" ")}` : ""} Binary files, files over the size limits and dependency or build folders (node_modules, venv, dist, .git …) are skipped.`,
        "Upload the source code itself: a zip of the repository without node_modules, virtual environments or build output, or the URL of the public Git repository. Then submit again.",
      ),
      ruleId: SCAN_EMPTY_RULE,
    });
  } else if (archive.truncated) {
    out.push(
      incomplete(
        "sast",
        "Part of the upload was not scanned",
        `Some files exceed the scan limits, so they were not checked. ${notes.join(" ")}`,
        `Remove generated files, datasets, vendored libraries and build output from the zip so the code fits within the limits (${LIMITS.maxEntries.toLocaleString("en-US")} files, ${LIMITS.maxTextBytes / 1024 / 1024} MB per source file), then submit again.`,
      ),
    );
  } else {
    // Bestanden in een herkende taal die toch niet gelezen konden worden (te groot, binair, corrupt/versleuteld)
    const candidates = archive.files.filter((f) => f.language !== undefined);
    const unread = candidates.filter((f) => f.text === undefined).map((f) => f.path);
    if (candidates.length >= 4 && unread.length * 2 > candidates.length) {
      const shown = unread.slice(0, 5).join(", ");
      out.push(
        incomplete(
          "sast",
          "Most source files could not be read",
          `${unread.length} of ${candidates.length} source and configuration files were not content-scanned (${shown}${unread.length > 5 ? ` and ${unread.length - 5} more` : ""}). They are larger than 1 MB, look binary, or could not be decompressed (for example an encrypted zip).${notes.length ? ` ${notes.join(" ")}` : ""}`,
          "Upload an unencrypted zip of the source code. Leave out generated or minified bundles and data files, and keep individual source files under 1 MB, then submit again.",
        ),
      );
    }
  }

  const other = new Map<string, number>();
  for (const f of archive.files) {
    if (f.language && UNANALYSED_LANGUAGES.has(f.language)) other.set(f.language, (other.get(f.language) ?? 0) + 1);
  }
  if (!other.size) return { findings: out };
  const summary = Array.from(other.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([lang, n]) => `${n} ${lang}`)
    .join(", ");
  const analysed = archive.files.some((f) => f.text !== undefined && ANALYSED_EXTS.has(f.ext));
  if (analysed) return { findings: out, sastNote: `Not covered by the code rules (Python and JavaScript/TypeScript only): ${summary} file(s).` };
  out.push(
    incomplete(
      "sast",
      "Code language not covered by the automated code checks",
      `The upload contains ${summary} source file(s). The static-analysis and AI/LLM code rules only cover Python and JavaScript/TypeScript, so this code was checked for secrets, dependencies, model files and configuration, but not for injection, unsafe deserialisation, prompt injection or excessive agency.`,
      "You do not need to change the code for this. A reviewer will assess it manually; you can speed that up by giving the reviewer the results of a full SAST run for these languages (for example Semgrep, CodeQL or SonarQube).",
    ),
  );
  return { findings: out };
}

/** Scant een geüpload AI-asset (zip of los bestand) met alle scanners. */
export async function scanArchive(fileName: string, data: Uint8Array, options: ScanOptions = {}): Promise<ScanOutput> {
  const archive: Archive = await readArchive(fileName, data);

  // SCA is netwerk-gebonden: direct starten, de CPU-scanners draaien ondertussen
  const remaining = options.deadline === undefined ? Infinity : options.deadline - Date.now() - FINISH_MARGIN_MS;
  const depsBudget = Math.max(1000, Math.min(DEPS_TIMEOUT_MS, remaining));
  let packages: PackageRef[] = [];
  const depsStart = Date.now();
  const depsPromise = withTimeout(
    timed(async () => {
      // Iets vóór de harde time-out hieronder: dan breekt de SCA zelf af en levert hij een gedeeltelijk resultaat
      const r = await scanDependencies(archive, depsStart + depsBudget - 500);
      packages = r.packages;
      return r;
    }),
    depsBudget,
    remaining < DEPS_TIMEOUT_MS
      ? `stopped after ${Math.round(depsBudget / 1000)} seconds because the time available for the scan ran out`
      : `timed out after ${Math.round(depsBudget / 1000)} seconds`,
  );
  const results = new Map<ScannerKey, Timed>();
  const secrets = await timed(() => scanSecrets(archive));
  results.set("secrets", secrets);
  results.set("sast", await timed(() => scanSast(archive)));
  results.set("ai", await timed(() => scanAi(archive)));
  results.set("model", await timed(() => scanModels(archive)));
  results.set("config", await timed(() => scanConfig(archive)));
  let skills: SkillReview[] = [];
  results.set(
    "skill",
    await timed(() => {
      const r = scanSkills(archive, secrets.result.findings);
      skills = r.skills;
      return r;
    }),
  );
  const deps = await depsPromise;
  results.set("dependencies", deps);
  // Na een time-out kan de SCA later alsnog packages zetten; die horen dan niet bij dit rapport
  const scannedPackages = deps.error === undefined ? packages : [];

  const raw: RawFinding[] = [];
  for (const def of SCANNERS) {
    const t = results.get(def.id);
    if (t) raw.push(...t.result.findings);
  }
  // .aigateignore, inline-uitzonderingen en test/demo-code: afwaarderen naar info, niet verbergen
  const suppression = applySuppressions(archive, dedupe(raw));
  // Dekkingsbevindingen ná de uitzonderingen: die mogen niet weg te zetten zijn
  const cov = coverage(archive, results);
  const all = [...suppression.findings, ...cov.findings];

  const scanners: ScannerRun[] = SCANNERS.map((def) => {
    const t = results.get(def.id);
    const findings = all.filter((f) => f.scanner === def.id);
    const notes: string[] = [];
    if (t?.error) notes.push(`Scanner failed: ${t.error}.`);
    if (t?.result.note) notes.push(t.result.note);
    if (def.id === "sast" && cov.sastNote) notes.push(cov.sastNote);
    // Archief-notities (overgeslagen mappen, limieten) en uitzonderingen bij de eerste scanner tonen
    if (def.id === "secrets" && archive.notes.length) notes.push(`Archive: ${archive.notes.join(" ")}`);
    if (def.id === "secrets" && suppression.note) notes.push(`Exceptions: ${suppression.note}`);
    const run: ScannerRun = {
      id: def.id,
      name: def.name,
      engine: def.engine,
      findings: findings.length,
      durationMs: t?.durationMs ?? 0,
      status: t?.error ? "error" : (t?.result.status ?? "ok"),
    };
    if (notes.length) run.note = notes.join(" ");
    return run;
  });

  all.sort(compareFindings);
  const stats: ScanStats = { ...archive.stats, packages: scannedPackages.length };
  return { findings: withIds(all), scanners, stats, packages: scannedPackages, skills };
}
