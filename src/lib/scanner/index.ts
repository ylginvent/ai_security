import { createHash } from "node:crypto";
import type { Finding, PackageRef, ScanStats, ScannerId, ScannerRun, SkillReview } from "../types";
import { SEVERITIES } from "../types";
import { errorMessage, readArchive, type Archive, type RawFinding, type ScannerResult } from "./archive";
import { scanAi, scanSast } from "./code";
import { scanConfig } from "./config";
import { scanDependencies } from "./dependencies";
import { scanModels } from "./models";
import { scanSecrets } from "./secrets";
import { scanSkills } from "./skills";

export interface ScanOutput {
  findings: Finding[];
  scanners: ScannerRun[];
  stats: ScanStats;
  packages: PackageRef[];
  /** Eén review per SKILL.md in het archief (leeg als het geen Agent Skill bevat). */
  skills: SkillReview[];
}

export const ENGINE_VERSION = "2026.10.0";

interface ScannerDef {
  id: Exclude<ScannerId, "questionnaire">;
  name: string;
  engine: string;
}

/** Volgorde = volgorde in het rapport. */
const SCANNERS: ScannerDef[] = [
  { id: "secrets", name: "Secret detection", engine: "Gitleaks-derived ruleset" },
  { id: "dependencies", name: "Dependency vulnerabilities (SCA)", engine: "OSV.dev (open-source vulnerability database)" },
  { id: "sast", name: "Static code analysis", engine: "Semgrep & Bandit-derived rules" },
  { id: "ai", name: "AI / LLM security", engine: "OWASP Top 10 for LLM Applications 2025" },
  { id: "model", name: "Model artefact scanning", engine: "ModelScan-style pickle opcode analysis" },
  { id: "config", name: "Configuration & IaC", engine: "Hadolint & Checkov-derived rules" },
  { id: "skill", name: "Agent skill review", engine: "Agent Skills spec + skill security rules" },
];

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

/** Scant een geüpload AI-asset (zip of los bestand) met alle scanners. */
export async function scanArchive(fileName: string, data: Uint8Array): Promise<ScanOutput> {
  const archive: Archive = await readArchive(fileName, data);

  // SCA is netwerk-gebonden: direct starten, de CPU-scanners draaien ondertussen
  let packages: PackageRef[] = [];
  const depsPromise = timed(async () => {
    const r = await scanDependencies(archive);
    packages = r.packages;
    return r;
  });
  const results = new Map<ScannerDef["id"], Timed>();
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

  const all: RawFinding[] = [];
  const scanners: ScannerRun[] = SCANNERS.map((def) => {
    const t = results.get(def.id);
    const findings = t ? t.result.findings.filter((f) => f.scanner === def.id) : [];
    all.push(...findings);
    const notes: string[] = [];
    if (t?.error) notes.push(`Scanner failed: ${t.error}`);
    if (t?.result.note) notes.push(t.result.note);
    // Archief-notities (overgeslagen mappen, limieten) bij de eerste scanner tonen
    if (def.id === "secrets" && archive.notes.length) notes.push(`Archive: ${archive.notes.join(" ")}`);
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
  const stats: ScanStats = { ...archive.stats, packages: packages.length };
  return { findings: withIds(all), scanners, stats, packages, skills };
}
