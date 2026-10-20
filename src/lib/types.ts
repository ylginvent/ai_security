export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export type ScannerId = "secrets" | "dependencies" | "sast" | "ai" | "model" | "config" | "skill" | "questionnaire" | "consistency";

export interface Finding {
  id: string;
  scanner: ScannerId;
  ruleId: string;
  severity: Severity;
  title: string;
  description: string;
  remediation: string;
  /** CWE, OWASP LLM Top 10, EU AI Act, CVE/GHSA ... */
  refs: string[];
  file?: string;
  line?: number;
  snippet?: string;
}

export type Decision = "approved" | "conditional" | "blocked";
export type AiActTier = "prohibited" | "high" | "limited" | "minimal";
export type ReviewStatus = "pending" | "approved" | "rejected";
export type CatalogStatus = "not_published" | "published";
export type SubmissionStatus = "scanning" | "completed" | "failed";

export interface PackageRef {
  ecosystem: "npm" | "PyPI" | "Maven" | "NuGet" | "Go" | "crates.io";
  name: string;
  version: string;
  /** Afgeleid uit een range (^1.2.3) in plaats van een lockfile. */
  approximate?: boolean;
  source: string;
  /** SPDX-licenties volgens deps.dev (leeg = geen licentie gevonden; ontbreekt = niet opgevraagd). */
  licenses?: string[];
}

export interface ScannerRun {
  id: ScannerId;
  name: string;
  engine: string;
  findings: number;
  durationMs: number;
  status: "ok" | "skipped" | "error";
  note?: string;
}

export interface ScanStats {
  filesTotal: number;
  filesScanned: number;
  filesSkipped: number;
  bytesScanned: number;
  linesScanned: number;
  languages: Record<string, number>;
  modelFiles: number;
  packages: number;
}

export interface Report {
  findings: Finding[];
  scanners: ScannerRun[];
  stats: ScanStats;
  packages: PackageRef[];
  gates: GateResult[];
  generatedAt: string;
  engineVersion: string;
  /** Eén review per gevonden SKILL.md (Agent Skills-formaat). Ontbreekt bij oudere rapporten. */
  skills?: SkillReview[];
}

export interface SkillCheck {
  id: string;
  category: "structure" | "quality" | "security";
  label: string;
  passed: boolean;
  /** Uitleg bij falen, of wat er goed ging. */
  detail: string;
  /** Concrete verbetersuggestie als de check faalt. */
  suggestion?: string;
}

export interface SkillReview {
  /** Pad van de skill-map in het archief ("" = root). */
  path: string;
  name: string | null;
  description: string | null;
  files: number;
  scripts: string[];
  lines: number;
  checks: SkillCheck[];
  /** 0–100, kwaliteit + veiligheid van de skill. */
  score: number;
  summary: string;
}

export interface GateResult {
  id: string;
  label: string;
  passed: boolean;
  blocking: boolean;
  detail: string;
}

export type Answers = Record<string, string | string[]>;

export interface Submission {
  id: string;
  created_at: string;
  asset_name: string;
  asset_version: string | null;
  owner_name: string;
  owner_email: string;
  business_unit: string | null;
  asset_type: string | null;
  answers: Answers;
  file_name: string | null;
  file_size: number | null;
  file_path: string | null;
  file_sha256: string | null;
  status: SubmissionStatus;
  decision: Decision | null;
  score: number | null;
  ai_act_tier: AiActTier | null;
  counts: Record<Severity, number> | null;
  report: Report | null;
  error: string | null;
  review_status: ReviewStatus;
  reviewer: string | null;
  review_comment: string | null;
  reviewed_at: string | null;
  catalog_status: CatalogStatus;
  published_at: string | null;
}

export interface AuditEvent {
  id: string;
  submission_id: string;
  created_at: string;
  actor: string;
  action: string;
  detail: Record<string, unknown>;
}
