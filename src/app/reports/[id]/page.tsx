import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { cache, type ReactNode } from "react";
import { Card, CardHeader, InitialsTile, TableScroll, btn, thead } from "@/components/Card";
import {
  AlertIcon,
  ArrowRightIcon,
  CheckCircleIcon,
  CheckIcon,
  ChevronRightIcon,
  DownloadIcon,
  FileIcon,
  SpinnerIcon,
  InfoIcon,
  XCircleIcon,
} from "@/components/icons";
import { ScoreRing } from "@/components/Score";
import { SEV_BG, SEV_TEXT, SeverityChip } from "@/components/SeverityChip";
import { REVIEW_LABEL, StatusPill, type Tone } from "@/components/StatusPill";
import {
  AI_ACT_SHORT,
  SCANNER_LABEL,
  SEVERITY_LABEL,
  assetTypeLabel,
  businessUnitLabel,
  formatBytes,
  formatDate,
  formatDateTime,
  formatDuration,
  formatNumber,
  humanize,
  shortHash,
  shortPath,
  suppressionInfo,
} from "@/lib/format";
import { ruleKey } from "@/lib/compare";
import { AI_ACT_LABEL, ALL_QUESTIONS, SECTIONS, answerLabel, isSkill, isVisible } from "@/lib/questionnaire";
import { DECISION_LABEL, PASS_SCORE, suppressionOf, trustScore } from "@/lib/scoring";
import { getStore } from "@/lib/store";
import {
  SCAN_EMPTY_RULE,
  SCAN_INCOMPLETE_RULE,
  SEVERITIES,
  type AuditEvent,
  type Comparison,
  type ComparedFinding,
  type Decision,
  type Finding,
  type GateResult,
  type PackageRef,
  type Report,
  type ScannerId,
  type ScannerRun,
  type Severity,
  type Submission,
  type VersionRef,
} from "@/lib/types";
import { findingAnchor } from "./anchors";
import AutoRefresh from "./AutoRefresh";
import DependencyTable, { type DependencyRow, type VulnCheck } from "./DependencyTable";
import FindingsExplorer from "./FindingsExplorer";
import FixFirstLink from "./FixFirstLink";
import PrintButton from "./PrintButton";
import ReviewPanel from "./ReviewPanel";
import SkillFeedback from "./SkillFeedback";

export const dynamic = "force-dynamic";

type Props = { params: Promise<{ id: string }> };

const getSubmission = cache(async (id: string) => getStore().get(id));

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { id } = await params;
  try {
    const s = await getSubmission(id);
    return { title: s ? `${s.asset_name} · Report` : "Report not found" };
  } catch {
    return { title: "Report" };
  }
}

/* ------------------------------------------------------------------ helpers */

const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function countFindings(findings: Finding[]): Record<Severity, number> {
  const c = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) c[f.severity]++;
  return c;
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

function escapeRegExp(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Dependency findings that are not about a known vulnerability (licences, deprecation, lockfiles, lookup errors).
 * Vulnerability findings use the advisory id (GHSA-…, CVE-…, PYSEC-…) as rule id.
 */
const NON_VULN_DEP_RULES = new Set([
  "osv-unavailable",
  "unpinned-python-dependencies",
  "license-copyleft",
  "license-unknown",
  "deprecated-package",
  "no-lockfile",
]);

function isVulnFinding(f: Finding): boolean {
  return f.scanner === "dependencies" && !NON_VULN_DEP_RULES.has(f.ruleId);
}

/**
 * Links vulnerability findings to packages. Prefers an exact "name@version" / "name version" match (so two versions of
 * one package are not mixed up), then falls back to a whole-word name match in title, snippet and description.
 */
function dependencyRows(packages: PackageRef[], findings: Finding[]): DependencyRow[] {
  const deps = findings.map((f, index) => ({ f, index })).filter((x) => isVulnFinding(x.f));
  const rows = packages.map((pkg): DependencyRow => {
    if (!pkg.name || deps.length === 0) return { pkg, vuln: null };
    const re = new RegExp(`(^|[^A-Za-z0-9_.@/-])${escapeRegExp(pkg.name)}($|[^A-Za-z0-9_/-])`, "i");
    const byName = deps.filter(({ f }) => re.test(f.title) || (f.snippet ? re.test(f.snippet) : false) || re.test(f.description));
    const exact = byName.filter(({ f }) => f.description.includes(`${pkg.name}@${pkg.version}`) || f.title.startsWith(`${pkg.name} ${pkg.version}`));
    const hits = exact.length ? exact : byName;
    if (!hits.length) return { pkg, vuln: null };
    const worst = hits.reduce((best, x) => (SEV_RANK[x.f.severity] < SEV_RANK[best.f.severity] ? x : best), hits[0]);
    return { pkg, vuln: { severity: worst.f.severity, count: hits.length, index: worst.index } };
  });
  return rows.sort((a, b) => {
    const va = a.vuln ? SEV_RANK[a.vuln.severity] : 9;
    const vb = b.vuln ? SEV_RANK[b.vuln.severity] : 9;
    return va - vb || a.pkg.name.localeCompare(b.pkg.name, "en");
  });
}

function vulnCheckState(report: Report): VulnCheck {
  const run = report.scanners.find((sc) => sc.id === "dependencies");
  if (!run || run.status !== "error") return "ok";
  return report.findings.some((f) => f.scanner === "dependencies" && f.ruleId === "osv-unavailable") ? "unavailable" : "partial";
}

/**
 * Findings that make a gate fail, mirroring the predicates in lib/scoring.ts `evaluate()`.
 * Gates without findings behind them (EU AI Act, trust score) are not listed.
 */
const GATE_FINDINGS: Record<string, (f: Finding) => boolean> = {
  "no-secrets": (f) => f.scanner === "secrets" && (f.severity === "critical" || f.severity === "high"),
  "no-malicious-models": (f) => f.scanner === "model" && f.severity === "critical",
  "no-critical": (f) => f.severity === "critical",
  "no-high": (f) => f.severity === "high",
  "scan-complete": (f) => f.ruleId === SCAN_INCOMPLETE_RULE || f.ruleId === SCAN_EMPTY_RULE,
  exceptions: (f) => {
    const s = suppressionOf(f);
    return s !== null && s.by !== "test-code" && (s.originalSeverity === "critical" || s.originalSeverity === "high");
  },
};

/** Plain-language "what to do" per failed gate. */
function gateAction(g: GateResult, report: Report): string | null {
  switch (g.id) {
    case "no-secrets":
      return "Delete the credentials from the code and its git history, revoke and reissue (rotate) them, and load them at runtime from environment variables or Azure Key Vault. Removing them from the code alone is not enough: anyone with the old copy can still use them.";
    case "no-malicious-models":
      return "Don't ship model files that run code when they are loaded. Re-export the model in a safe format such as safetensors or ONNX, or download it from a trusted source and verify its checksum.";
    case "no-critical":
      return "Fix every critical finding listed below. Each one blocks publication on its own.";
    case "ai-act":
      return g.blocking
        ? "The declared use case is a prohibited AI practice under the EU AI Act and can't be published. If your answers in the questionnaire are wrong, correct them and submit again; otherwise contact the AI governance board."
        : "High-risk AI systems need approval from the AI governance board. A reviewer will pick this up; make sure the questionnaire answers on human oversight, logging and data governance are complete.";
    case "no-high":
      return "Fix the high-severity findings, or explain in your resubmission why the risk is acceptable so a reviewer can sign off.";
    case "score": {
      const withoutHigh = trustScore(report.findings.filter((f) => f.severity !== "critical" && f.severity !== "high"));
      const withoutMedium = trustScore(report.findings.filter((f) => f.severity === "low" || f.severity === "info"));
      if (withoutHigh >= PASS_SCORE)
        return `Every finding lowers the score; critical and high findings weigh most. Fixing the critical and high findings would bring the score to about ${withoutHigh}, above the ${PASS_SCORE} needed.`;
      return `Every finding lowers the score; critical and high findings weigh most, and repeats of the same issue weigh less. Fixing the critical and high findings would bring it to about ${withoutHigh}; also fixing the medium findings would bring it to about ${withoutMedium} (${PASS_SCORE} needed).`;
    }
    case "scan-complete":
      return g.blocking
        ? "Nothing in the upload could be scanned. Upload the source code itself (a zip without node_modules, virtual environments or build output, or a public Git link) and submit again."
        : "Part of the upload was not checked automatically (see the findings below). Fix the cause if you can, for example a smaller zip or a reachable lockfile, and submit again; otherwise a reviewer assesses what was not covered.";
    case "exceptions":
      return "You marked serious findings as exceptions in .aigateignore or with an inline comment. A reviewer has to confirm each one; add a short reason to every exception so they can.";
    default:
      return null;
  }
}

/** What made the scan less than complete: failed scanners, skipped files, suppressed findings. */
function scanGaps(report: Report): { failed: ScannerRun[]; skippedFiles: number; totalFiles: number; suppressed: number } {
  return {
    failed: report.scanners.filter((sc) => sc.status === "error"),
    skippedFiles: report.stats?.filesSkipped ?? 0,
    totalFiles: report.stats?.filesTotal ?? 0,
    suppressed: report.findings.filter((f) => suppressionInfo(f) !== null).length,
  };
}

function answerSeverity(qId: string, value: string | string[] | undefined): Severity | null {
  const q = ALL_QUESTIONS.find((x) => x.id === qId);
  if (!q?.options || value === undefined) return null;
  const values = Array.isArray(value) ? value : [value];
  let best: Severity | null = null;
  for (const o of q.options) {
    if (o.finding && values.includes(o.value) && (best === null || SEV_RANK[o.finding.severity] < SEV_RANK[best])) best = o.finding.severity;
  }
  return best;
}

function findingLocation(f: Finding): string | null {
  if (!f.file) return null;
  return f.line ? `${f.file}:${f.line}` : f.file;
}

/** True when this finding on its own makes a blocking gate fail. */
function blocksPublication(f: Finding): boolean {
  return f.severity === "critical" || GATE_FINDINGS["no-secrets"](f) || GATE_FINDINGS["no-malicious-models"](f);
}

/**
 * The three findings to fix first: most severe first (info excluded). Within one severity, findings that block
 * publication come first (a high-severity secret blocks, other high findings don't), then findings from a rule that
 * is not yet in the list win over repeats of the same rule.
 */
function fixFirst(findings: Finding[]): { f: Finding; index: number; blocking: boolean }[] {
  const ranked = findings
    .map((f, index) => ({ f, index, blocking: blocksPublication(f) }))
    .filter((x) => x.f.severity !== "info")
    .sort((a, b) => SEV_RANK[a.f.severity] - SEV_RANK[b.f.severity] || Number(b.blocking) - Number(a.blocking) || a.index - b.index);
  const seen = new Set<string>();
  const withRepeat = ranked.map((x) => {
    const rule = `${x.f.scanner}:${x.f.ruleId}`;
    const repeat = seen.has(rule) ? 1 : 0;
    seen.add(rule);
    return { ...x, repeat };
  });
  return withRepeat
    .sort(
      (a, b) =>
        SEV_RANK[a.f.severity] - SEV_RANK[b.f.severity] || Number(b.blocking) - Number(a.blocking) || a.repeat - b.repeat || a.index - b.index,
    )
    .slice(0, 3)
    .map(({ f, index, blocking }) => ({ f, index, blocking }));
}

/** Number of findings per rule (scanner:ruleId). */
function ruleCounts(findings: Finding[]): Map<string, number> {
  const m = new Map<string, number>();
  for (const f of findings) m.set(ruleKey(f), (m.get(ruleKey(f)) ?? 0) + 1);
  return m;
}

/** Repeats of one rule as one line: the worst (then first) finding of each rule plus how often the rule fired. Worst rules first. */
function groupByRule<T extends { f: { scanner: string; ruleId: string; severity: Severity }; index: number }>(list: T[]): (T & { count: number })[] {
  const sorted = [...list].sort((a, b) => SEV_RANK[a.f.severity] - SEV_RANK[b.f.severity] || a.index - b.index);
  const out = new Map<string, T & { count: number }>();
  for (const x of sorted) {
    const k = ruleKey(x.f);
    const hit = out.get(k);
    if (hit) hit.count++;
    else out.set(k, { ...x, count: 1 });
  }
  return [...out.values()];
}

function versionLabel(v: string | null | undefined): string {
  return v ? `v${v.replace(/^v/i, "")}` : "the previous version";
}

/** First sentence of a text, for compact previews. */
function firstSentence(text: string, max = 160): string {
  const t = text.trim();
  const m = /^(.+?[.!?])(\s|$)/.exec(t);
  const s = m ? m[1] : t;
  return s.length > max ? `${s.slice(0, max - 1).trimEnd()}…` : s;
}

const ACTION_LABEL: Record<string, string> = {
  submitted: "Submitted",
  scan_completed: "Scan completed",
  scan_failed: "Scan failed",
  review_approved: "Approved by reviewer",
  review_rejected: "Rejected by reviewer",
  published_to_catalogue: "Published to Azure AI catalogue",
};

const ACTION_DOT: Record<string, string> = {
  submitted: "bg-faint",
  scan_completed: "bg-brand",
  scan_failed: "bg-sev-critical",
  review_approved: "bg-ok",
  review_rejected: "bg-sev-critical",
  published_to_catalogue: "bg-brand",
};

function eventSummary(detail: Record<string, unknown>, gateLabels: Map<string, string>): string[] {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(detail ?? {})) {
    if (k === "comment" || v === null || v === undefined || v === "") continue;
    let text: string | null = null;
    if (k === "sha256" && typeof v === "string") text = `SHA-256 ${shortHash(v, 12)}`;
    else if (k === "size" && typeof v === "number") text = formatBytes(v);
    else if (k === "decision" && typeof v === "string" && v in DECISION_LABEL) text = DECISION_LABEL[v as Decision];
    else if (k === "score" && typeof v === "number") text = `Score ${v}/100`;
    else if (k === "findings" && typeof v === "number") text = `${v} finding${v === 1 ? "" : "s"}`;
    else if (k === "failedGates" && Array.isArray(v))
      text = v.length ? `Failed: ${v.map((g) => gateLabels.get(String(g)) ?? String(g)).join(", ")}` : "All gates passed";
    else if (k === "catalogueId") text = `Entry ${String(v)}`;
    else if (k === "previousId" && typeof v === "string") text = `New version of submission ${v.slice(0, 8)}`;
    else if (k === "previousVersion" && typeof v === "string") text = `Previous ${versionLabel(v)}`;
    else if (k === "fixedSincePrevious" && typeof v === "number") text = `${v} fixed`;
    else if (k === "newSincePrevious" && typeof v === "number") text = `${v} new`;
    else if (k === "stillOpen" && typeof v === "number") text = `${v} still open`;
    else if (k === "file" && typeof v === "string") text = v;
    else if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") text = `${humanize(k)}: ${String(v)}`;
    else if (Array.isArray(v)) text = `${humanize(k)}: ${v.map((x) => String(x)).join(", ")}`;
    if (text) parts.push(text.length > 160 ? `${text.slice(0, 157)}…` : text);
  }
  return parts;
}

const LANG_COLORS = ["bg-brand", "bg-navy", "bg-[#5B9BD5]", "bg-[#94A3B8]", "bg-[#2F855A]", "bg-[#CBD5E1]"];

/* Local table cell styles (no colour/alignment, so callers can add them without class conflicts). */
const thc = "whitespace-nowrap px-4 py-3 text-xs font-medium text-muted first:pl-5 last:pr-5 sm:first:pl-6 sm:last:pr-6";
const tdc = "px-4 py-3.5 align-middle text-sm first:pl-5 last:pr-5 sm:first:pl-6 sm:last:pr-6";

/* ------------------------------------------------------------------ page */

export default async function ReportPage({ params }: Props) {
  const { id } = await params;
  const s = await getSubmission(id);
  if (!s) notFound();

  const [events, newer] = await Promise.all([
    getStore()
      .events(s.id)
      .catch((e): AuditEvent[] => {
        console.error("audit events", e);
        return [];
      }),
    getStore()
      .findNewerVersion(s.id)
      .catch((e): VersionRef | null => {
        console.error("newer version", e);
        return null;
      }),
  ]);

  const report = s.status === "completed" ? s.report : null;
  const gateLabels = new Map((report?.gates ?? []).map((g) => [g.id, g.label] as const));
  const comparison = report?.comparison ?? null;

  return (
    <div className="space-y-8">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between print:hidden">
        <nav aria-label="Breadcrumb" className="min-w-0">
          <ol className="flex min-w-0 items-center gap-1.5 text-sm text-muted">
            <li>
              <Link href="/" className="hover:text-ink">
                Overview
              </Link>
            </li>
            <li aria-hidden="true" className="text-faint">
              <ChevronRightIcon size={14} />
            </li>
            <li className="whitespace-nowrap">Report</li>
            <li aria-hidden="true" className="text-faint">
              <ChevronRightIcon size={14} />
            </li>
            <li aria-current="page" className="min-w-0 truncate font-medium text-ink-2">
              {s.asset_name}
            </li>
          </ol>
        </nav>
        <div className="flex shrink-0 flex-wrap gap-2">
          <a href={`/api/submissions/${s.id}/report`} download className={btn.secondary}>
            <DownloadIcon size={16} />
            Download JSON report
          </a>
          {s.status === "completed" && (
            <a href={`/api/submissions/${s.id}/sbom`} download className={btn.secondary}>
              <DownloadIcon size={16} />
              SBOM (CycloneDX)
            </a>
          )}
          <PrintButton />
        </div>
      </div>

      {newer && <NewerVersionNotice newer={newer} />}

      <Hero s={s} report={report} hasNewer={!!newer} />

      {report && comparison && <ComparisonCard s={s} report={report} c={comparison} />}

      {report && <ScanNotice report={report} />}

      {report && report.skills && report.skills.length > 0 ? <SkillFeedback skills={report.skills} /> : null}

      <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_340px] print:block">
        <div className="min-w-0 space-y-6 print:space-y-5">
          {report && (
            <>
              <GatesCard report={report} />
              <Card id="findings" labelledBy="findings-title" className="scroll-mt-24">
                <CardHeader
                  id="findings-title"
                  title="Findings"
                  meta={report.findings.length}
                  description="Everything the scanners and the questionnaire flagged, most severe first. Open a finding to see what is wrong, where it is and how to fix it."
                />
                <FindingsExplorer
                  findings={report.findings}
                  scanners={scannerOptions(report)}
                  incomplete={report.scanners.some((sc) => sc.status === "error")}
                  added={comparison?.added}
                  previousLabel={comparison ? versionLabel(comparison.previousVersion) : undefined}
                />
              </Card>
              <CoverageCard report={report} />
              <DependenciesCard report={report} />
            </>
          )}
          <AnswersCard answers={s.answers} />
        </div>

        <aside className="min-w-0 space-y-6 print:mt-5" aria-label="Review and audit">
          <ReviewPanel
            id={s.id}
            status={s.status}
            decision={s.decision}
            reviewStatus={s.review_status}
            reviewer={s.reviewer}
            reviewComment={s.review_comment}
            reviewedAtLabel={s.reviewed_at ? formatDateTime(s.reviewed_at) : null}
            catalogStatus={s.catalog_status}
            publishedAtLabel={s.published_at ? formatDateTime(s.published_at) : null}
          />
          <AuditTrail events={events} gateLabels={gateLabels} />
        </aside>
      </div>

      <p className="text-[13px] text-subtle">
        Report generated {report ? formatDateTime(report.generatedAt) : "—"}
        {report?.engineVersion ? ` · engine ${report.engineVersion}` : ""} · submission <span className="font-mono text-xs">{s.id}</span>
      </p>
    </div>
  );
}

/* ------------------------------------------------------------------ hero */

type HeroTone = Decision | "neutral";

/** Literal class strings (Tailwind must see them). Colours follow the "Guided" result screen. */
const HERO: Record<HeroTone, { card: string; divider: string; pill: string; dot: string; row: string }> = {
  approved: {
    card: "border-[#ABEFC6] bg-[#F6FEF9]",
    divider: "border-[#D1F2DF]",
    pill: "bg-[#DCFAE6] text-[#067647]",
    dot: "bg-[#17B26A]",
    row: "border-[#CDEFDB] hover:border-[#75E0A7]",
  },
  conditional: {
    card: "border-[#F5D9A8] bg-[#FFFBF3]",
    divider: "border-[#F3E6CC]",
    pill: "bg-[#FDECC8] text-[#8A4B00]",
    dot: "bg-[#C27803]",
    row: "border-[#EEDFC4] hover:border-[#E0BF85]",
  },
  blocked: {
    card: "border-[#FDA29B] bg-[#FFFBFA]",
    divider: "border-[#FCD9D5]",
    pill: "bg-[#FEE4E2] text-[#9F1D14]",
    dot: "bg-[#D92D20]",
    row: "border-[#F9D3CF] hover:border-[#F3A49C]",
  },
  neutral: {
    card: "border-line bg-white",
    divider: "border-line",
    pill: "bg-[#F2F4F7] text-ink-2",
    dot: "bg-subtle",
    row: "border-line hover:border-line-strong",
  },
};

/** One or two short plain-language sentences: what the result means and what happens next. */
/** True for Agent Skill submissions (light intake, skill feedback in the report). */
function isSkillSubmission(s: Submission): boolean {
  return s.asset_type === "skill" || isSkill(s.answers ?? {});
}

function heroMessage(s: Submission, report: Report, decision: Decision): string {
  const skill = isSkillSubmission(s);
  const noun = skill ? "skill" : "asset";
  const feedback = skill && (report.skills?.length ?? 0) > 0;
  if (s.catalog_status === "published") {
    return `Published to the Azure AI catalogue${s.published_at ? ` on ${formatDate(s.published_at)}` : ""}. This report and the SBOM are attached to the catalogue entry.`;
  }
  if (s.review_status === "rejected") {
    return `Rejected by ${s.reviewer ?? "the reviewer"}. Address the reviewer's comment and the findings below, then submit a new version.`;
  }
  if (s.review_status === "approved") {
    return `Approved by ${s.reviewer ?? "the reviewer"}. The ${noun} can now be published to the Azure AI catalogue.`;
  }
  const blockingGates = report.gates.filter((g) => g.blocking && !g.passed);
  const failedBlocking = blockingGates.length;
  const failedOther = report.gates.filter((g) => !g.blocking && !g.passed).length;
  const counts = s.counts ?? countFindings(report.findings);
  if (decision === "blocked") {
    const names = blockingGates.map((g) => `“${g.label}”`).join(", ");
    return failedBlocking > 0
      ? `This ${noun} can't be published yet: ${plural(failedBlocking, "blocking check")} failed (${names}). Start with the “Fix first” list, then submit a new version.`
      : `This ${noun} can't be published yet. Fix the issues listed here, then submit a new version.`;
  }
  if (decision === "conditional") {
    if (skill) {
      return `No blocking issues, but a security reviewer has to accept the remaining risk before the skill is published.${
        feedback ? " The skill feedback below shows what to improve first." : ""
      }`;
    }
    return counts.high > 0
      ? `No blocking issues, but a security reviewer has to accept the remaining risk before publication. Fixing the ${plural(counts.high, "high-severity finding")} speeds up approval.`
      : `No blocking issues, but ${plural(failedOther, "check")} ${failedOther === 1 ? "needs" : "need"} a security reviewer's sign-off before the asset can be published.`;
  }
  if (skill) {
    return `All ${report.gates.length} checks passed. A security reviewer signs off next, then the skill can be published to the catalogue.${
      feedback ? " The skill feedback below has suggestions to make it even better." : ""
    }`;
  }
  return `All ${report.gates.length} checks passed. A security reviewer signs off next, then the asset can be published to the catalogue.`;
}

function Hero({ s, report, hasNewer }: { s: Submission; report: Report | null; hasNewer: boolean }) {
  const decision: Decision | null = report ? (s.decision ?? "conditional") : null;
  const tone: HeroTone = decision ?? (s.status === "failed" ? "blocked" : "neutral");
  const t = HERO[tone];
  const picks = report ? fixFirst(report.findings) : [];
  const reviewTone: Tone = s.review_status === "approved" ? "ok" : s.review_status === "rejected" ? "danger" : "neutral";

  let pill: ReactNode;
  let message: ReactNode;
  let cta: ReactNode = null;
  if (report && decision) {
    pill = DECISION_LABEL[decision];
    const text = heroMessage(s, report, decision);
    const partial = report.scanners.some((sc) => sc.status === "error") && s.catalog_status !== "published";
    message = partial ? `${text} Part of the scan did not finish, so the result may change when you submit again.` : text;
    if (!hasNewer) {
      // Fixing is the expected next step unless the asset is approved or published; then a new version is optional.
      const needsWork = s.review_status !== "approved" && s.catalog_status !== "published" && (decision !== "approved" || s.review_status === "rejected");
      cta = (
        <div className="mt-4 flex flex-wrap items-center gap-x-3 gap-y-2 print:hidden">
          <Link href={`/submit?previous=${s.id}`} className={needsWork ? btn.primary : btn.secondary}>
            Submit a new version
            <ArrowRightIcon size={16} />
          </Link>
          <span className="text-[13px] text-muted">Your answers are filled in, and the new report shows what you fixed.</span>
        </div>
      );
    }
  } else if (s.status === "failed") {
    pill = "Scan failed";
    message = (
      <span role="alert">
        {s.error ?? "An unexpected error occurred while scanning the upload. Check that the upload is a valid zip archive or source file."}{" "}
        Your questionnaire answers are kept in this browser, so you only need to provide the code again.
      </span>
    );
    cta = (
      <div className="mt-4 flex flex-wrap gap-2 print:hidden">
        <Link href={s.previous_id ? `/submit?previous=${s.previous_id}` : "/submit"} className={btn.primary}>
          Submit again
          <ArrowRightIcon size={16} />
        </Link>
        <Link href="/" className={btn.secondary}>
          Back to overview
        </Link>
      </div>
    );
  } else if (s.status === "scanning") {
    pill = (
      <>
        <SpinnerIcon size={14} />
        Scan in progress
      </>
    );
    message = (
      <span role="status">
        <AutoRefresh />
        The automated scan is still running. This page updates automatically when the result is ready, or{" "}
        <Link href={`/reports/${s.id}`} className="font-semibold text-brand hover:text-brand-strong">
          refresh now
        </Link>
        .
      </span>
    );
  } else {
    pill = "Report data unavailable";
    message = "The scan completed but no report was stored for this submission.";
  }

  return (
    <section aria-labelledby="report-title" className={`avoid-break rounded-2xl border p-6 sm:p-8 ${t.card}`}>
      <div className={`grid gap-8 ${report ? "xl:grid-cols-[minmax(0,1fr)_minmax(0,400px)]" : ""} print:block`}>
        <div className="min-w-0">
          <div className="flex flex-col gap-5 sm:flex-row sm:items-center sm:gap-6">
            {report ? (
              <div className="flex shrink-0 flex-col items-center gap-1.5">
                <ScoreRing score={s.score ?? 0} />
                <span className="text-xs font-medium text-subtle" aria-hidden="true">
                  Trust score · {(s.score ?? 0) >= PASS_SCORE ? "passes" : "needs"} ≥ {PASS_SCORE}
                </span>
              </div>
            ) : (
              <InitialsTile name={s.asset_name} size="lg" />
            )}
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`inline-flex h-7 items-center gap-2 rounded-full px-3 text-[13px] font-semibold ${t.pill}`}>
                  {(report || s.status !== "scanning") && <span className={`size-2 rounded-full ${t.dot}`} aria-hidden="true" />}
                  {pill}
                </span>
                {report && (
                  <StatusPill tone={s.catalog_status === "published" ? "brand" : reviewTone}>
                    {s.catalog_status === "published" ? "Published to catalogue" : REVIEW_LABEL[s.review_status]}
                  </StatusPill>
                )}
              </div>
              <h1 id="report-title" className="mt-3 text-[28px] font-bold leading-tight tracking-tight text-ink sm:text-[34px]">
                <span className="break-words">{s.asset_name}</span>
                {s.asset_version && (
                  <span className="ml-2.5 align-middle font-sans text-base font-medium tracking-normal text-subtle">v{s.asset_version.replace(/^v/i, "")}</span>
                )}
              </h1>
              <p className="mt-2 max-w-2xl text-base leading-7 text-muted">{message}</p>
              {cta}
            </div>
          </div>

          <dl className={`mt-7 grid grid-cols-1 gap-x-8 gap-y-4 border-t pt-6 sm:grid-cols-2 lg:grid-cols-3 ${t.divider}`}>
            <Fact label="Owner">
              {s.owner_name}
              <a href={`mailto:${s.owner_email}`} className="block truncate text-[13px] font-normal text-brand hover:text-brand-strong">
                {s.owner_email}
              </a>
            </Fact>
            <Fact label="Business unit">{businessUnitLabel(s.business_unit)}</Fact>
            <Fact label="Asset type">{isSkillSubmission(s) ? "Agent skill" : assetTypeLabel(s.asset_type)}</Fact>
            <Fact label="EU AI Act">
              <span
                title={s.ai_act_tier ? AI_ACT_LABEL[s.ai_act_tier] : undefined}
                className={s.ai_act_tier === "prohibited" ? "text-sev-critical" : s.ai_act_tier === "high" ? "text-sev-high-ink" : undefined}
              >
                {s.ai_act_tier ? AI_ACT_SHORT[s.ai_act_tier] : "Not classified"}
              </span>
            </Fact>
            <Fact label="Submitted">
              <span className="tabular">{formatDateTime(s.created_at)}</span>
            </Fact>
            <Fact label="Scanned file">
              <span className="flex min-w-0 items-center gap-1.5">
                <FileIcon size={15} className="shrink-0 text-subtle" />
                <span className="truncate print:whitespace-normal print:break-all" title={s.file_name ?? undefined}>
                  {s.file_name ?? "—"}
                </span>
              </span>
              <span className="mt-0.5 block text-[13px] font-normal text-subtle">
                <span className="tabular">{formatBytes(s.file_size)}</span>
                <span aria-hidden="true"> · </span>
                SHA-256{" "}
                <code className="font-mono text-xs text-ink-2" title={s.file_sha256 ?? undefined}>
                  <span className="print:hidden">{shortHash(s.file_sha256, 12)}</span>
                  <span className="hidden break-all print:inline">{s.file_sha256 ?? "—"}</span>
                </code>
              </span>
            </Fact>
          </dl>
        </div>

        {report && (
          <FixFirst
            picks={picks}
            total={report.findings.length}
            rowCls={t.row}
            incomplete={report.scanners.some((sc) => sc.status === "error")}
            ruleCounts={ruleCounts(report.findings)}
            added={new Set(report.comparison?.added ?? [])}
          />
        )}
      </div>
    </section>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[13px] text-subtle">{label}</dt>
      <dd className="mt-1 min-w-0 break-words text-sm font-medium text-ink">{children}</dd>
    </div>
  );
}

function FixFirst({
  picks,
  total,
  rowCls,
  incomplete,
  ruleCounts,
  added,
}: {
  picks: { f: Finding; index: number; blocking: boolean }[];
  total: number;
  rowCls: string;
  incomplete: boolean;
  ruleCounts: Map<string, number>;
  added: Set<number>;
}) {
  return (
    <div className="min-w-0 print:mt-6">
      <h2 className="font-sans text-[13px] font-bold uppercase tracking-[0.06em] text-muted">Fix first</h2>
      {picks.length > 0 && <p className="mt-1 text-[13px] leading-5 text-muted">The most important issues. Select one to see where it is and how to fix it.</p>}
      {picks.length === 0 ? (
        <div className="mt-3 flex gap-3 rounded-xl border border-line bg-white px-4 py-4">
          <CheckCircleIcon size={20} className="shrink-0 text-ok" />
          <div>
            <p className="text-[15px] font-semibold text-ink">Nothing to fix</p>
            <p className="mt-0.5 text-[13px] text-muted">
              {incomplete
                ? "Nothing was flagged, but the scan was incomplete. See the notice below."
                : total > 0
                  ? "Only informational findings were reported."
                  : "The scanners and the questionnaire came back clean."}
            </p>
          </div>
        </div>
      ) : (
        <>
          <ol className="mt-3 space-y-2.5">
            {picks.map(({ f, index, blocking }) => {
              const loc = findingLocation(f);
              const repeats = (ruleCounts.get(ruleKey(f)) ?? 1) - 1;
              return (
                <li key={findingAnchor(index)}>
                  <FixFirstLink
                    index={index}
                    className={`group flex items-center justify-between gap-3 rounded-xl border bg-white px-4 py-3.5 text-ink shadow-xs transition-colors ${rowCls}`}
                  >
                    <span className="flex min-w-0 flex-col gap-1">
                      <span className="break-words text-[15px] font-semibold leading-snug">{f.title}</span>
                      <span className="flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-0.5 text-[13px] text-muted">
                        <span className={`inline-flex items-center gap-1.5 font-semibold ${SEV_TEXT[f.severity]}`}>
                          <span className={`size-1.5 rounded-full ${SEV_BG[f.severity]}`} aria-hidden="true" />
                          {SEVERITY_LABEL[f.severity]}
                          {blocking ? " · blocks publication" : ""}
                        </span>
                        <span aria-hidden="true">·</span>
                        {loc ? (
                          <span className="min-w-0 break-all font-mono text-xs" title={loc}>
                            {shortPath(loc, 48)}
                          </span>
                        ) : (
                          <span>{SCANNER_LABEL[f.scanner] ?? f.scanner}</span>
                        )}
                        {repeats > 0 && (
                          <>
                            <span aria-hidden="true">·</span>
                            <span className="font-medium text-ink-2">+{repeats} more like this</span>
                          </>
                        )}
                        {added.has(index) && (
                          <>
                            <span aria-hidden="true">·</span>
                            <span className="font-semibold text-sev-high-ink">New</span>
                          </>
                        )}
                      </span>
                      {f.remediation && (
                        <span className="text-[13px] leading-5 text-ink-2">
                          <span className="font-semibold">Fix: </span>
                          {firstSentence(f.remediation)}
                        </span>
                      )}
                    </span>
                    <ArrowRightIcon size={18} className="shrink-0 text-brand transition-transform group-hover:translate-x-0.5 print:hidden" />
                  </FixFirstLink>
                </li>
              );
            })}
          </ol>
          {total > picks.length && (
            <a href="#findings" className="mt-3 inline-flex items-center gap-1 text-sm font-semibold text-brand hover:text-brand-strong print:hidden">
              See all {total} findings
              <ArrowRightIcon size={14} />
            </a>
          )}
        </>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ versions */

function NewerVersionNotice({ newer }: { newer: VersionRef }) {
  const result =
    newer.status === "completed" && newer.decision
      ? `${DECISION_LABEL[newer.decision]}${typeof newer.score === "number" ? `, score ${newer.score}` : ""}`
      : newer.status === "scanning"
        ? "scan in progress"
        : "scan failed";
  return (
    <div className="flex flex-col gap-3 rounded-xl border border-brand/25 bg-brand-soft px-5 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-6 print:hidden" role="note">
      <p className="flex items-start gap-2 text-sm leading-5 text-ink-2">
        <InfoIcon size={18} className="mt-px shrink-0 text-brand" />
        <span>
          <span className="font-semibold text-ink">A newer version was submitted</span>
          {newer.asset_version ? ` (${versionLabel(newer.asset_version)})` : ""} on {formatDate(newer.created_at)}: {result}. This report is kept for the
          record.
        </span>
      </p>
      <Link href={`/reports/${newer.id}`} className={`${btn.primary} shrink-0`}>
        Open the latest report
        <ArrowRightIcon size={16} />
      </Link>
    </div>
  );
}

const MAX_CHANGE_ROWS = 6;

interface ChangeRow {
  key: string;
  title: string;
  severity: Severity;
  count: number;
  /** Location when the rule fired once. */
  loc: string | null;
  /** Finding index in this report (new and still-open rows link to it). */
  index?: number;
  note?: string;
}

function fixedRows(fixed: ComparedFinding[]): ChangeRow[] {
  const map = new Map<string, ChangeRow & { waived: number }>();
  for (const f of fixed) {
    const k = ruleKey(f);
    const loc = f.file ? (f.line ? `${f.file}:${f.line}` : f.file) : null;
    const hit = map.get(k);
    if (!hit) {
      map.set(k, { key: k, title: f.title, severity: f.severity, count: 1, loc, waived: f.waived ? 1 : 0 });
      continue;
    }
    hit.count++;
    hit.loc = null;
    if (f.waived) hit.waived++;
    if (SEV_RANK[f.severity] < SEV_RANK[hit.severity]) hit.severity = f.severity;
  }
  return [...map.values()]
    .map(({ waived, ...r }) => ({
      ...r,
      note: waived === 0 ? undefined : waived === r.count ? "now an exception or test code" : `${waived} now an exception or test code`,
    }))
    .sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || b.count - a.count);
}

function currentRows(report: Report, list: { index: number; was?: Severity }[]): ChangeRow[] {
  const indexed = list.filter((x) => report.findings[x.index]).map((x) => ({ f: report.findings[x.index], index: x.index, was: x.was }));
  return groupByRule(indexed).map(({ f, index, count, was }) => ({
    key: ruleKey(f),
    title: f.title,
    severity: f.severity,
    count,
    loc: count === 1 ? findingLocation(f) : null,
    index,
    note: was && count === 1 ? `was ${SEVERITY_LABEL[was]}` : undefined,
  }));
}

function ComparisonCard({ s, report, c }: { s: Submission; report: Report; c: Comparison }) {
  const prev = versionLabel(c.previousVersion);
  const fixed = c.fixedTotal;
  const added = c.added.length;
  const open = c.open.length;
  const before = fixed + open;
  const pct = before > 0 ? Math.round((fixed / before) * 100) : 0;
  const delta = typeof s.score === "number" && typeof c.previousScore === "number" ? s.score - c.previousScore : null;
  const newIssues = added > 0 ? ` ${plural(added, "new issue")} appeared.` : " No new issues.";

  let headline: string;
  if (before === 0) headline = added === 0 ? `Nothing to fix in ${prev}, and still nothing to fix.` : `${prev} had nothing to fix.${newIssues}`;
  else if (fixed === before) headline = `All ${plural(before, "issue")} from ${prev} ${before === 1 ? "is" : "are"} fixed.${newIssues}`;
  else if (fixed > 0) headline = `You fixed ${fixed} of the ${plural(before, "issue")} from ${prev}.${newIssues}`;
  else headline = `None of the ${plural(before, "issue")} from ${prev} ${before === 1 ? "is" : "are"} fixed yet.${newIssues}`;

  const fixedList = fixedRows(c.fixed);
  const newList = currentRows(report, c.added.map((index) => ({ index })));
  const openList = currentRows(report, c.open);
  const engineChanged = !!c.previousEngineVersion && c.previousEngineVersion !== report.engineVersion;

  const tiles: { label: string; value: ReactNode; sub: string; cls: string }[] = [
    {
      label: "Fixed",
      value: fixed,
      sub: before > 0 ? `${pct}% of ${prev}'s issues` : "No earlier issues",
      cls: fixed > 0 ? "border-[#ABEFC6] bg-[#F6FEF9] text-ok" : "border-line text-ink",
    },
    { label: "New", value: added, sub: added > 0 ? "Not in the previous version" : "Nothing new", cls: added > 0 ? "border-[#F9D3CF] bg-[#FFFBFA] text-sev-critical" : "border-line text-ink" },
    { label: "Still open", value: open, sub: open > 0 ? "Carried over" : "Nothing carried over", cls: "border-line text-ink" },
    {
      label: "Trust score",
      value: (
        <>
          {c.previousScore ?? "—"} <span className="text-subtle">→</span> {s.score ?? "—"}
        </>
      ),
      sub: delta === null ? "" : delta === 0 ? "Unchanged" : `${delta > 0 ? "+" : ""}${delta} points`,
      cls: delta !== null && delta > 0 ? "border-line text-ok" : delta !== null && delta < 0 ? "border-line text-sev-critical" : "border-line text-ink",
    },
  ];

  return (
    <Card id="changes" labelledBy="changes-title" className="avoid-break scroll-mt-24">
      <CardHeader
        id="changes-title"
        title={`Since ${prev}`}
        description={
          <>
            {headline} Compared with {prev}, submitted {formatDate(c.previousSubmittedAt)}
            {c.previousDecision ? ` (${DECISION_LABEL[c.previousDecision]})` : ""}.
          </>
        }
        actions={
          <Link href={`/reports/${c.previousId}`} className={`${btn.secondary} print:hidden`}>
            Previous report
          </Link>
        }
      />
      <div className="space-y-5 px-5 py-5 sm:px-6">
        {before > 0 && (
          <div>
            <div className="flex items-center justify-between text-[13px] text-muted">
              <span>Progress on the issues from {prev}</span>
              <span className="tabular font-semibold text-ink-2">
                {fixed}/{before}
              </span>
            </div>
            <div className="mt-1.5 h-2 overflow-hidden rounded-full bg-line" role="img" aria-label={`${pct}% of the issues from ${prev} fixed`}>
              <span className="block h-full rounded-full bg-ok" style={{ width: `${pct}%` }} />
            </div>
          </div>
        )}

        <dl className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          {tiles.map((t) => (
            <div key={t.label} className={`min-w-0 rounded-lg border px-3.5 py-3 ${t.cls}`}>
              <dt className="truncate text-[13px] text-subtle">{t.label}</dt>
              <dd className="tabular mt-1 font-display text-xl font-semibold">{t.value}</dd>
              {t.sub && <dd className="mt-0.5 truncate text-xs text-muted">{t.sub}</dd>}
            </div>
          ))}
        </dl>

        {c.previousDecision && s.decision && c.previousDecision !== s.decision && (
          <p className="text-[13px] text-ink-2">
            Decision changed from <span className="font-semibold">{DECISION_LABEL[c.previousDecision]}</span> to{" "}
            <span className="font-semibold">{DECISION_LABEL[s.decision]}</span>.
          </p>
        )}

        <div className="grid gap-5 md:grid-cols-2">
          <ChangeList
            title="Fixed"
            icon={<CheckCircleIcon size={16} className="text-ok" />}
            rows={fixedList}
            empty="Nothing from the previous version was fixed yet."
            more={fixed - c.fixed.length}
            struck
          />
          <ChangeList title="New" icon={<AlertIcon size={16} className="text-sev-critical" />} rows={newList} empty="No new issues. Nice work." />
        </div>

        {openList.length > 0 && (
          <details className="group rounded-lg border border-line">
            <summary className="flex items-center justify-between gap-2 px-4 py-3 text-sm font-semibold text-ink">
              <span>
                Still open: {plural(open, "finding")} in {plural(openList.length, "issue")}
              </span>
              <ChevronRightIcon size={16} className="text-subtle transition-transform group-open:rotate-90" />
            </summary>
            <div className="border-t border-line px-4 py-3">
              <ChangeList rows={openList} empty="" bare />
            </div>
          </details>
        )}

        {engineChanged && (
          <p className="flex gap-2 text-[13px] leading-5 text-muted">
            <InfoIcon size={16} className="mt-0.5 shrink-0 text-brand" />
            <span>
              The scanner was updated between the two versions (engine {c.previousEngineVersion} → {report.engineVersion}). Some new findings may come from
              new checks rather than from changes to your code.
            </span>
          </p>
        )}
      </div>
    </Card>
  );
}

function ChangeList({
  title,
  icon,
  rows,
  empty,
  more = 0,
  struck = false,
  bare = false,
}: {
  title?: string;
  icon?: ReactNode;
  rows: ChangeRow[];
  empty: string;
  more?: number;
  struck?: boolean;
  bare?: boolean;
}) {
  const shown = bare ? rows : rows.slice(0, MAX_CHANGE_ROWS);
  const hidden = rows.length - shown.length;
  return (
    <div className="min-w-0">
      {title && (
        <h3 className="flex items-center gap-1.5 text-[13px] font-semibold text-ink">
          {icon}
          {title}
        </h3>
      )}
      {rows.length === 0 ? (
        <p className={`${title ? "mt-1.5" : ""} text-[13px] text-muted`}>{empty}</p>
      ) : (
        <ul className={`${title ? "mt-1.5" : ""} space-y-1.5`}>
          {shown.map((r) => {
            const body = (
              <span className="flex min-w-0 flex-col">
                <span className={`break-words text-[13px] font-medium leading-5 ${struck ? "text-muted line-through decoration-faint" : "text-ink group-hover:underline"}`}>
                  {r.title}
                </span>
                <span className="flex flex-wrap items-center gap-x-1.5 text-xs text-subtle">
                  <span className={`inline-flex items-center gap-1 font-semibold ${SEV_TEXT[r.severity]}`}>
                    <span className={`size-1.5 rounded-full ${SEV_BG[r.severity]}`} aria-hidden="true" />
                    {SEVERITY_LABEL[r.severity]}
                  </span>
                  {r.count > 1 ? (
                    <span>· {r.count} places</span>
                  ) : r.loc ? (
                    <span className="min-w-0 break-all font-mono" title={r.loc}>
                      · {shortPath(r.loc, 44)}
                    </span>
                  ) : null}
                  {r.note && <span>· {r.note}</span>}
                </span>
              </span>
            );
            return (
              <li key={r.key} className="min-w-0">
                {r.index !== undefined ? (
                  <FixFirstLink index={r.index} className="group flex min-w-0 items-start gap-1.5">
                    <ArrowRightIcon size={13} className="mt-1 shrink-0 text-brand print:hidden" />
                    {body}
                  </FixFirstLink>
                ) : (
                  <div className="flex min-w-0 items-start gap-1.5">
                    <CheckIcon size={13} className="mt-1 shrink-0 text-ok" />
                    {body}
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
      {(hidden > 0 || more > 0) && (
        <p className="mt-1.5 text-xs text-muted">
          and {hidden > 0 ? plural(hidden, "more issue") : ""}
          {hidden > 0 && more > 0 ? ", plus " : ""}
          {more > 0 ? `${more} more not listed` : ""}
        </p>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ cards */

const MAX_GATE_LINKS = 3;

function GatesCard({ report }: { report: Report }) {
  const passed = report.gates.filter((g) => g.passed).length;
  const failed = report.gates.length - passed;
  // Failed blocking checks first, then failed non-blocking, then passed; otherwise keep the policy order.
  const order = (g: GateResult) => (g.passed ? 2 : g.blocking ? 0 : 1);
  const gates = report.gates.map((g, i) => ({ g, i })).sort((a, b) => order(a.g) - order(b.g) || a.i - b.i);
  const indexed = report.findings.map((f, index) => ({ f, index }));
  return (
    <Card id="gates" labelledBy="gates-title" className="scroll-mt-24">
      <CardHeader
        id="gates-title"
        title="What's needed for approval"
        meta={`${passed}/${report.gates.length} passed`}
        description={
          failed === 0
            ? "All checks pass. A security reviewer signs off next."
            : "Every check must pass for a smooth approval. A failed blocking check stops publication until it is fixed; any other failed check needs a security reviewer's sign-off."
        }
      />
      <ul className="divide-y divide-line">
        {gates.map(({ g }) => {
          const match = GATE_FINDINGS[g.id];
          const causes = !g.passed && match ? groupByRule(indexed.filter((x) => match(x.f))) : [];
          const action = g.passed ? null : gateAction(g, report);
          const status = g.passed ? "Passed" : g.blocking ? "Blocks publication" : "Needs reviewer sign-off";
          return (
            <li key={g.id} className="avoid-break flex items-start gap-3 px-5 py-4 sm:px-6">
              {g.passed ? (
                <CheckCircleIcon size={20} className="shrink-0 text-ok" />
              ) : g.blocking ? (
                <XCircleIcon size={20} className="shrink-0 text-sev-critical" />
              ) : (
                <AlertIcon size={20} className="shrink-0 text-warn" />
              )}
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium text-ink">{g.label}</span>
                    {g.blocking && (
                      <span className="inline-flex h-5 items-center rounded-md bg-white px-1.5 text-[11px] font-semibold text-muted ring-1 ring-inset ring-line-strong">
                        Blocking
                      </span>
                    )}
                  </span>
                  <StatusPill tone={g.passed ? "ok" : g.blocking ? "danger" : "warn"}>{status}</StatusPill>
                </div>
                <p className="mt-0.5 text-[13px] leading-5 text-muted">{g.detail}</p>
                {action && (
                  <p className="mt-2 text-[13px] leading-5 text-ink-2">
                    <span className="font-semibold text-ink">What to do: </span>
                    {action}
                  </p>
                )}
                {causes.length > 0 && (
                  <div className="mt-2.5">
                    <p className="text-xs font-medium text-subtle">Caused by</p>
                    <ul className="mt-1 space-y-1">
                      {causes.slice(0, MAX_GATE_LINKS).map(({ f, index, count }) => {
                        const loc = findingLocation(f);
                        return (
                          <li key={index} className="min-w-0 text-[13px] leading-5">
                            <FixFirstLink index={index} className="group inline-flex max-w-full items-baseline gap-1.5 text-brand hover:text-brand-strong">
                              <ArrowRightIcon size={13} className="shrink-0 translate-y-0.5 print:hidden" />
                              <span className="min-w-0 break-words">
                                <span className="font-medium group-hover:underline">{f.title}</span>
                                {count > 1 ? (
                                  <span className="ml-1.5 text-xs font-medium text-muted">{count} places</span>
                                ) : (
                                  loc && (
                                    <span className="ml-1.5 break-all font-mono text-xs text-muted" title={loc}>
                                      {shortPath(loc, 48)}
                                    </span>
                                  )
                                )}
                              </span>
                            </FixFirstLink>
                          </li>
                        );
                      })}
                    </ul>
                    {causes.length > MAX_GATE_LINKS && (
                      <a href="#findings" className="mt-1 inline-block text-[13px] font-semibold text-brand hover:text-brand-strong print:hidden">
                        and {plural(causes.length - MAX_GATE_LINKS, "more issue")} in the findings list
                      </a>
                    )}
                  </div>
                )}
              </div>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

/** Tells the reader when the result is less than complete: scanner errors, skipped files, suppressed findings. */
function ScanNotice({ report }: { report: Report }) {
  const { failed, skippedFiles, totalFiles, suppressed } = scanGaps(report);
  if (failed.length === 0 && skippedFiles === 0 && suppressed === 0) return null;
  const incomplete = failed.length > 0;
  return (
    <section
      aria-labelledby="scan-notice-title"
      className={`avoid-break rounded-xl border px-5 py-4 sm:px-6 ${incomplete ? "border-[#FEDF89] bg-warn-soft" : "border-line bg-white shadow-xs"}`}
    >
      <h2 id="scan-notice-title" className="flex items-center gap-2 text-[15px] font-semibold text-ink">
        {incomplete ? <AlertIcon size={18} className="shrink-0 text-warn" /> : <InfoIcon size={18} className="shrink-0 text-brand" />}
        {incomplete ? "This scan is incomplete" : "About this scan"}
      </h2>
      <ul className="mt-2 space-y-2 text-[13px] leading-5 text-ink-2">
        {failed.map((sc, i) => (
          <li key={`${sc.id}-${i}`}>
            <span className="font-semibold text-ink">{sc.name || SCANNER_LABEL[sc.id] || sc.id} did not finish.</span>{" "}
            {sc.id === "dependencies"
              ? "Known vulnerabilities in your packages were not (fully) checked, so the dependency results below may be missing issues."
              : "Issues of this type may be missing from the report."}{" "}
            {sc.note && <span className="break-words text-muted">Details: {sc.note}</span>}
          </li>
        ))}
        {incomplete && (
          <li>
            The decision is based only on what was checked. Submit the same version again later to get a complete result; reviewers see this notice too.
          </li>
        )}
        {skippedFiles > 0 && (
          <li>
            <span className="font-semibold text-ink">
              {formatNumber(skippedFiles)}
              {totalFiles > 0 ? ` of ${formatNumber(totalFiles)}` : ""} {skippedFiles === 1 ? "file was" : "files were"} not content-scanned
            </span>{" "}
            (for example <code className="font-mono text-xs">node_modules</code>, build output, binaries or files over the size limit).{" "}
            <a href="#coverage" className="font-semibold text-brand hover:text-brand-strong">
              See scanner coverage
            </a>
            .
          </li>
        )}
        {suppressed > 0 && (
          <li>
            <span className="font-semibold text-ink">
              {plural(suppressed, "finding was", "findings were")} downgraded to Info
            </span>{" "}
            because {suppressed === 1 ? "it is" : "they are"} in test or example code or marked as an exception (<code className="font-mono text-xs">nosec</code>,{" "}
            <code className="font-mono text-xs">aigate:ignore</code>, <code className="font-mono text-xs">.aigateignore</code>). They don&apos;t count towards
            the decision, but they stay visible in the findings list and a reviewer checks that each exception is justified.
          </li>
        )}
      </ul>
    </section>
  );
}

function scannerOptions(report: Report): { id: ScannerId; label: string }[] {
  const out: { id: ScannerId; label: string }[] = [];
  const seen = new Set<string>();
  for (const sc of report.scanners) {
    if (seen.has(sc.id)) continue;
    seen.add(sc.id);
    out.push({ id: sc.id, label: sc.name || SCANNER_LABEL[sc.id] || sc.id });
  }
  for (const f of report.findings) {
    if (seen.has(f.scanner)) continue;
    seen.add(f.scanner);
    out.push({ id: f.scanner, label: SCANNER_LABEL[f.scanner] ?? f.scanner });
  }
  return out;
}

const SCANNER_STATUS: Record<"ok" | "skipped" | "error", { tone: Tone; label: string }> = {
  ok: { tone: "ok", label: "Completed" },
  skipped: { tone: "muted", label: "Skipped" },
  error: { tone: "danger", label: "Error" },
};

function CoverageCard({ report }: { report: Report }) {
  const st = report.stats;
  const langs = Object.entries(st.languages ?? {})
    .filter(([, n]) => typeof n === "number" && n > 0)
    .sort((a, b) => b[1] - a[1]);
  const top = langs.slice(0, 5);
  const rest = langs.slice(5).reduce((a, [, n]) => a + n, 0);
  const segments = rest > 0 ? [...top, ["Other", rest] as [string, number]] : top;
  const total = segments.reduce((a, [, n]) => a + n, 0);

  const stats: { label: string; value: string }[] = [
    { label: "Files scanned", value: `${formatNumber(st.filesScanned)} / ${formatNumber(st.filesTotal)}` },
    { label: "Files skipped", value: formatNumber(st.filesSkipped) },
    { label: "Lines analysed", value: formatNumber(st.linesScanned) },
    { label: "Bytes analysed", value: formatBytes(st.bytesScanned) },
    { label: "Packages", value: formatNumber(st.packages) },
    { label: "Model files", value: formatNumber(st.modelFiles) },
  ];

  return (
    <Card id="coverage" labelledBy="coverage-title" className="scroll-mt-24">
      <CardHeader
        id="coverage-title"
        title="Scanner coverage"
        description="What was analysed, by which engine, and how long it took. Skipped files are dependency and build folders, binaries, or files over the size limit."
      />

      <dl className="grid grid-cols-2 gap-3 px-5 py-5 sm:grid-cols-3 sm:px-6 xl:grid-cols-6">
        {stats.map((x) => (
          <div key={x.label} className="min-w-0 rounded-lg border border-line px-3.5 py-3">
            <dt className="truncate text-[13px] text-subtle">{x.label}</dt>
            <dd className="tabular mt-1 truncate font-display text-lg font-semibold text-ink">{x.value}</dd>
          </div>
        ))}
      </dl>

      <TableScroll label="Scanner coverage table">
        <table className="w-full min-w-[620px] border-collapse">
          <thead className={`${thead} border-t`}>
            <tr>
              <th scope="col" className={`${thc} text-left`}>Scanner</th>
              <th scope="col" className={`${thc} text-left`}>Engine / ruleset</th>
              <th scope="col" className={`${thc} text-left`}>Status</th>
              <th scope="col" className={`${thc} text-right`}>Findings</th>
              <th scope="col" className={`${thc} text-right`}>Duration</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {report.scanners.map((sc, i) => {
              const status = SCANNER_STATUS[sc.status] ?? SCANNER_STATUS.ok;
              return (
                <tr key={`${sc.id}-${i}`}>
                  <td className={`${tdc} font-medium text-ink`}>
                    {sc.name || SCANNER_LABEL[sc.id]}
                    {sc.note && (
                      <div className={`mt-0.5 max-w-prose break-words text-[13px] font-normal ${sc.status === "error" ? "text-sev-critical" : "text-subtle"}`}>{sc.note}</div>
                    )}
                  </td>
                  <td className={`${tdc} text-muted`}>{sc.engine}</td>
                  <td className={tdc}>
                    <StatusPill tone={status.tone}>{status.label}</StatusPill>
                  </td>
                  <td className={`${tdc} tabular text-right ${sc.findings ? "font-semibold text-ink" : "text-subtle"}`}>{sc.findings}</td>
                  <td className={`${tdc} tabular text-right text-muted`}>{formatDuration(sc.durationMs)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </TableScroll>

      {total > 0 && (
        <div className="border-t border-line px-5 py-5 sm:px-6">
          <div className="mb-2 text-[13px] font-medium text-ink-2">Languages</div>
          <div
            className="flex h-2 overflow-hidden rounded-full bg-line"
            role="img"
            aria-label={segments.map(([l, n]) => `${l} ${Math.round((n / total) * 100)}%`).join(", ")}
          >
            {segments.map(([lang, n], i) => (
              <span key={lang} className={`${LANG_COLORS[i % LANG_COLORS.length]} h-full border-r-2 border-white last:border-r-0`} style={{ width: `${(n / total) * 100}%` }} />
            ))}
          </div>
          <ul className="mt-3 flex flex-wrap gap-x-5 gap-y-1.5 text-[13px] text-ink-2">
            {segments.map(([lang, n], i) => (
              <li key={lang} className="flex items-center gap-1.5">
                <span className={`size-2 rounded-full ${LANG_COLORS[i % LANG_COLORS.length]}`} aria-hidden="true" />
                {lang}
                <span className="tabular text-subtle">{Math.round((n / total) * 100)}%</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
}

function DependenciesCard({ report }: { report: Report }) {
  const rows = report.packages.length ? dependencyRows(report.packages, report.findings) : [];
  const vulnerable = rows.filter((r) => r.vuln).length;
  const check = vulnCheckState(report);
  const basis = report.packages.some((p) => Array.isArray(p.licenses))
    ? "Third-party packages found in your manifests and lockfiles, checked against the OSV.dev vulnerability database; licences from deps.dev."
    : "Third-party packages found in your manifests and lockfiles, checked against the OSV.dev vulnerability database.";
  return (
    <Card id="dependencies" labelledBy="deps-title" className="scroll-mt-24">
      <CardHeader
        id="deps-title"
        title="Dependencies"
        meta={report.packages.length}
        description={
          rows.length ? (
            <>
              {basis}{" "}
              {vulnerable > 0 ? (
                <span className="font-medium text-sev-critical">
                  {plural(vulnerable, "package")} with known vulnerabilities. Upgrade to the fixed version named in each finding.
                </span>
              ) : check === "unavailable" ? (
                <span className="font-medium text-warn">The vulnerability database could not be reached, so packages were not checked.</span>
              ) : check === "partial" ? (
                <span className="font-medium text-warn">No known vulnerabilities found, but the check was incomplete.</span>
              ) : (
                <span className="font-medium text-ok">No known vulnerabilities.</span>
              )}
              {vulnerable > 0 && check !== "ok" ? <span className="font-medium text-warn"> The check was incomplete, so there may be more.</span> : null}
            </>
          ) : (
            basis
          )
        }
      />
      {rows.length ? (
        <DependencyTable rows={rows} vulnCheck={check} />
      ) : (
        <p className="px-5 py-8 text-center text-sm text-muted sm:px-6">No package manifests were found in the upload.</p>
      )}
    </Card>
  );
}

function AnswersCard({ answers }: { answers: Submission["answers"] }) {
  const a = answers ?? {};
  return (
    <Card labelledBy="answers-title">
      <CardHeader id="answers-title" title="Questionnaire answers" description="As submitted by the asset owner. Flagged answers add findings to the report." />
      <div className="divide-y divide-line">
        {SECTIONS.map((section) => {
          const qs = section.questions.filter((q) => isVisible(q, a));
          if (qs.length === 0) return null;
          const flagged = qs.filter((q) => answerSeverity(q.id, a[q.id]) !== null).length;
          return (
            <section key={section.id} aria-labelledby={`ans-${section.id}`} className="avoid-break px-5 py-5 sm:px-6">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <h3 id={`ans-${section.id}`} className="flex items-center gap-2 text-[15px] font-semibold text-ink">
                  {section.title}
                  {flagged > 0 && <StatusPill tone="warn">{flagged} flagged</StatusPill>}
                </h3>
                <span className="inline-flex h-6 items-center rounded-full bg-surface-2 px-2.5 text-xs font-medium text-muted ring-1 ring-inset ring-line">
                  {section.framework}
                </span>
              </div>
              <dl className="divide-y divide-line rounded-lg border border-line">
                {qs.map((q) => {
                  const v = a[q.id];
                  const sev = answerSeverity(q.id, v);
                  const empty = v === undefined || (Array.isArray(v) ? v.length === 0 : String(v).trim() === "");
                  return (
                    <div key={q.id} className="grid gap-1 px-4 py-3 md:grid-cols-[minmax(0,2fr)_minmax(0,3fr)] md:gap-6">
                      <dt className="text-[13px] leading-5 text-muted">{q.label}</dt>
                      <dd className="flex min-w-0 items-start justify-between gap-3 text-sm leading-5 text-ink">
                        <span className="min-w-0 whitespace-pre-line break-words">{empty ? <span className="italic text-subtle">Not answered</span> : answerLabel(q.id, v)}</span>
                        {sev && <SeverityChip severity={sev} />}
                      </dd>
                    </div>
                  );
                })}
              </dl>
            </section>
          );
        })}
      </div>
    </Card>
  );
}

function AuditTrail({ events, gateLabels }: { events: AuditEvent[]; gateLabels: Map<string, string> }) {
  return (
    <Card labelledBy="audit-title" as="section">
      <CardHeader id="audit-title" title="Audit trail" meta={events.length} />
      {events.length === 0 ? (
        <p className="px-5 py-6 text-sm text-muted">No events recorded.</p>
      ) : (
        <ol className="px-5 py-5">
          {events.map((e, i) => {
            const summary = eventSummary(e.detail ?? {}, gateLabels);
            const rawComment = e.detail ? e.detail.comment : undefined;
            const comment = typeof rawComment === "string" ? rawComment : null;
            const last = i === events.length - 1;
            return (
              <li key={e.id} className={`avoid-break relative pl-6 ${last ? "" : "pb-5"}`}>
                {!last && <span className="absolute bottom-0 left-[4.5px] top-4 w-px bg-line" aria-hidden="true" />}
                <span className={`absolute left-0 top-1.5 size-2.5 rounded-full ring-4 ring-white ${ACTION_DOT[e.action] ?? "bg-faint"}`} aria-hidden="true" />
                <div className="text-sm font-medium text-ink">{ACTION_LABEL[e.action] ?? humanize(e.action)}</div>
                <div className="mt-0.5 text-[13px] text-subtle">
                  <time dateTime={e.created_at} className="tabular">
                    {formatDateTime(e.created_at)}
                  </time>{" "}
                  · {e.actor}
                </div>
                {summary.length > 0 && <div className="mt-1 break-words text-[13px] leading-5 text-muted">{summary.join(" · ")}</div>}
                {comment && <p className="mt-2 rounded-lg border border-line bg-surface-2 px-3 py-2 text-[13px] leading-5 text-ink-2">{comment}</p>}
              </li>
            );
          })}
        </ol>
      )}
    </Card>
  );
}
