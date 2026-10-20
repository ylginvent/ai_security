import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { cache, type ReactNode } from "react";
import { Card, CardHeader, InitialsTile, TableScroll, btn, thead } from "@/components/Card";
import {
  AlertIcon,
  ArrowRightIcon,
  CheckCircleIcon,
  ChevronRightIcon,
  DownloadIcon,
  FileIcon,
  SpinnerIcon,
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
} from "@/lib/format";
import { AI_ACT_LABEL, ALL_QUESTIONS, SECTIONS, answerLabel, isVisible } from "@/lib/questionnaire";
import { DECISION_LABEL, PASS_SCORE } from "@/lib/scoring";
import { getStore } from "@/lib/store";
import { SEVERITIES, type AuditEvent, type Decision, type Finding, type PackageRef, type Report, type ScannerId, type Severity, type Submission } from "@/lib/types";
import { findingAnchor } from "./anchors";
import DependencyTable, { type DependencyRow } from "./DependencyTable";
import FindingsExplorer from "./FindingsExplorer";
import FixFirstLink from "./FixFirstLink";
import PrintButton from "./PrintButton";
import ReviewPanel from "./ReviewPanel";

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

/** Links dependency findings to packages by name (title first, then snippet and description). */
function dependencyRows(packages: PackageRef[], findings: Finding[]): DependencyRow[] {
  const deps = findings.filter((f) => f.scanner === "dependencies");
  const rows = packages.map((pkg): DependencyRow => {
    if (!pkg.name || deps.length === 0) return { pkg, vuln: null };
    const re = new RegExp(`(^|[^A-Za-z0-9_.@/-])${escapeRegExp(pkg.name)}($|[^A-Za-z0-9_/-])`, "i");
    const hits = deps.filter((f) => re.test(f.title) || (f.snippet ? re.test(f.snippet) : false) || re.test(f.description));
    if (!hits.length) return { pkg, vuln: null };
    const severity = hits.reduce<Severity>((best, f) => (SEV_RANK[f.severity] < SEV_RANK[best] ? f.severity : best), "info");
    return { pkg, vuln: { severity, count: hits.length } };
  });
  return rows.sort((a, b) => {
    const va = a.vuln ? SEV_RANK[a.vuln.severity] : 9;
    const vb = b.vuln ? SEV_RANK[b.vuln.severity] : 9;
    return va - vb || a.pkg.name.localeCompare(b.pkg.name);
  });
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

/**
 * The three findings to fix first: most severe first (info excluded). Within one severity,
 * findings from a rule that is not yet in the list win over repeats of the same rule.
 */
function fixFirst(findings: Finding[]): { f: Finding; index: number }[] {
  const ranked = findings
    .map((f, index) => ({ f, index }))
    .filter((x) => x.f.severity !== "info")
    .sort((a, b) => SEV_RANK[a.f.severity] - SEV_RANK[b.f.severity] || a.index - b.index);
  const seen = new Set<string>();
  const withRepeat = ranked.map((x) => {
    const rule = `${x.f.scanner}:${x.f.ruleId}`;
    const repeat = seen.has(rule) ? 1 : 0;
    seen.add(rule);
    return { ...x, repeat };
  });
  return withRepeat
    .sort((a, b) => SEV_RANK[a.f.severity] - SEV_RANK[b.f.severity] || a.repeat - b.repeat || a.index - b.index)
    .slice(0, 3)
    .map(({ f, index }) => ({ f, index }));
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

  let events: AuditEvent[] = [];
  try {
    events = await getStore().events(s.id);
  } catch (e) {
    console.error("audit events", e);
  }

  const report = s.status === "completed" ? s.report : null;
  const gateLabels = new Map((report?.gates ?? []).map((g) => [g.id, g.label] as const));

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

      <Hero s={s} report={report} />

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
                  description="Everything the scanners and the questionnaire flagged. Open a finding to see what it means and how to fix it."
                />
                <FindingsExplorer findings={report.findings} scanners={scannerOptions(report)} />
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
function heroMessage(s: Submission, report: Report, decision: Decision): string {
  if (s.catalog_status === "published") {
    return `Published to the Azure AI catalogue${s.published_at ? ` on ${formatDate(s.published_at)}` : ""}. This report and the SBOM are attached to the catalogue entry.`;
  }
  if (s.review_status === "rejected") {
    return `Rejected by ${s.reviewer ?? "the reviewer"}. Address the reviewer's comment and the findings below, then submit a new version.`;
  }
  if (s.review_status === "approved") {
    return `Approved by ${s.reviewer ?? "the reviewer"}. The asset can now be published to the Azure AI catalogue.`;
  }
  const failedBlocking = report.gates.filter((g) => g.blocking && !g.passed).length;
  const failedOther = report.gates.filter((g) => !g.blocking && !g.passed).length;
  const counts = s.counts ?? countFindings(report.findings);
  if (decision === "blocked") {
    return `This asset can't be published yet: ${plural(failedBlocking, "blocking check")} failed. Fix the issues listed here, then submit a new version.`;
  }
  if (decision === "conditional") {
    return counts.high > 0
      ? `No blocking issues, but a security reviewer has to accept the remaining risk before publication. Fixing the ${plural(counts.high, "high-severity finding")} speeds up approval.`
      : `No blocking issues, but ${plural(failedOther, "check")} ${failedOther === 1 ? "needs" : "need"} a security reviewer's sign-off before the asset can be published.`;
  }
  return `All ${report.gates.length} checks passed. A security reviewer signs off next, then the asset can be published to the catalogue.`;
}

function Hero({ s, report }: { s: Submission; report: Report | null }) {
  const decision: Decision | null = report ? (s.decision ?? "conditional") : null;
  const tone: HeroTone = decision ?? (s.status === "failed" ? "blocked" : "neutral");
  const t = HERO[tone];
  const picks = report ? fixFirst(report.findings) : [];
  const reviewTone: Tone = s.review_status === "approved" ? "ok" : s.review_status === "rejected" ? "danger" : "neutral";

  let pill: ReactNode;
  let message: ReactNode;
  if (report && decision) {
    pill = DECISION_LABEL[decision];
    message = heroMessage(s, report, decision);
  } else if (s.status === "failed") {
    pill = "Scan failed";
    message = (
      <span role="alert">
        {s.error ?? "An unexpected error occurred while scanning the upload."} Check that the upload is a valid zip archive or source file, then{" "}
        <Link href="/submit" className="font-semibold text-brand hover:text-brand-strong">
          submit it again
        </Link>
        .
      </span>
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
        The automated scan is still running.{" "}
        <Link href={`/reports/${s.id}`} className="font-semibold text-brand hover:text-brand-strong">
          Refresh
        </Link>{" "}
        in a few seconds to see the result.
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
                <span className="text-xs font-medium text-subtle">Trust score · pass ≥ {PASS_SCORE}</span>
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
            <Fact label="Asset type">{assetTypeLabel(s.asset_type)}</Fact>
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
            <Fact label="Uploaded file">
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

        {report && <FixFirst picks={picks} total={report.findings.length} rowCls={t.row} />}
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

function FixFirst({ picks, total, rowCls }: { picks: { f: Finding; index: number }[]; total: number; rowCls: string }) {
  return (
    <div className="min-w-0 print:mt-6">
      <h2 className="font-sans text-[13px] font-bold uppercase tracking-[0.06em] text-muted">Fix first</h2>
      {picks.length === 0 ? (
        <div className="mt-3 flex gap-3 rounded-xl border border-line bg-white px-4 py-4">
          <CheckCircleIcon size={20} className="shrink-0 text-ok" />
          <div>
            <p className="text-[15px] font-semibold text-ink">Nothing to fix</p>
            <p className="mt-0.5 text-[13px] text-muted">
              {total > 0 ? "Only informational findings were reported." : "The scanners and the questionnaire came back clean."}
            </p>
          </div>
        </div>
      ) : (
        <>
          <ol className="mt-3 space-y-2.5">
            {picks.map(({ f, index }) => {
              const ref = f.refs[0] ?? f.ruleId;
              const where = findingLocation(f) ?? SCANNER_LABEL[f.scanner] ?? f.scanner;
              return (
                <li key={findingAnchor(index)}>
                  <FixFirstLink
                    index={index}
                    className={`group flex items-center justify-between gap-3 rounded-xl border bg-white px-4 py-3.5 text-ink shadow-xs transition-colors ${rowCls}`}
                  >
                    <span className="flex min-w-0 flex-col gap-1">
                      <span className="text-[15px] font-semibold leading-snug">{f.title}</span>
                      <span className="flex min-w-0 flex-wrap items-center gap-x-1.5 text-[13px] text-muted">
                        <span className={`inline-flex items-center gap-1.5 font-semibold ${SEV_TEXT[f.severity]}`}>
                          <span className={`size-1.5 rounded-full ${SEV_BG[f.severity]}`} aria-hidden="true" />
                          {SEVERITY_LABEL[f.severity]}
                        </span>
                        <span aria-hidden="true">·</span>
                        <span className="break-all">{ref}</span>
                        <span aria-hidden="true">·</span>
                        <span className="min-w-0 break-all font-mono text-xs">{where}</span>
                      </span>
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

/* ------------------------------------------------------------------ cards */

function GatesCard({ report }: { report: Report }) {
  const passed = report.gates.filter((g) => g.passed).length;
  return (
    <Card labelledBy="gates-title" className="avoid-break">
      <CardHeader
        id="gates-title"
        title="Gate checks"
        meta={`${passed}/${report.gates.length} passed`}
        description="Blocking checks must pass before publication. A failed non-blocking check needs a reviewer's sign-off."
      />
      <ul className="divide-y divide-line">
        {report.gates.map((g) => (
          <li key={g.id} className="flex items-start gap-3 px-5 py-4 sm:px-6">
            {g.passed ? (
              <CheckCircleIcon size={20} className="shrink-0 text-ok" />
            ) : g.blocking ? (
              <XCircleIcon size={20} className="shrink-0 text-sev-critical" />
            ) : (
              <AlertIcon size={20} className="shrink-0 text-warn" />
            )}
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-medium text-ink">{g.label}</span>
                {g.blocking && (
                  <span className="inline-flex h-5 items-center rounded-md bg-white px-1.5 text-[11px] font-semibold text-muted ring-1 ring-inset ring-line-strong">
                    Blocking
                  </span>
                )}
              </div>
              <p className="mt-0.5 text-[13px] leading-5 text-muted">{g.detail}</p>
            </div>
            <StatusPill tone={g.passed ? "ok" : g.blocking ? "danger" : "warn"}>{g.passed ? "Passed" : "Failed"}</StatusPill>
          </li>
        ))}
      </ul>
    </Card>
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
    <Card labelledBy="coverage-title" className="avoid-break">
      <CardHeader id="coverage-title" title="Scanner coverage" description="What was analysed, by which engine, and how long it took." />

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
                    {sc.note && <div className="mt-0.5 text-[13px] font-normal text-subtle">{sc.note}</div>}
                  </td>
                  <td className={`${tdc} text-muted`}>{sc.engine}</td>
                  <td className={tdc}>
                    <StatusPill tone={status.tone}>{status.label}</StatusPill>
                  </td>
                  <td className={`${tdc} tabular text-right ${sc.findings ? "font-semibold text-ink" : "text-faint"}`}>{sc.findings}</td>
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
  return (
    <Card labelledBy="deps-title">
      <CardHeader
        id="deps-title"
        title="Dependencies"
        meta={report.packages.length}
        description={
          rows.length ? (
            <>
              Packages resolved from manifests and lockfiles, checked against OSV.dev.{" "}
              {vulnerable > 0 ? (
                <span className="font-medium text-sev-critical">{plural(vulnerable, "package")} with known vulnerabilities.</span>
              ) : (
                <span className="font-medium text-ok">No known vulnerabilities.</span>
              )}
            </>
          ) : (
            "Packages resolved from manifests and lockfiles, checked against OSV.dev."
          )
        }
      />
      {rows.length ? (
        <DependencyTable rows={rows} />
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
                        <span className="min-w-0 whitespace-pre-line break-words">{empty ? <span className="text-faint">Not answered</span> : answerLabel(q.id, v)}</span>
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
