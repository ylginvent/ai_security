import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { cache, type ReactNode } from "react";
import { Card, CardHeader, Eyebrow, TableScroll, btn, td, th } from "@/components/Card";
import { DECISION_STYLE } from "@/components/DecisionBadge";
import { AlertIcon, CheckCircleIcon, ChevronRightIcon, DownloadIcon, FileIcon, InfoIcon, SpinnerIcon, XCircleIcon } from "@/components/icons";
import { ScoreRing } from "@/components/Score";
import { SEV_BG, SeverityChip } from "@/components/SeverityChip";
import { REVIEW_LABEL, StatusPill, type Tone } from "@/components/StatusPill";
import {
  SCANNER_LABEL,
  SEVERITY_LABEL,
  assetTypeLabel,
  businessUnitLabel,
  formatBytes,
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
import DependencyTable, { type DependencyRow } from "./DependencyTable";
import FindingsExplorer from "./FindingsExplorer";
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

const DECISION_TEXT: Record<Decision, string> = {
  approved: "All gates passed. The asset can be published to the catalogue after reviewer sign-off.",
  conditional: "No blocking issues, but one or more non-blocking gates failed. A reviewer must accept or reject the residual risk.",
  blocked: "One or more blocking gates failed. The asset cannot be published until the issues are resolved and the asset is resubmitted.",
};

const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function countFindings(findings: Finding[]): Record<Severity, number> {
  const c = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) c[f.severity]++;
  return c;
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

const ACTION_LABEL: Record<string, string> = {
  submitted: "Submitted",
  scan_completed: "Scan completed",
  scan_failed: "Scan failed",
  review_approved: "Approved by reviewer",
  review_rejected: "Rejected by reviewer",
  published_to_catalogue: "Published to Azure AI catalogue",
};

const ACTION_DOT: Record<string, string> = {
  submitted: "bg-slate-400",
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
    <div className="space-y-6">
      <nav aria-label="Breadcrumb" className="print:hidden">
        <ol className="flex min-w-0 items-center gap-1.5 text-xs text-slate-500">
          <li>
            <Link href="/" className="hover:text-slate-900 hover:underline">
              Overview
            </Link>
          </li>
          <li aria-hidden="true">
            <ChevronRightIcon size={12} />
          </li>
          <li aria-current="page" className="min-w-0 truncate text-slate-700">
            {s.asset_name}
          </li>
        </ol>
      </nav>

      <ReportHeader s={s} />

      {s.status === "failed" && (
        <StateCard tone="danger" icon={<AlertIcon size={18} />} title="The scan could not be completed">
          <p>{s.error ?? "An unexpected error occurred while scanning the upload."}</p>
          <p className="mt-2">
            Check that the upload is a valid zip archive or source file, then{" "}
            <Link href="/submit" className="font-medium text-brand hover:underline">
              submit it again
            </Link>
            .
          </p>
        </StateCard>
      )}
      {s.status === "scanning" && (
        <StateCard tone="neutral" icon={<SpinnerIcon size={18} />} title="Scan in progress">
          <p>
            The automated scan is still running.{" "}
            <Link href={`/reports/${s.id}`} className="font-medium text-brand hover:underline">
              Refresh
            </Link>{" "}
            in a few seconds to see the result.
          </p>
        </StateCard>
      )}
      {s.status === "completed" && !report && (
        <StateCard tone="neutral" icon={<InfoIcon size={18} />} title="Report data unavailable">
          <p>The scan completed but no report was stored for this submission.</p>
        </StateCard>
      )}

      {report && <DecisionBanner s={s} report={report} />}

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_320px] print:block">
        <div className="min-w-0 space-y-6 print:space-y-5">
          {report && (
            <>
              <GatesCard report={report} />
              <Card labelledBy="findings-title">
                <CardHeader
                  id="findings-title"
                  title="Findings"
                  meta={report.findings.length}
                  description="Code, dependency, model and configuration scanners plus questionnaire-derived risks."
                />
                <FindingsExplorer findings={report.findings} scanners={scannerOptions(report)} />
              </Card>
              <CoverageCard report={report} />
              <Card labelledBy="deps-title">
                <CardHeader
                  id="deps-title"
                  title="Dependencies"
                  meta={report.packages.length}
                  description="Packages resolved from manifests and lockfiles, checked against OSV.dev."
                />
                {report.packages.length ? (
                  <DependencyTable rows={dependencyRows(report.packages, report.findings)} />
                ) : (
                  <p className="px-5 py-6 text-sm text-slate-500">No package manifests were found in the upload.</p>
                )}
              </Card>
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

      <p className="text-xs text-slate-500">
        Report generated {report ? formatDateTime(report.generatedAt) : "—"}
        {report?.engineVersion ? ` · engine ${report.engineVersion}` : ""} · submission <span className="font-mono">{s.id}</span>
      </p>
    </div>
  );
}

/* ------------------------------------------------------------------ sections */

function ReportHeader({ s }: { s: Submission }) {
  return (
    <header className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
      <div className="min-w-0">
        <Eyebrow>
          Assessment report · <span className="font-mono normal-case tracking-normal">{s.id.slice(0, 8)}</span>
        </Eyebrow>
        <h1 className="mt-1 flex flex-wrap items-baseline gap-x-2.5 text-2xl font-semibold tracking-tight text-slate-900">
          <span className="break-words">{s.asset_name}</span>
          {s.asset_version && <span className="font-mono text-base font-normal text-slate-500">v{s.asset_version.replace(/^v/i, "")}</span>}
        </h1>
        <dl className="mt-3 grid grid-cols-1 gap-x-8 gap-y-2 text-[13px] sm:grid-cols-2 xl:flex xl:flex-wrap">
          <Meta label="Owner">
            {s.owner_name}{" "}
            <a href={`mailto:${s.owner_email}`} className="text-brand hover:underline">
              {s.owner_email}
            </a>
          </Meta>
          <Meta label="Business unit">{businessUnitLabel(s.business_unit)}</Meta>
          <Meta label="Asset type">{assetTypeLabel(s.asset_type)}</Meta>
          <Meta label="Submitted">
            <span className="tabular">{formatDateTime(s.created_at)}</span>
          </Meta>
        </dl>
        <p className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-500">
          <FileIcon size={14} className="text-slate-400" />
          <span className="break-all font-mono text-slate-700">{s.file_name ?? "—"}</span>
          <span aria-hidden="true">·</span>
          <span className="tabular">{formatBytes(s.file_size)}</span>
          <span aria-hidden="true">·</span>
          <span>
            SHA-256{" "}
            <code className="font-mono text-slate-700" title={s.file_sha256 ?? undefined}>
              <span className="print:hidden">{shortHash(s.file_sha256, 16)}</span>
              <span className="hidden break-all print:inline">{s.file_sha256 ?? "—"}</span>
            </code>
          </span>
        </p>
      </div>
      <div className="flex shrink-0 flex-wrap gap-2 print:hidden">
        <a href={`/api/submissions/${s.id}/report`} download className={btn.secondary}>
          <DownloadIcon size={16} />
          Download JSON report
        </a>
        {s.status === "completed" && (
          <a href={`/api/submissions/${s.id}/sbom`} download className={btn.secondary}>
            <DownloadIcon size={16} />
            Download SBOM (CycloneDX)
          </a>
        )}
        <PrintButton />
      </div>
    </header>
  );
}

function Meta({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[11px] font-medium uppercase tracking-[0.06em] text-slate-500">{label}</dt>
      <dd className="mt-0.5 break-words text-slate-800">{children}</dd>
    </div>
  );
}

function StateCard({ tone, icon, title, children }: { tone: "danger" | "neutral"; icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <div
      className={`flex gap-3 rounded-lg border px-4 py-4 text-sm sm:px-5 ${
        tone === "danger" ? "border-sev-critical/30 bg-sev-critical-soft text-slate-700" : "border-slate-200 bg-white text-slate-700"
      }`}
      role={tone === "danger" ? "alert" : "status"}
    >
      <span className={`mt-0.5 shrink-0 ${tone === "danger" ? "text-sev-critical" : "text-slate-500"}`}>{icon}</span>
      <div className="min-w-0">
        <h2 className={`font-semibold ${tone === "danger" ? "text-sev-critical" : "text-slate-900"}`}>{title}</h2>
        <div className="mt-1">{children}</div>
      </div>
    </div>
  );
}

function DecisionBanner({ s, report }: { s: Submission; report: Report }) {
  const decision: Decision = s.decision ?? "conditional";
  const style = DECISION_STYLE[decision];
  const counts = s.counts ?? countFindings(report.findings);
  const score = s.score ?? 0;
  const failedBlocking = report.gates.filter((g) => g.blocking && !g.passed).length;
  const failedOther = report.gates.filter((g) => !g.blocking && !g.passed).length;
  const reviewTone: Tone = s.review_status === "approved" ? "ok" : s.review_status === "rejected" ? "danger" : "neutral";

  return (
    <section aria-label="Gate decision" className="avoid-break overflow-hidden rounded-lg border border-slate-200 bg-white shadow-[0_1px_2px_rgba(15,23,42,0.04)]">
      <div className={`h-1 ${style.bar}`} aria-hidden="true" />
      <div className="flex flex-col divide-y divide-slate-200 md:flex-row md:divide-x md:divide-y-0 print:flex-row print:divide-x print:divide-y-0">
        <div className="min-w-0 flex-[1.3] px-5 py-5">
          <Eyebrow>Gate decision</Eyebrow>
          <p className={`mt-1.5 text-xl font-semibold tracking-tight ${style.text}`}>{DECISION_LABEL[decision]}</p>
          <p className="mt-1.5 text-[13px] leading-5 text-slate-600">{DECISION_TEXT[decision]}</p>
          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-600">
            <span className="tabular">
              Failed gates: {failedBlocking} blocking, {failedOther} non-blocking
            </span>
            <span aria-hidden="true" className="text-slate-300">
              |
            </span>
            <StatusPill tone={s.catalog_status === "published" ? "brand" : reviewTone}>
              {s.catalog_status === "published" ? "Published to catalogue" : REVIEW_LABEL[s.review_status]}
            </StatusPill>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-4 px-5 py-5">
          <ScoreRing score={score} />
          <div>
            <Eyebrow>Trust score</Eyebrow>
            <p className="mt-1 text-[13px] text-slate-600">
              Pass threshold <span className="tabular font-medium text-slate-900">{PASS_SCORE}</span>
            </p>
            <p className="mt-0.5 text-xs text-slate-500">100 minus weighted findings</p>
          </div>
        </div>
        <div className="min-w-0 flex-1 px-5 py-5">
          <Eyebrow>EU AI Act</Eyebrow>
          <p className={`mt-1.5 text-[13px] font-medium ${s.ai_act_tier === "prohibited" ? "text-sev-critical" : s.ai_act_tier === "high" ? "text-sev-high-ink" : "text-slate-900"}`}>
            {s.ai_act_tier ? AI_ACT_LABEL[s.ai_act_tier] : "Not classified"}
          </p>
          <Eyebrow className="mt-4">Findings by severity</Eyebrow>
          <ul className="mt-2 grid grid-cols-5 gap-2">
            {SEVERITIES.map((sev) => (
              <li key={sev} className="min-w-0">
                <span className={`block h-1 rounded-full ${counts[sev] ? SEV_BG[sev] : "bg-slate-200"}`} aria-hidden="true" />
                <span className="tabular mt-1.5 block text-lg font-semibold leading-none text-slate-900">{counts[sev] ?? 0}</span>
                <span className="mt-1 block truncate text-[11px] text-slate-500">{SEVERITY_LABEL[sev]}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}

function GatesCard({ report }: { report: Report }) {
  const passed = report.gates.filter((g) => g.passed).length;
  return (
    <Card labelledBy="gates-title" className="avoid-break">
      <CardHeader
        id="gates-title"
        title="Gate checks"
        meta={`${passed}/${report.gates.length}`}
        description="Blocking gates must pass for publication; failed non-blocking gates require reviewer sign-off."
      />
      <ul className="divide-y divide-slate-100">
        {report.gates.map((g) => (
          <li key={g.id} className="flex items-start gap-3 px-4 py-3 sm:px-5">
            {g.passed ? (
              <CheckCircleIcon size={18} className="mt-px shrink-0 text-ok" />
            ) : g.blocking ? (
              <XCircleIcon size={18} className="mt-px shrink-0 text-sev-critical" />
            ) : (
              <AlertIcon size={18} className="mt-px shrink-0 text-sev-medium" />
            )}
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-[13px] font-medium text-slate-900">{g.label}</span>
                {g.blocking && (
                  <span className="rounded border border-slate-300 px-1 text-[10px] font-semibold uppercase leading-4 tracking-wide text-slate-600">Blocking</span>
                )}
              </div>
              <p className="mt-0.5 text-[13px] leading-5 text-slate-500">{g.detail}</p>
            </div>
            <span
              className={`shrink-0 pt-px text-xs font-medium ${g.passed ? "text-ok" : g.blocking ? "text-sev-critical" : "text-sev-medium-ink"}`}
            >
              {g.passed ? "Passed" : "Failed"}
            </span>
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
      <TableScroll label="Scanner coverage table">
        <table className="w-full min-w-[620px] text-[13px]">
          <thead className="border-b border-slate-200 bg-slate-50/70">
            <tr>
              <th scope="col" className={th}>Scanner</th>
              <th scope="col" className={th}>Engine / ruleset</th>
              <th scope="col" className={th}>Status</th>
              <th scope="col" className={`${th} text-right`}>Findings</th>
              <th scope="col" className={`${th} text-right`}>Duration</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {report.scanners.map((sc, i) => {
              const status = SCANNER_STATUS[sc.status] ?? SCANNER_STATUS.ok;
              return (
                <tr key={`${sc.id}-${i}`}>
                  <td className={`${td} py-2 font-medium text-slate-900`}>
                    {sc.name || SCANNER_LABEL[sc.id]}
                    {sc.note && <div className="mt-0.5 text-xs font-normal text-slate-500">{sc.note}</div>}
                  </td>
                  <td className={`${td} py-2 text-slate-600`}>{sc.engine}</td>
                  <td className={`${td} py-2`}>
                    <StatusPill tone={status.tone}>{status.label}</StatusPill>
                  </td>
                  <td className={`${td} tabular py-2 text-right ${sc.findings ? "font-medium text-slate-900" : "text-slate-500"}`}>{sc.findings}</td>
                  <td className={`${td} tabular py-2 text-right text-slate-600`}>{formatDuration(sc.durationMs)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </TableScroll>

      <div className="border-t border-slate-200 px-4 py-4 sm:px-5">
        <dl className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-3 xl:grid-cols-6">
          {stats.map((x) => (
            <div key={x.label}>
              <dt className="text-[11px] font-medium uppercase tracking-[0.06em] text-slate-500">{x.label}</dt>
              <dd className="tabular mt-0.5 text-sm font-semibold text-slate-900">{x.value}</dd>
            </div>
          ))}
        </dl>

        {total > 0 && (
          <div className="mt-5">
            <div className="mb-1.5 text-[11px] font-medium uppercase tracking-[0.06em] text-slate-500">Languages</div>
            <div className="flex h-2 overflow-hidden rounded-full bg-slate-100" role="img" aria-label={segments.map(([l, n]) => `${l} ${Math.round((n / total) * 100)}%`).join(", ")}>
              {segments.map(([lang, n], i) => (
                <span key={lang} className={`${LANG_COLORS[i % LANG_COLORS.length]} h-full border-r border-white last:border-r-0`} style={{ width: `${(n / total) * 100}%` }} />
              ))}
            </div>
            <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-600">
              {segments.map(([lang, n], i) => (
                <li key={lang} className="flex items-center gap-1.5">
                  <span className={`size-2 rounded-sm ${LANG_COLORS[i % LANG_COLORS.length]}`} aria-hidden="true" />
                  {lang}
                  <span className="tabular text-slate-500">{Math.round((n / total) * 100)}%</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Card>
  );
}

function AnswersCard({ answers }: { answers: Submission["answers"] }) {
  const a = answers ?? {};
  return (
    <Card labelledBy="answers-title">
      <CardHeader id="answers-title" title="Questionnaire answers" description="As submitted by the asset owner. Flagged answers contribute findings." />
      <div className="divide-y divide-slate-200">
        {SECTIONS.map((section) => {
          const qs = section.questions.filter((q) => isVisible(q, a));
          return (
            <section key={section.id} aria-labelledby={`ans-${section.id}`} className="avoid-break px-4 py-4 sm:px-5">
              <div className="mb-2.5 flex flex-wrap items-baseline justify-between gap-2">
                <h3 id={`ans-${section.id}`} className="text-[13px] font-semibold text-slate-900">
                  {section.title}
                </h3>
                <span className="text-[11px] text-slate-500">{section.framework}</span>
              </div>
              <dl className="grid gap-x-6 gap-y-2 text-[13px] md:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
                {qs.map((q) => {
                  const v = a[q.id];
                  const sev = answerSeverity(q.id, v);
                  const empty = v === undefined || (Array.isArray(v) ? v.length === 0 : String(v).trim() === "");
                  return (
                    <div key={q.id} className="contents">
                      <dt className="text-slate-500">{q.label}</dt>
                      <dd className="flex min-w-0 items-start justify-between gap-3 text-slate-900">
                        <span className="min-w-0 whitespace-pre-line break-words">{empty ? <span className="text-slate-400">Not answered</span> : answerLabel(q.id, v)}</span>
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
        <p className="px-4 py-5 text-[13px] text-slate-500">No events recorded.</p>
      ) : (
        <ol className="px-4 py-4">
          {events.map((e, i) => {
            const summary = eventSummary(e.detail ?? {}, gateLabels);
            const rawComment = e.detail ? e.detail.comment : undefined;
            const comment = typeof rawComment === "string" ? rawComment : null;
            const last = i === events.length - 1;
            return (
              <li key={e.id} className={`relative pl-5 ${last ? "" : "pb-4"}`}>
                {!last && <span className="absolute bottom-0 left-[3.5px] top-3 w-px bg-slate-200" aria-hidden="true" />}
                <span className={`absolute left-0 top-1.5 size-2 rounded-full ring-2 ring-white ${ACTION_DOT[e.action] ?? "bg-slate-400"}`} aria-hidden="true" />
                <div className="text-[13px] font-medium text-slate-900">{ACTION_LABEL[e.action] ?? humanize(e.action)}</div>
                <div className="mt-0.5 text-xs text-slate-500">
                  <time dateTime={e.created_at} className="tabular">
                    {formatDateTime(e.created_at)}
                  </time>{" "}
                  · {e.actor}
                </div>
                {summary.length > 0 && <div className="mt-1 break-words text-xs text-slate-600">{summary.join(" · ")}</div>}
                {comment && <p className="mt-1.5 rounded border-l-2 border-slate-300 bg-slate-50 px-2 py-1 text-xs text-slate-700">{comment}</p>}
              </li>
            );
          })}
        </ol>
      )}
    </Card>
  );
}
