import type { Metadata } from "next";
import Link from "next/link";
import { Card, CardHeader, Eyebrow, PageHeader, TableScroll, btn, td, th } from "@/components/Card";
import { DecisionBadge } from "@/components/DecisionBadge";
import { ArchiveIcon, ArrowRightIcon, PlusIcon } from "@/components/icons";
import { ScoreBar } from "@/components/Score";
import { SeverityCounts } from "@/components/SeverityChip";
import { CatalogueState } from "@/components/StatusPill";
import { AI_ACT_SHORT, assetTypeLabel, businessUnitLabel, formatDate, formatRelative } from "@/lib/format";
import { PASS_SCORE } from "@/lib/scoring";
import { getStore } from "@/lib/store";
import type { AiActTier, Submission } from "@/lib/types";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Overview" };

const TIER_CLASS: Record<AiActTier, string> = {
  prohibited: "text-sev-critical font-medium",
  high: "text-sev-high-ink font-medium",
  limited: "text-slate-700",
  minimal: "text-slate-500",
};

const PIPELINE = [
  { n: "01", title: "Intake questionnaire", meta: "6 sections · NIST AI RMF, ISO/IEC 42001, EU AI Act, GDPR" },
  { n: "02", title: "Automated scan", meta: "Secrets, dependencies, SAST, LLM rules, models, IaC" },
  { n: "03", title: "Gate decision", meta: "Blocking gates and trust score" },
  { n: "04", title: "Reviewer sign-off", meta: "Approve or reject with rationale" },
  { n: "05", title: "Azure AI catalogue", meta: "Published with report and SBOM" },
];

export default async function OverviewPage() {
  let subs: Submission[] = [];
  let loadError: string | null = null;
  try {
    subs = await getStore().list(200);
  } catch (e) {
    console.error(e);
    loadError = "Submissions could not be loaded. Check the storage configuration and try again.";
  }

  const now = Date.now();
  const completed = subs.filter((s) => s.status === "completed");
  const approved = completed.filter((s) => s.decision === "approved").length;
  const review = completed.filter((s) => s.decision === "conditional").length;
  const blocked = completed.filter((s) => s.decision === "blocked").length;
  const published = subs.filter((s) => s.catalog_status === "published").length;
  const scores = completed.map((s) => s.score).filter((v): v is number => typeof v === "number");
  const avg = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null;
  const pct = (n: number) => (completed.length ? `${Math.round((n / completed.length) * 100)}% of scanned` : "No scans yet");

  const kpis: { label: string; value: string; sub: string; accent?: string }[] = [
    { label: "Submissions", value: String(subs.length), sub: `${completed.length} scanned` },
    { label: "Gate approved", value: String(approved), sub: pct(approved), accent: "bg-ok" },
    { label: "Manual review", value: String(review), sub: pct(review), accent: "bg-sev-medium" },
    { label: "Blocked", value: String(blocked), sub: pct(blocked), accent: "bg-sev-critical" },
    { label: "In catalogue", value: String(published), sub: "Published assets", accent: "bg-brand" },
    { label: "Avg. trust score", value: avg === null ? "—" : String(avg), sub: `Pass threshold ${PASS_SCORE}` },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        title="AI asset intake"
        description="Every AI asset is scanned and assessed against a governance questionnaire before it can be listed in the Azure AI catalogue. Blocking gates stop publication; remaining risks are routed to a reviewer."
        actions={
          <Link href="/submit" className={btn.primary}>
            <PlusIcon size={16} />
            New submission
          </Link>
        }
      />

      <Card as="div" className="overflow-hidden">
        <dl className="grid grid-cols-2 gap-px bg-slate-200 sm:grid-cols-3 lg:grid-cols-6">
          {kpis.map((k) => (
            <div key={k.label} className="bg-white px-4 py-4 sm:px-5">
              <dt>
                <Eyebrow className="flex items-center gap-1.5">
                  {k.accent && <span className={`size-1.5 rounded-full ${k.accent}`} aria-hidden="true" />}
                  {k.label}
                </Eyebrow>
              </dt>
              <dd className="tabular mt-1.5 text-2xl font-semibold tracking-tight text-slate-900">{k.value}</dd>
              <dd className="mt-0.5 text-xs text-slate-500">{k.sub}</dd>
            </div>
          ))}
        </dl>
      </Card>

      <section aria-labelledby="pipeline-title">
        <h2 id="pipeline-title" className="sr-only">
          Publication pipeline
        </h2>
        <ol className="grid overflow-hidden rounded-lg border border-slate-200 bg-white md:grid-cols-5">
          {PIPELINE.map((p, i) => (
            <li
              key={p.n}
              className={`relative flex gap-3 px-4 py-3 md:block md:py-3.5 ${i > 0 ? "border-t border-slate-200 md:border-l md:border-t-0" : ""} ${
                i === PIPELINE.length - 1 ? "bg-brand-soft/60" : ""
              }`}
            >
              <span className="tabular font-mono text-xs font-medium text-brand md:block">{p.n}</span>
              <span className="min-w-0">
                <span className="block text-[13px] font-semibold text-slate-900 md:mt-1">{p.title}</span>
                <span className="mt-0.5 block text-xs leading-5 text-slate-500">{p.meta}</span>
              </span>
              {i < PIPELINE.length - 1 && (
                <span
                  className="absolute -right-[7px] top-1/2 z-10 hidden size-3 -translate-y-1/2 rotate-45 border-r border-t border-slate-200 bg-white md:block"
                  aria-hidden="true"
                />
              )}
            </li>
          ))}
        </ol>
      </section>

      <Card labelledBy="subs-title">
        <CardHeader
          id="subs-title"
          title="Submissions"
          meta={subs.length}
          description="Most recent first. Select a row to open the full report."
        />
        {loadError ? (
          <div className="px-5 py-10 text-center text-sm text-sev-critical" role="alert">
            {loadError}
          </div>
        ) : subs.length === 0 ? (
          <EmptyState />
        ) : (
          <TableScroll label="Submissions table">
            <table className="w-full min-w-[1120px] text-sm">
              <thead className="border-b border-slate-200 bg-slate-50/70">
                <tr>
                  <th scope="col" className={th}>Asset</th>
                  <th scope="col" className={th}>Business unit</th>
                  <th scope="col" className={th}>Type</th>
                  <th scope="col" className={th}>Submitted</th>
                  <th scope="col" className={th}>Trust score</th>
                  <th scope="col" className={th}>Findings</th>
                  <th scope="col" className={th}>EU AI Act</th>
                  <th scope="col" className={th}>Gate decision</th>
                  <th scope="col" className={th}>Catalogue</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {subs.map((s) => (
                  <tr key={s.id} className="group relative transition-colors hover:bg-slate-50 focus-within:bg-slate-50">
                    <td className={`${td} max-w-[260px]`}>
                      <Link
                        href={`/reports/${s.id}`}
                        className="flex min-w-0 items-baseline gap-1.5 font-medium text-slate-900 after:absolute after:inset-0 after:content-[''] group-hover:text-brand focus-visible:outline-none focus-visible:after:outline-2 focus-visible:after:-outline-offset-2 focus-visible:after:outline-brand"
                      >
                        <span className="min-w-0 truncate">{s.asset_name}</span>
                        {s.asset_version && <span className="shrink-0 font-mono text-xs font-normal text-slate-500">v{s.asset_version.replace(/^v/i, "")}</span>}
                      </Link>
                      <div className="truncate text-xs text-slate-500">{s.owner_name}</div>
                    </td>
                    <td className={`${td} whitespace-nowrap text-slate-700`}>{businessUnitLabel(s.business_unit)}</td>
                    <td className={`${td} whitespace-nowrap text-slate-700`}>{assetTypeLabel(s.asset_type)}</td>
                    <td className={`${td} whitespace-nowrap`}>
                      <div className="tabular text-slate-700">{formatDate(s.created_at)}</div>
                      <div className="text-xs text-slate-500">{formatRelative(s.created_at, now)}</div>
                    </td>
                    <td className={td}>
                      <ScoreBar score={s.status === "completed" ? s.score : null} />
                    </td>
                    <td className={td}>
                      <SeverityCounts counts={s.status === "completed" ? s.counts : null} />
                    </td>
                    <td className={`${td} whitespace-nowrap`}>
                      {s.ai_act_tier ? <span className={TIER_CLASS[s.ai_act_tier]}>{AI_ACT_SHORT[s.ai_act_tier]}</span> : <span className="text-slate-400">—</span>}
                    </td>
                    <td className={td}>
                      <DecisionBadge decision={s.decision} status={s.status} />
                    </td>
                    <td className={td}>
                      <CatalogueState status={s.status} decision={s.decision} review={s.review_status} catalog={s.catalog_status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
        )}
      </Card>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center px-6 py-14 text-center">
      <span className="flex size-10 items-center justify-center rounded-md border border-slate-200 bg-slate-50 text-slate-500">
        <ArchiveIcon size={20} />
      </span>
      <h3 className="mt-4 text-[15px] font-semibold text-slate-900">No submissions yet</h3>
      <p className="mt-1.5 max-w-md text-sm leading-6 text-slate-600">
        Submit an AI asset to run the automated scan and the governance gate. No application at hand? The upload step offers a demo application — a
        deliberately vulnerable RAG assistant — together with example questionnaire answers.
      </p>
      <Link href="/submit" className={`${btn.primary} mt-5`}>
        Start a submission
        <ArrowRightIcon size={16} />
      </Link>
    </div>
  );
}
