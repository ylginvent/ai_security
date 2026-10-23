import type { Metadata } from "next";
import Link from "next/link";
import { Card, InitialsTile, TableScroll, btn, td, th, thead } from "@/components/Card";
import { DecisionBadge } from "@/components/DecisionBadge";
import FlowDiagram from "@/components/FlowDiagram";
import LayerDiagram from "@/components/LayerDiagram";
import { ArrowRightIcon, PlusIcon, SearchIcon } from "@/components/icons";
import { ScoreBar } from "@/components/Score";
import { SeverityCounts } from "@/components/SeverityChip";
import { CatalogueState } from "@/components/StatusPill";
import { AI_ACT_SHORT, businessUnitLabel, formatDate, formatRelative } from "@/lib/format";
import { PASS_SCORE } from "@/lib/scoring";
import { getStore } from "@/lib/store";
import type { AiActTier, Submission } from "@/lib/types";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Overview" };

const TIER_CLASS: Record<AiActTier, string> = {
  prohibited: "font-medium text-sev-critical",
  high: "font-medium text-sev-high-ink",
  limited: "text-ink-2",
  minimal: "text-muted",
};

type View = "all" | "review" | "blocked" | "approved" | "published";

const VIEWS: { id: View; label: string; match: (s: Submission) => boolean }[] = [
  { id: "all", label: "All", match: () => true },
  // Only items a reviewer still has to act on: once approved or rejected they leave this view.
  {
    id: "review",
    label: "Needs review",
    match: (s) => s.status === "completed" && s.decision === "conditional" && s.review_status === "pending" && s.catalog_status !== "published",
  },
  { id: "blocked", label: "Blocked", match: (s) => s.status === "completed" && s.decision === "blocked" },
  { id: "approved", label: "Approved", match: (s) => s.status === "completed" && s.decision === "approved" && s.catalog_status !== "published" },
  { id: "published", label: "Published", match: (s) => s.catalog_status === "published" },
];

function href(view: View, q: string) {
  const p = new URLSearchParams();
  if (view !== "all") p.set("view", view);
  if (q) p.set("q", q);
  const s = p.toString();
  return s ? `/?${s}` : "/";
}

export default async function OverviewPage({ searchParams }: { searchParams: Promise<{ view?: string | string[]; q?: string | string[] }> }) {
  const sp = await searchParams;
  const rawView = Array.isArray(sp.view) ? sp.view[0] : sp.view;
  const view: View = VIEWS.some((v) => v.id === rawView) ? (rawView as View) : "all";
  const q = (Array.isArray(sp.q) ? sp.q[0] : sp.q)?.trim().slice(0, 100) ?? "";

  let subs: Submission[] = [];
  let loadError: string | null = null;
  try {
    subs = await getStore().list(200, { summary: true });
  } catch (e) {
    console.error(e);
    loadError = "Submissions could not be loaded. Check the storage configuration and try again.";
  }

  const now = Date.now();
  const completed = subs.filter((s) => s.status === "completed");
  const count = (v: View) => subs.filter(VIEWS.find((x) => x.id === v)!.match).length;
  const scores = completed.map((s) => s.score).filter((v): v is number => typeof v === "number");
  const avg = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null;

  const needle = q.toLowerCase();
  const rows = subs
    .filter(VIEWS.find((v) => v.id === view)!.match)
    .filter((s) => !needle || [s.asset_name, s.owner_name, s.owner_email, businessUnitLabel(s.business_unit)].some((x) => x?.toLowerCase().includes(needle)));

  const kpis: { label: string; value: string; sub: string; dot?: string }[] = [
    { label: "Submissions", value: String(subs.length), sub: `${completed.length} scanned` },
    { label: "Needs review", value: String(count("review")), sub: "Waiting for a reviewer", dot: "bg-[#F79009]" },
    { label: "Blocked", value: String(count("blocked")), sub: "Must be fixed first", dot: "bg-[#F04438]" },
    { label: "In catalogue", value: String(count("published")), sub: "Published assets", dot: "bg-brand" },
    { label: "Average trust score", value: avg === null ? "—" : String(avg), sub: `Pass mark ${PASS_SCORE}` },
  ];

  return (
    <div className="space-y-10">
      <section className="flex flex-col gap-6 lg:flex-row lg:items-end lg:justify-between">
        <div className="max-w-2xl">
          <p className="flex flex-wrap items-center gap-2 text-sm font-semibold text-brand">
            Azure AI catalogue · intake
            <span className="inline-flex h-6 items-center rounded-full bg-navy px-2.5 text-xs font-semibold text-white">Admin view</span>
          </p>
          <h1 className="mt-2 text-[32px] font-bold leading-[1.15] tracking-tight text-ink sm:text-[40px]">Get your AI asset ready for the catalogue</h1>
          <p className="mt-3 text-base leading-7 text-muted sm:text-[17px]">
            Every asset is scanned and checked against a short governance intake before it is uploaded to the Azure AI catalogue. This overview is for
            admins and reviewers; asset owners only see the questionnaire and their report.
          </p>
        </div>
        <Link href="/submit" className={`${btn.hero} shrink-0`}>
          <PlusIcon size={18} />
          Submit an asset
        </Link>
      </section>

      <dl className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5">
        {kpis.map((k) => (
          <div key={k.label} className="rounded-xl border border-line bg-white px-5 py-5 shadow-xs">
            <dt className="flex items-center gap-2 text-[13px] font-medium text-muted">
              {k.dot && <span className={`size-2 rounded-full ${k.dot}`} aria-hidden="true" />}
              {k.label}
            </dt>
            <dd className="tabular mt-2 font-display text-[30px] font-bold leading-none tracking-tight text-ink">{k.value}</dd>
            <dd className="mt-2 text-[13px] text-subtle">{k.sub}</dd>
          </div>
        ))}
      </dl>

      <section aria-labelledby="how-title" className="rounded-2xl border border-line bg-tint px-5 py-6 sm:px-8 sm:py-8">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
          <div className="max-w-2xl">
            <h2 id="how-title" className="text-xl font-bold text-ink">
              How it works
            </h2>
            <p className="mt-1 text-sm leading-6 text-muted">
              The gate is a layer in front of the Azure AI catalogue database. Asset owners choose their path, share the code and get a decision in
              about a minute; nothing reaches the catalogue without a security reviewer&apos;s sign-off.
            </p>
          </div>
          <Link href="/methodology" className="inline-flex shrink-0 items-center gap-1 text-sm font-semibold text-brand hover:text-brand-strong">
            What we check
            <ArrowRightIcon size={14} />
          </Link>
        </div>
        <LayerDiagram className="mt-6" />
        <h3 className="mt-8 text-[15px] font-semibold text-ink">Inside the gate, step by step</h3>
        <FlowDiagram className="mt-4" />
      </section>

      <Card labelledBy="subs-title">
        <div className="flex flex-col gap-4 px-5 py-5 sm:px-6 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-2">
            <h2 id="subs-title" className="text-lg font-bold text-ink">
              Submissions
            </h2>
            <span className="tabular rounded-full bg-brand-soft px-2.5 py-0.5 text-xs font-medium text-brand-strong">{subs.length}</span>
          </div>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <nav aria-label="Filter submissions" className="flex overflow-x-auto rounded-lg border border-line-strong shadow-xs">
              {VIEWS.map((v, i) => {
                const active = v.id === view;
                return (
                  <Link
                    key={v.id}
                    href={href(v.id, q)}
                    aria-current={active ? "page" : undefined}
                    className={`flex h-10 items-center gap-1.5 whitespace-nowrap px-3.5 text-sm font-semibold transition-colors ${i > 0 ? "border-l border-line-strong" : ""} ${
                      active ? "bg-surface-2 text-ink" : "bg-white text-ink-2 hover:bg-surface-2"
                    }`}
                  >
                    {v.label}
                    <span className={`tabular text-xs font-medium ${active ? "text-muted" : "text-faint"}`}>{count(v.id)}</span>
                  </Link>
                );
              })}
            </nav>
            <form action="/" method="get" role="search" className="relative">
              {view !== "all" && <input type="hidden" name="view" value={view} />}
              <label htmlFor="q" className="sr-only">
                Search submissions
              </label>
              <span className="pointer-events-none absolute inset-y-0 left-3 flex items-center text-subtle">
                <SearchIcon size={16} />
              </span>
              <input
                id="q"
                name="q"
                type="search"
                defaultValue={q}
                placeholder="Search asset or owner"
                className="h-10 w-full rounded-lg border border-line-strong bg-white pl-9 pr-3 text-sm text-ink shadow-xs placeholder:text-subtle focus:border-brand focus:outline-none focus:ring-4 focus:ring-brand/15 sm:w-60"
              />
            </form>
          </div>
        </div>

        {loadError ? (
          <div className="border-t border-line px-6 py-12 text-center text-sm text-sev-critical" role="alert">
            {loadError}
          </div>
        ) : subs.length === 0 ? (
          <EmptyState />
        ) : rows.length === 0 ? (
          <div className="border-t border-line px-6 py-12 text-center">
            <p className="font-display text-base font-bold text-ink">No submissions match</p>
            <p className="mt-1 text-sm text-muted">Try another filter or search term.</p>
            <Link href="/" className={`${btn.secondary} mt-4`}>
              Clear filters
            </Link>
          </div>
        ) : (
          <TableScroll label="Submissions table">
            <table className="w-full min-w-[1080px] text-sm">
              <thead className={thead}>
                <tr>
                  <th scope="col" className={th}>Asset</th>
                  <th scope="col" className={th}>Business unit</th>
                  <th scope="col" className={th}>Trust score</th>
                  <th scope="col" className={th}>Findings</th>
                  <th scope="col" className={th}>EU AI Act</th>
                  <th scope="col" className={th}>Decision</th>
                  <th scope="col" className={th}>Catalogue</th>
                  <th scope="col" className={th}>Submitted</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {rows.map((s) => (
                  <tr key={s.id} className="group relative transition-colors hover:bg-surface-2 focus-within:bg-surface-2">
                    <td className={`${td} max-w-[300px]`}>
                      <div className="flex items-center gap-3">
                        <InitialsTile name={s.asset_name} />
                        <div className="min-w-0">
                          <Link
                            href={`/reports/${s.id}`}
                            className="block truncate font-semibold text-ink after:absolute after:inset-0 after:content-[''] group-hover:text-brand focus-visible:outline-none focus-visible:after:outline-2 focus-visible:after:-outline-offset-2 focus-visible:after:outline-brand"
                          >
                            {s.asset_name}
                          </Link>
                          <div className="truncate text-[13px] text-subtle">
                            {s.asset_version ? `v${s.asset_version.replace(/^v/i, "")} · ` : ""}
                            {s.owner_name}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className={`${td} whitespace-nowrap`}>{businessUnitLabel(s.business_unit)}</td>
                    <td className={td}>
                      <ScoreBar score={s.status === "completed" ? s.score : null} />
                    </td>
                    <td className={td}>
                      <SeverityCounts counts={s.status === "completed" ? s.counts : null} />
                    </td>
                    <td className={`${td} whitespace-nowrap`}>
                      {s.ai_act_tier ? <span className={TIER_CLASS[s.ai_act_tier]}>{AI_ACT_SHORT[s.ai_act_tier]}</span> : <span className="text-faint">—</span>}
                    </td>
                    <td className={td}>
                      <DecisionBadge decision={s.decision} status={s.status} />
                    </td>
                    <td className={td}>
                      <CatalogueState status={s.status} decision={s.decision} review={s.review_status} catalog={s.catalog_status} />
                    </td>
                    <td className={`${td} whitespace-nowrap`}>
                      <div className="tabular text-ink-2">{formatDate(s.created_at)}</div>
                      <div className="text-[13px] text-subtle">{formatRelative(s.created_at, now)}</div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableScroll>
        )}
        {rows.length > 0 && !loadError && (
          <div className="border-t border-line px-5 py-3 text-[13px] text-muted sm:px-6">
            Showing {rows.length} of {subs.length} submission{subs.length === 1 ? "" : "s"}
          </div>
        )}
      </Card>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center border-t border-line px-6 py-16 text-center">
      <svg width="120" height="84" viewBox="0 0 120 84" aria-hidden="true">
        <rect x="22" y="14" width="60" height="64" rx="10" fill="#DCEAF4" />
        <rect x="38" y="6" width="60" height="64" rx="10" fill="#fff" stroke="#BCD3E3" strokeWidth="1.5" />
        <rect x="50" y="22" width="30" height="5" rx="2.5" fill="#BCD3E3" />
        <rect x="50" y="33" width="36" height="5" rx="2.5" fill="#DCEAF4" />
        <rect x="50" y="44" width="24" height="5" rx="2.5" fill="#DCEAF4" />
        <circle cx="92" cy="62" r="16" fill="#0070AD" />
        <path d="M92 69V55m-6 6 6-6 6 6" fill="none" stroke="#fff" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <h3 className="mt-5 text-lg font-bold text-ink">No submissions yet</h3>
      <p className="mt-2 max-w-md text-sm leading-6 text-muted">
        Submit your first AI asset or agent skill to see the scan and the gate decision. Nothing at hand? The upload step offers a deliberately
        vulnerable demo application and a demo skill, with example answers.
      </p>
      <Link href="/submit" className={`${btn.hero} mt-6`}>
        Start a submission
        <ArrowRightIcon size={18} />
      </Link>
    </div>
  );
}
