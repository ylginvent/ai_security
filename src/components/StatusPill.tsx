import type { ReactNode } from "react";
import type { CatalogStatus, Decision, ReviewStatus, SubmissionStatus } from "@/lib/types";

export type Tone = "neutral" | "ok" | "warn" | "danger" | "brand" | "muted";

const TONE: Record<Tone, { box: string; dot: string }> = {
  neutral: { box: "bg-[#F2F4F7] text-ink-2", dot: "bg-subtle" },
  muted: { box: "bg-white text-subtle ring-1 ring-inset ring-line", dot: "bg-line-strong" },
  ok: { box: "bg-ok-soft text-ok", dot: "bg-ok" },
  warn: { box: "bg-warn-soft text-warn", dot: "bg-sev-medium" },
  danger: { box: "bg-sev-critical-soft text-sev-critical", dot: "bg-sev-critical" },
  brand: { box: "bg-brand-soft text-brand-strong", dot: "bg-brand" },
};

export function StatusPill({ tone = "neutral", children, dot = true }: { tone?: Tone; children: ReactNode; dot?: boolean }) {
  const t = TONE[tone];
  return (
    <span className={`inline-flex h-6 items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 text-xs font-medium ${t.box}`}>
      {dot && <span className={`size-1.5 rounded-full ${t.dot}`} aria-hidden="true" />}
      {children}
    </span>
  );
}

export const REVIEW_LABEL: Record<ReviewStatus, string> = {
  pending: "Awaiting review",
  approved: "Approved by reviewer",
  rejected: "Rejected by reviewer",
};

/** Combined review + catalogue state, as shown in the overview table. */
export function CatalogueState({
  status,
  decision,
  review,
  catalog,
}: {
  status: SubmissionStatus;
  decision: Decision | null;
  review: ReviewStatus;
  catalog: CatalogStatus;
}) {
  if (catalog === "published") return <StatusPill tone="brand">Published</StatusPill>;
  if (status !== "completed") return <StatusPill tone="muted">Not published</StatusPill>;
  if (review === "rejected") return <StatusPill tone="danger">Rejected</StatusPill>;
  if (review === "approved") return <StatusPill tone="ok">Ready to publish</StatusPill>;
  if (decision === "blocked") return <StatusPill tone="muted">Not eligible</StatusPill>;
  return <StatusPill tone="neutral">Awaiting review</StatusPill>;
}
