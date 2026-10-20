"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState, useTransition } from "react";
import { btn } from "@/components/Card";
import { CheckCircleIcon, InfoIcon, SpinnerIcon } from "@/components/icons";
import { REVIEW_LABEL, StatusPill } from "@/components/StatusPill";
import type { CatalogStatus, Decision, ReviewStatus, SubmissionStatus } from "@/lib/types";

type Action = "approve" | "reject" | "publish";

const REVIEWER_KEY = "aag.reviewer-name";

export interface ReviewPanelProps {
  id: string;
  status: SubmissionStatus;
  decision: Decision | null;
  reviewStatus: ReviewStatus;
  reviewer: string | null;
  reviewComment: string | null;
  /** Pre-formatted on the server to avoid hydration differences. */
  reviewedAtLabel: string | null;
  catalogStatus: CatalogStatus;
  publishedAtLabel: string | null;
}

const inputCls =
  "block w-full rounded-lg border bg-white px-3.5 text-sm text-ink shadow-xs placeholder:text-faint focus:border-brand focus:outline-none focus:ring-4 focus:ring-brand/15";

export default function ReviewPanel(p: ReviewPanelProps) {
  const router = useRouter();
  const [name, setName] = useState("");
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState<Action | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<{ reviewer?: string; comment?: string }>({});
  const [notice, setNotice] = useState<string | null>(null);
  const [refreshing, startTransition] = useTransition();

  useEffect(() => {
    try {
      const stored = window.localStorage.getItem(REVIEWER_KEY);
      if (stored) setName(stored);
    } catch {
      /* ignore */
    }
  }, []);

  const published = p.catalogStatus === "published";
  const completed = p.status === "completed";
  const isBlocked = p.decision === "blocked";
  const working = busy !== null || refreshing;
  const catalogueId = `aicat-${p.id.slice(0, 8)}`;

  async function run(action: Action) {
    setError(null);
    setNotice(null);
    const reviewer = name.trim();
    const errs: { reviewer?: string; comment?: string } = {};
    if (!reviewer) errs.reviewer = "Enter your name to sign the review.";
    if (action === "reject" && !comment.trim()) errs.comment = "Explain why the submission is rejected.";
    setFieldErrors(errs);
    if (errs.reviewer || errs.comment) return;

    setBusy(action);
    try {
      const res = await fetch(`/api/submissions/${encodeURIComponent(p.id)}/review`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action, reviewer, comment: comment.trim() || undefined }),
      });
      let data: Record<string, unknown> = {};
      try {
        const v: unknown = await res.json();
        if (v && typeof v === "object") data = v as Record<string, unknown>;
      } catch {
        /* non-JSON response */
      }
      if (!res.ok) {
        const f = data.fields && typeof data.fields === "object" ? (data.fields as Record<string, unknown>) : {};
        setFieldErrors({
          reviewer: typeof f.reviewer === "string" ? "Enter your name to sign the review." : undefined,
          comment: typeof f.comment === "string" ? "A comment is required for this action." : undefined,
        });
        throw new Error(typeof data.error === "string" ? data.error : `The action failed (HTTP ${res.status}).`);
      }
      try {
        window.localStorage.setItem(REVIEWER_KEY, reviewer);
      } catch {
        /* ignore */
      }
      setComment("");
      setNotice(
        action === "approve" ? "Submission approved." : action === "reject" ? "Submission rejected." : `Published to the Azure AI catalogue as ${catalogueId}.`,
      );
      startTransition(() => router.refresh());
    } catch (e) {
      setError(e instanceof Error ? e.message : "The action failed.");
    } finally {
      setBusy(null);
    }
  }

  const reviewTone = p.reviewStatus === "approved" ? "ok" : p.reviewStatus === "rejected" ? "danger" : "neutral";

  return (
    <section aria-labelledby="review-title" className="rounded-xl border border-line bg-white shadow-xs print:hidden">
      <div className="border-b border-line px-5 py-4">
        <h2 id="review-title" className="text-[17px] font-semibold text-ink">
          Review &amp; publication
        </h2>
        <p className="mt-1 text-sm text-muted">A security reviewer signs off before the asset is listed.</p>
      </div>

      {/* Current state */}
      <dl className="space-y-3 border-b border-line px-5 py-4 text-sm">
        <div className="flex items-center justify-between gap-3">
          <dt className="text-muted">Review</dt>
          <dd>
            <StatusPill tone={reviewTone}>{REVIEW_LABEL[p.reviewStatus]}</StatusPill>
          </dd>
        </div>
        {p.reviewer && (
          <div className="flex items-start justify-between gap-3">
            <dt className="text-muted">Reviewer</dt>
            <dd className="text-right font-medium text-ink">
              {p.reviewer}
              {p.reviewedAtLabel && <div className="tabular text-xs font-normal text-subtle">{p.reviewedAtLabel}</div>}
            </dd>
          </div>
        )}
        {p.reviewComment && (
          <div>
            <dt className="sr-only">Review comment</dt>
            <dd className="rounded-lg border border-line bg-surface-2 px-3.5 py-2.5 text-[13px] leading-5 text-ink-2">{p.reviewComment}</dd>
          </div>
        )}
        <div className="flex items-center justify-between gap-3">
          <dt className="text-muted">Catalogue</dt>
          <dd>{published ? <StatusPill tone="brand">Published</StatusPill> : <StatusPill tone="muted">Not published</StatusPill>}</dd>
        </div>
      </dl>

      <div className="px-5 py-5">
        {!completed ? (
          <p className="flex gap-2.5 text-sm leading-6 text-muted">
            <InfoIcon size={18} className="mt-0.5 shrink-0 text-subtle" />
            {p.status === "failed" ? "The scan did not complete, so this submission cannot be reviewed. Resubmit the asset." : "Review becomes available once the scan has completed."}
          </p>
        ) : published ? (
          <div className="rounded-lg border border-brand/20 bg-brand-soft px-4 py-3.5">
            <div className="flex items-center gap-2 text-sm font-semibold text-brand-strong">
              <CheckCircleIcon size={18} />
              Listed in the Azure AI catalogue
            </div>
            <dl className="mt-2.5 grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-[13px]">
              <dt className="text-muted">Entry ID</dt>
              <dd className="font-mono text-xs leading-5 text-ink">{catalogueId}</dd>
              <dt className="text-muted">Published</dt>
              <dd className="tabular text-ink">{p.publishedAtLabel ?? "—"}</dd>
            </dl>
            <p className="mt-2.5 text-xs text-subtle">Catalogue publication is simulated in this demo.</p>
          </div>
        ) : (
          <div className="space-y-4">
            <div>
              <label htmlFor="reviewer-name" className="mb-1.5 block text-sm font-medium text-ink-2">
                Reviewer name
              </label>
              <input
                id="reviewer-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoComplete="name"
                maxLength={100}
                placeholder="Full name"
                aria-invalid={fieldErrors.reviewer ? true : undefined}
                aria-describedby={fieldErrors.reviewer ? "reviewer-error" : undefined}
                className={`${inputCls} h-10 ${fieldErrors.reviewer ? "border-sev-critical" : "border-line-strong"}`}
              />
              {fieldErrors.reviewer && (
                <p id="reviewer-error" className="mt-1.5 text-[13px] font-medium text-sev-critical">
                  {fieldErrors.reviewer}
                </p>
              )}
            </div>
            <div>
              <div className="mb-1.5 flex items-baseline justify-between gap-2">
                <label htmlFor="review-comment" className="text-sm font-medium text-ink-2">
                  Comment
                </label>
                <span className="text-xs text-subtle">Required to reject</span>
              </div>
              <textarea
                id="review-comment"
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                rows={3}
                maxLength={2000}
                placeholder={p.decision === "conditional" ? "Rationale for accepting or rejecting the residual risk" : "Optional note"}
                aria-invalid={fieldErrors.comment ? true : undefined}
                aria-describedby={fieldErrors.comment ? "comment-error" : undefined}
                className={`${inputCls} resize-y py-2.5 leading-5 ${fieldErrors.comment ? "border-sev-critical" : "border-line-strong"}`}
              />
              {fieldErrors.comment && (
                <p id="comment-error" className="mt-1.5 text-[13px] font-medium text-sev-critical">
                  {fieldErrors.comment}
                </p>
              )}
            </div>
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => run("approve")}
                disabled={working || isBlocked || p.reviewStatus === "approved"}
                className={btn.secondary}
              >
                {busy === "approve" && <SpinnerIcon size={14} />}
                Approve
              </button>
              <button type="button" onClick={() => run("reject")} disabled={working || p.reviewStatus === "rejected"} className={btn.danger}>
                {busy === "reject" && <SpinnerIcon size={14} />}
                Reject
              </button>
            </div>
            {isBlocked && (
              <p className="text-[13px] leading-5 text-subtle">
                Blocked submissions cannot be approved. The owner must resolve the blocking findings and resubmit.
              </p>
            )}

            <div className="border-t border-line pt-4">
              <button
                type="button"
                onClick={() => run("publish")}
                disabled={working || p.reviewStatus !== "approved"}
                className={`${btn.primary} w-full`}
              >
                {busy === "publish" && <SpinnerIcon size={14} />}
                Publish to Azure AI catalogue
              </button>
              <p className="mt-2 text-[13px] leading-5 text-subtle">
                {p.reviewStatus === "approved" ? "Creates the catalogue entry with this report attached." : "Available after reviewer approval."}
              </p>
            </div>
          </div>
        )}

        {error && (
          <p className="mt-4 rounded-lg border border-[#FDA29B] bg-sev-critical-soft px-3.5 py-2.5 text-sm text-sev-critical" role="alert">
            {error}
          </p>
        )}
        <p className={notice && !error ? "mt-4 text-[13px] font-medium text-ok" : "sr-only"} aria-live="polite">
          {notice && !error ? notice : ""}
        </p>
      </div>
    </section>
  );
}
