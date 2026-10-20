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
  "block w-full rounded-md border bg-white px-3 text-sm text-slate-900 shadow-sm placeholder:text-slate-400 focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/20";

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
    <section aria-labelledby="review-title" className="rounded-lg border border-slate-200 bg-white shadow-[0_1px_2px_rgba(15,23,42,0.04)] print:hidden">
      <div className="border-b border-slate-200 px-4 py-3">
        <h2 id="review-title" className="text-[15px] font-semibold text-slate-900">
          Review &amp; publication
        </h2>
      </div>

      {/* Current state */}
      <dl className="space-y-3 border-b border-slate-200 px-4 py-3 text-[13px]">
        <div className="flex items-center justify-between gap-3">
          <dt className="text-slate-500">Review</dt>
          <dd>
            <StatusPill tone={reviewTone}>{REVIEW_LABEL[p.reviewStatus]}</StatusPill>
          </dd>
        </div>
        {p.reviewer && (
          <div className="flex items-start justify-between gap-3">
            <dt className="text-slate-500">Reviewer</dt>
            <dd className="text-right text-slate-800">
              {p.reviewer}
              {p.reviewedAtLabel && <div className="tabular text-xs text-slate-500">{p.reviewedAtLabel}</div>}
            </dd>
          </div>
        )}
        {p.reviewComment && (
          <div>
            <dt className="sr-only">Review comment</dt>
            <dd className="rounded-md border-l-2 border-slate-300 bg-slate-50 px-3 py-2 text-slate-700">{p.reviewComment}</dd>
          </div>
        )}
        <div className="flex items-center justify-between gap-3">
          <dt className="text-slate-500">Catalogue</dt>
          <dd>{published ? <StatusPill tone="brand">Published</StatusPill> : <StatusPill tone="muted">Not published</StatusPill>}</dd>
        </div>
      </dl>

      <div className="px-4 py-4">
        {!completed ? (
          <p className="flex gap-2 text-[13px] text-slate-600">
            <InfoIcon size={16} className="mt-0.5 shrink-0 text-slate-400" />
            {p.status === "failed" ? "The scan did not complete, so this submission cannot be reviewed. Resubmit the asset." : "Review becomes available once the scan has completed."}
          </p>
        ) : published ? (
          <div className="rounded-md border border-brand/25 bg-brand-soft px-3 py-3">
            <div className="flex items-center gap-2 text-[13px] font-semibold text-brand-strong">
              <CheckCircleIcon size={16} />
              Listed in the Azure AI catalogue
            </div>
            <dl className="mt-2 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
              <dt className="text-slate-500">Entry ID</dt>
              <dd className="font-mono text-slate-800">{catalogueId}</dd>
              <dt className="text-slate-500">Published</dt>
              <dd className="tabular text-slate-800">{p.publishedAtLabel ?? "—"}</dd>
            </dl>
            <p className="mt-2 text-xs text-slate-500">Catalogue publication is simulated in this demo.</p>
          </div>
        ) : (
          <div className="space-y-3">
            <div>
              <label htmlFor="reviewer-name" className="mb-1 block text-[13px] font-medium text-slate-800">
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
                className={`${inputCls} h-9 ${fieldErrors.reviewer ? "border-sev-critical" : "border-slate-300"}`}
              />
              {fieldErrors.reviewer && (
                <p id="reviewer-error" className="mt-1 text-xs font-medium text-sev-critical">
                  {fieldErrors.reviewer}
                </p>
              )}
            </div>
            <div>
              <div className="mb-1 flex items-baseline justify-between">
                <label htmlFor="review-comment" className="text-[13px] font-medium text-slate-800">
                  Comment
                </label>
                <span className="text-xs text-slate-500">Required to reject</span>
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
                className={`${inputCls} resize-y py-2 leading-5 ${fieldErrors.comment ? "border-sev-critical" : "border-slate-300"}`}
              />
              {fieldErrors.comment && (
                <p id="comment-error" className="mt-1 text-xs font-medium text-sev-critical">
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
              <p className="text-xs leading-5 text-slate-500">
                Blocked submissions cannot be approved. The owner must resolve the blocking findings and resubmit.
              </p>
            )}

            <div className="border-t border-slate-200 pt-3">
              <button
                type="button"
                onClick={() => run("publish")}
                disabled={working || p.reviewStatus !== "approved"}
                className={`${btn.primary} w-full`}
              >
                {busy === "publish" && <SpinnerIcon size={14} />}
                Publish to Azure AI catalogue
              </button>
              <p className="mt-1.5 text-xs leading-5 text-slate-500">
                {p.reviewStatus === "approved" ? "Creates the catalogue entry with this report attached." : "Available after reviewer approval."}
              </p>
            </div>
          </div>
        )}

        {error && (
          <p className="mt-3 rounded-md border border-sev-critical/30 bg-sev-critical-soft px-3 py-2 text-[13px] text-sev-critical" role="alert">
            {error}
          </p>
        )}
        <p className={notice && !error ? "mt-3 text-xs font-medium text-ok" : "sr-only"} aria-live="polite">
          {notice && !error ? notice : ""}
        </p>
      </div>
    </section>
  );
}
