import { DECISION_LABEL } from "@/lib/scoring";
import type { Decision, SubmissionStatus } from "@/lib/types";
import { SpinnerIcon } from "./icons";

export const DECISION_SHORT: Record<Decision, string> = {
  approved: "Approved",
  conditional: "Manual review",
  blocked: "Blocked",
};

export const DECISION_STYLE: Record<Decision, { chip: string; text: string; bar: string; border: string; soft: string }> = {
  approved: { chip: "bg-ok-soft text-ok ring-ok/25", text: "text-ok", bar: "bg-ok", border: "border-ok", soft: "bg-ok-soft" },
  conditional: { chip: "bg-warn-soft text-warn ring-warn/25", text: "text-warn", bar: "bg-sev-medium", border: "border-sev-medium", soft: "bg-warn-soft" },
  blocked: {
    chip: "bg-sev-critical-soft text-sev-critical ring-sev-critical/25",
    text: "text-sev-critical",
    bar: "bg-sev-critical",
    border: "border-sev-critical",
    soft: "bg-sev-critical-soft",
  },
};

const base = "inline-flex h-6 items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 text-xs font-medium ring-1 ring-inset";

export function DecisionBadge({
  decision,
  status = "completed",
  long = false,
}: {
  decision: Decision | null;
  status?: SubmissionStatus;
  long?: boolean;
}) {
  if (status === "scanning") {
    return (
      <span className={`${base} bg-surface-2 text-ink-2 ring-line`}>
        <SpinnerIcon size={12} />
        Scanning
      </span>
    );
  }
  if (status === "failed") {
    return <span className={`${base} bg-white text-sev-critical ring-sev-critical/40`}>Scan failed</span>;
  }
  if (!decision) return <span className="text-faint">—</span>;
  const s = DECISION_STYLE[decision];
  return (
    <span className={`${base} ${s.chip}`}>
      <span className={`size-1.5 rounded-full ${s.bar}`} aria-hidden="true" />
      {long ? DECISION_LABEL[decision] : DECISION_SHORT[decision]}
    </span>
  );
}
