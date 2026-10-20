import { SEVERITY_LABEL } from "@/lib/format";
import type { Severity } from "@/lib/types";

/** Literal class strings so Tailwind can detect them. */
export const SEV_CHIP: Record<Severity, string> = {
  critical: "bg-sev-critical-soft text-sev-critical-ink",
  high: "bg-sev-high-soft text-sev-high-ink",
  medium: "bg-sev-medium-soft text-sev-medium-ink",
  low: "bg-sev-low-soft text-sev-low-ink",
  info: "bg-sev-info-soft text-sev-info-ink",
};

export const SEV_BG: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

export const SEV_TEXT: Record<Severity, string> = {
  critical: "text-sev-critical-ink",
  high: "text-sev-high-ink",
  medium: "text-sev-medium-ink",
  low: "text-sev-low-ink",
  info: "text-sev-info-ink",
};

export function SeverityChip({ severity, className = "" }: { severity: Severity; className?: string }) {
  return (
    <span
      className={`inline-flex h-5 shrink-0 items-center gap-1.5 rounded-[3px] px-1.5 text-[11px] font-semibold uppercase leading-none tracking-wide ${SEV_CHIP[severity]} ${className}`}
    >
      <span className={`size-1.5 rounded-full ${SEV_BG[severity]}`} aria-hidden="true" />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

const MINI: { key: Severity; letter: string }[] = [
  { key: "critical", letter: "C" },
  { key: "high", letter: "H" },
  { key: "medium", letter: "M" },
  { key: "low", letter: "L" },
];

/** Compact C/H/M/L counts for tables. Zero counts are rendered muted. */
export function SeverityCounts({ counts }: { counts: Record<Severity, number> | null }) {
  if (!counts) return <span className="text-slate-400">—</span>;
  const label = MINI.map((m) => `${counts[m.key] ?? 0} ${SEVERITY_LABEL[m.key].toLowerCase()}`).join(", ");
  return (
    <span className="inline-flex items-center gap-1" aria-label={label} title={label}>
      {MINI.map((m) => {
        const n = counts[m.key] ?? 0;
        return (
          <span
            key={m.key}
            aria-hidden="true"
            className={`tabular inline-flex h-5 min-w-[2.25rem] items-center justify-between gap-1 rounded-[3px] px-1.5 font-mono text-[11px] leading-none ${
              n > 0 ? `${SEV_CHIP[m.key]} font-semibold` : "bg-slate-50 text-slate-400"
            }`}
          >
            <span>{m.letter}</span>
            <span>{n}</span>
          </span>
        );
      })}
    </span>
  );
}
