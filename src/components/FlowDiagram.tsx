import type { CSSProperties, ReactNode } from "react";
import { AlertIcon, ArrowRightIcon, CheckCircleIcon, UploadIcon, XCircleIcon } from "./icons";
import { AppIcon, CatalogueIcon, GitBranchIcon, LoopIcon, PlayIcon, ReviewerIcon, SkillIcon } from "./icons-extra";

/**
 * "How it works" flow: two entry paths -> provide the code -> automated scan -> gate decision -> three outcomes.
 * Desktop (lg+): a CSS grid with fixed-size connector tracks; every connector is drawn by the node next to it
 * (absolutely positioned, aria-hidden), so no measuring is needed. Mobile: a vertical list with down arrows.
 * Server component: no client JavaScript.
 */

const SCANNERS = ["Secrets", "Dependencies & licences", "Code", "AI / LLM risks", "Model files", "Infrastructure", "Skill review", "Answers vs. code"];

const ENTRY = [
  {
    key: "app",
    icon: <AppIcon size={18} />,
    eyebrow: "Full intake",
    title: "AI application or model",
    line: "6 short sections on data, model, architecture, controls and governance.",
    time: "~10 min",
  },
  {
    key: "skill",
    icon: <SkillIcon size={18} />,
    eyebrow: "Quick intake",
    title: "Agent skill",
    line: "1 section for a SKILL.md folder. We review the skill itself and give feedback.",
    time: "~2 min",
  },
] as const;

const PROVIDE_METHODS = [
  { icon: <UploadIcon size={14} />, label: "Upload a zip" },
  { icon: <GitBranchIcon size={14} />, label: "Paste a Git link" },
  { icon: <PlayIcon size={14} />, label: "Or try the demo" },
];

type OutcomeTone = "approved" | "review" | "blocked";

const OUTCOME: Record<OutcomeTone, { card: string; badge: string; title: string; icon: ReactNode; label: string; line: string }> = {
  approved: {
    card: "border-[#ABEFC6] bg-[#F6FEF9]",
    badge: "bg-[#DCFAE6] text-[#067647]",
    title: "text-[#067647]",
    icon: <CheckCircleIcon size={18} />,
    label: "Approved",
    line: "All checks passed.",
  },
  review: {
    card: "border-[#F5D9A8] bg-[#FFFBF3]",
    badge: "bg-[#FDECC8] text-[#8A4B00]",
    title: "text-[#8A4B00]",
    icon: <AlertIcon size={18} />,
    label: "Needs review",
    line: "No blockers, but a reviewer must accept the remaining risk.",
  },
  blocked: {
    card: "border-[#FDA29B] bg-[#FFFBFA]",
    badge: "bg-[#FEE4E2] text-[#B42318]",
    title: "text-[#B42318]",
    icon: <XCircleIcon size={18} />,
    label: "Blocked",
    line: "A blocking check failed, e.g. an exposed secret.",
  },
};

/* ------------------------------------------------------------------ building blocks */

/** Connector stroke colour (lines and arrowheads). */
const STROKE = "border-faint";

function Badge({ children, className = "bg-brand-soft text-brand" }: { children: ReactNode; className?: string }) {
  return (
    <span aria-hidden="true" className={`flex size-8 shrink-0 items-center justify-center rounded-lg font-display text-sm font-bold ${className}`}>
      {children}
    </span>
  );
}

function Time({ children }: { children: ReactNode }) {
  return <p className="mt-auto pt-3 text-xs font-semibold text-brand">{children}</p>;
}

/** White card used for every non-outcome node. */
function Node({
  badge,
  eyebrow,
  title,
  line,
  time,
  children,
  className = "",
}: {
  badge: ReactNode;
  eyebrow?: string;
  title: string;
  line: string;
  time?: string;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <div className={`relative flex h-full flex-col rounded-xl border border-line bg-white p-4 shadow-xs ${className}`}>
      <div className="flex items-start gap-3">
        {badge}
        <div className="min-w-0">
          {eyebrow && <p className="text-[11px] font-semibold uppercase tracking-[0.06em] text-subtle">{eyebrow}</p>}
          <p className="font-display text-[15px] font-bold leading-5 text-ink">{title}</p>
        </div>
      </div>
      <p className="mt-2 text-[13px] leading-5 text-muted">{line}</p>
      {children}
      {time && <Time>{time}</Time>}
    </div>
  );
}

function OutcomeNode({ tone, children }: { tone: OutcomeTone; children?: ReactNode }) {
  const o = OUTCOME[tone];
  return (
    <div className={`relative flex h-full flex-col rounded-xl border p-4 shadow-xs ${o.card}`}>
      <div className="flex items-center gap-3">
        <Badge className={o.badge}>{o.icon}</Badge>
        <p className={`font-display text-[15px] font-bold leading-5 ${o.title}`}>{o.label}</p>
      </div>
      <p className="mt-2 text-[13px] leading-5 text-ink-2">{o.line}</p>
      {children}
    </div>
  );
}

function ScannerChips() {
  return (
    <ul className="mt-3 flex flex-wrap gap-1.5" aria-label="Scanners">
      {SCANNERS.map((s) => (
        <li key={s} className="inline-flex h-6 items-center rounded-full bg-surface-2 px-2 text-xs font-medium text-ink-2 ring-1 ring-inset ring-line">
          {s}
        </li>
      ))}
    </ul>
  );
}

function ProvideMethods() {
  return (
    <ul className="mt-3 space-y-1.5" aria-label="Ways to provide the code">
      {PROVIDE_METHODS.map((m) => (
        <li key={m.label} className="flex items-center gap-2 text-[13px] font-medium text-ink-2">
          <span className="flex size-6 shrink-0 items-center justify-center rounded-md bg-surface-2 text-muted ring-1 ring-inset ring-line">{m.icon}</span>
          {m.label}
        </li>
      ))}
    </ul>
  );
}

/* Connector primitives (all aria-hidden). Positions are px/% relative to the node that draws them. */

function Line({ style, className = "" }: { style: CSSProperties; className?: string }) {
  return <span aria-hidden="true" className={`pointer-events-none absolute ${STROKE} ${className}`} style={style} />;
}

function Head({ dir, style }: { dir: "right" | "down"; style: CSSProperties }) {
  return (
    <svg
      width="10"
      height="10"
      viewBox="0 0 10 10"
      aria-hidden="true"
      focusable="false"
      className="pointer-events-none absolute text-faint"
      style={style}
    >
      <path d={dir === "right" ? "M1.5 1.2L9 5 1.5 8.8z" : "M1.2 1.5L5 9l3.8-7.5z"} fill="currentColor" />
    </svg>
  );
}

/** Arrow entering the node from the left, through a gap of `gap` px, at vertical position `y`. */
function ArrowInFromLeft({ gap, y = "50%" }: { gap: number; y?: string }) {
  return (
    <>
      <Line className="border-t-[1.5px]" style={{ left: -gap, width: gap - 8, top: `calc(${y} - 0.75px)` }} />
      <Head dir="right" style={{ left: -10, top: `calc(${y} - 5px)` }} />
    </>
  );
}

/** Arrow entering the node from above, through a gap of `gap` px, at the horizontal centre. */
function ArrowInFromTop({ gap }: { gap: number }) {
  return (
    <>
      <Line className="border-l-[1.5px]" style={{ left: "calc(50% - 0.75px)", top: -gap, height: gap - 8 }} />
      <Head dir="down" style={{ left: "calc(50% - 5px)", top: -10 }} />
    </>
  );
}

/** Arrow leaving the node downwards (used where the next node spans several columns). */
function ArrowOutBottom({ gap }: { gap: number }) {
  return (
    <>
      <Line className="border-l-[1.5px]" style={{ left: "calc(50% - 0.75px)", top: "100%", height: gap - 8 }} />
      <Head dir="down" style={{ left: "calc(50% - 5px)", top: `calc(100% + ${gap - 10}px)` }} />
    </>
  );
}

function MobileArrow() {
  return (
    <div aria-hidden="true" className="flex justify-center py-1.5">
      <svg width="12" height="28" viewBox="0 0 12 28" focusable="false" className="text-faint">
        <path d="M6 0v19" stroke="currentColor" strokeWidth="1.5" />
        <path d="M1.5 18.5L6 26.5l4.5-8z" fill="currentColor" />
      </svg>
    </div>
  );
}

function NextSteps({ items }: { items: { icon: ReactNode; text: string; hint?: string }[] }) {
  return (
    <div className="mt-3 border-t border-black/5 pt-3">
      <p className="text-xs font-medium text-subtle">What happens next</p>
      <ol className="mt-1.5 space-y-1.5">
        {items.map((it) => (
          <li key={it.text} className="flex items-start gap-2 text-[13px] leading-5 text-ink-2">
            <span className="mt-0.5 shrink-0 text-muted">{it.icon}</span>
            <span>
              <span className="font-medium text-ink">{it.text}</span>
              {it.hint && <span className="text-subtle"> · {it.hint}</span>}
            </span>
          </li>
        ))}
      </ol>
    </div>
  );
}

/* ------------------------------------------------------------------ layout constants (desktop) */

const GAP_ENTRY = 56; // between the entry paths and "Provide the code" (merge bracket + loop line)
const GAP_COL = 36; // between the other columns
const BUS_ROW = 44; // between the gate row and the outcomes
const STEP_ROW = 32; // between stacked nodes
const LOOP_X = -18; // x of the dashed loop line, relative to the left edge of the "Provide" column
const ENTRY_GAP = 12; // gap between the two entry cards
const ENTRY_CENTER = `calc((100% - ${ENTRY_GAP}px) / 4)`; // vertical centre of the first entry card (and inset of the second)

const GRID: CSSProperties = {
  gridTemplateColumns: `minmax(0,1fr) ${GAP_ENTRY}px minmax(0,1fr) ${GAP_COL}px minmax(0,1.2fr) ${GAP_COL}px minmax(0,1fr)`,
  gridTemplateRows: `auto ${BUS_ROW}px auto ${STEP_ROW}px auto ${STEP_ROW}px auto`,
};

const at = (column: string, row: string): CSSProperties => ({ gridColumn: column, gridRow: row });

/* ------------------------------------------------------------------ component */

export default function FlowDiagram({ className = "" }: { className?: string }) {
  return (
    <div className={className}>
      {/* Desktop: horizontal flow */}
      <ol className="hidden lg:grid" style={GRID} aria-label="Submission process">
        {/* Start: two entry paths */}
        <li className="relative" style={at("1", "1")}>
          <p className="sr-only">Start: choose what you submit.</p>
          <ul className="grid h-full grid-rows-2" style={{ rowGap: ENTRY_GAP }}>
            {ENTRY.map((e) => (
              <li key={e.key} className="min-h-0">
                <Node badge={<Badge>{e.icon}</Badge>} eyebrow={e.eyebrow} title={e.title} line={e.line} time={e.time} />
              </li>
            ))}
          </ul>
        </li>

        {/* 1 Provide the code: merge bracket from both entry cards + end of the resubmit loop */}
        <li className="relative" style={at("3", "1")}>
          <Line
            className="rounded-r-lg border-y-[1.5px] border-r-[1.5px]"
            style={{ left: -GAP_ENTRY, width: 22, top: ENTRY_CENTER, bottom: ENTRY_CENTER }}
          />
          <Line className="border-t-[1.5px]" style={{ left: -GAP_ENTRY + 22, width: GAP_ENTRY - 22 - 8, top: "calc(50% - 0.75px)" }} />
          <Head dir="right" style={{ left: -10, top: "calc(50% - 5px)" }} />
          <Line className="rounded-tl-lg border-l-[1.5px] border-t-[1.5px] border-dashed" style={{ left: LOOP_X, width: -LOOP_X - 8, top: "84%", bottom: 0 }} />
          <Head dir="right" style={{ left: -10, top: "calc(84% - 5px)" }} />
          <Node badge={<Badge>1</Badge>} title="Provide the code" line="Share the source so it can be scanned." time="~1 min">
            <ProvideMethods />
          </Node>
        </li>

        {/* 2 Automated scan */}
        <li className="relative" style={at("5", "1")}>
          <ArrowInFromLeft gap={GAP_COL} />
          <Node badge={<Badge>2</Badge>} title="Automated scan" line="Read-only analysis. Your code is never executed." time="Under a minute">
            <ScannerChips />
          </Node>
        </li>

        {/* 3 Gate decision */}
        <li className="relative" style={at("7", "1")}>
          <ArrowInFromLeft gap={GAP_COL} />
          <Node badge={<Badge>3</Badge>} title="Gate decision" line="A fixed policy turns the results into one of three outcomes, with the reasons." time="Instant" />
        </li>

        {/* Outcomes. Blocked sits under "Provide the code" so the loop back is short. */}
        <li className="relative" style={at("3", "3")}>
          {/* bus: from this column's centre to the right, across the gap, plus the drop into this node */}
          <Line
            className="rounded-tl-lg border-l-[1.5px] border-t-[1.5px]"
            style={{ left: "calc(50% - 0.75px)", right: -GAP_COL, top: -(BUS_ROW - 16), height: BUS_ROW - 16 - 8 }}
          />
          <Head dir="down" style={{ left: "calc(50% - 5px)", top: -10 }} />
          {/* dashed loop line running past this node */}
          <Line className="border-l-[1.5px] border-dashed" style={{ left: LOOP_X, top: -BUS_ROW, bottom: -STEP_ROW }} />
          <OutcomeNode tone="blocked" />
        </li>
        <li className="relative" style={at("5", "3")}>
          <Line className="border-t-[1.5px]" style={{ left: 0, right: -GAP_COL, top: -(BUS_ROW - 16) }} />
          <ArrowInFromTop gap={BUS_ROW - 16} />
          <ArrowOutBottom gap={STEP_ROW} />
          <OutcomeNode tone="review" />
        </li>
        <li className="relative" style={at("7", "3")}>
          <Line className="border-t-[1.5px]" style={{ left: 0, right: "50%", top: -(BUS_ROW - 16) }} />
          <ArrowInFromTop gap={BUS_ROW} />
          <ArrowOutBottom gap={STEP_ROW} />
          <OutcomeNode tone="approved" />
        </li>

        {/* Follow-ups */}
        <li className="relative" style={at("3", "5")}>
          <ArrowInFromTop gap={STEP_ROW} />
          <Line className="rounded-bl-lg border-b-[1.5px] border-l-[1.5px] border-dashed" style={{ left: LOOP_X, width: -LOOP_X, top: 0, height: "50%" }} />
          <Node
            badge={
              <Badge className="bg-surface-2 text-ink-2 ring-1 ring-inset ring-line">
                <LoopIcon size={17} />
              </Badge>
            }
            title="Fix and resubmit"
            line="Follow the fixes in the report, then submit a new version. Its report shows what you fixed."
            time="Back to step 1"
          />
        </li>
        <li className="relative" style={at("5 / 8", "5")}>
          <Node
            badge={<Badge>4</Badge>}
            title="Reviewer sign-off"
            line="A security reviewer checks the report and approves, or asks for changes."
            time="1–2 working days"
          />
        </li>
        <li className="relative" style={at("5 / 8", "7")}>
          <ArrowInFromTop gap={STEP_ROW} />
          <Node
            badge={<Badge>5</Badge>}
            title="Uploaded to the Azure AI catalogue"
            line="Only now is the asset written to the catalogue database, with its report and SBOM attached."
            time="Same day"
          />
        </li>

        {/* Key */}
        <li aria-hidden="true" className="self-end pr-6 text-xs text-subtle" style={at("1", "5 / 8")}>
          <p className="font-medium text-muted">Key</p>
          <p className="mt-2 flex items-center gap-2">
            <span className="w-7 border-t-[1.5px] border-faint" />
            Next step
          </p>
          <p className="mt-1.5 flex items-center gap-2">
            <span className="w-7 border-t-[1.5px] border-dashed border-faint" />
            Fix and resubmit
          </p>
          <p className="mt-1.5 flex items-center gap-2">
            <CatalogueIcon size={14} className="text-faint" />
            Only reviewed assets are published
          </p>
        </li>
      </ol>

      {/* Mobile and tablet: vertical flow */}
      <ol className="lg:hidden" aria-label="Submission process">
        <li>
          <p className="mb-2 text-[13px] font-semibold text-ink-2">Start: choose what you submit</p>
          <ul className="grid gap-3 sm:grid-cols-2">
            {ENTRY.map((e) => (
              <li key={e.key}>
                <Node badge={<Badge>{e.icon}</Badge>} eyebrow={e.eyebrow} title={e.title} line={e.line} time={e.time} />
              </li>
            ))}
          </ul>
          <MobileArrow />
        </li>
        <li>
          <Node badge={<Badge>1</Badge>} title="Provide the code" line="Share the source so it can be scanned." time="~1 min">
            <ProvideMethods />
          </Node>
          <MobileArrow />
        </li>
        <li>
          <Node badge={<Badge>2</Badge>} title="Automated scan" line="Read-only analysis. Your code is never executed." time="Under a minute">
            <ScannerChips />
          </Node>
          <MobileArrow />
        </li>
        <li>
          <Node badge={<Badge>3</Badge>} title="Gate decision" line="A fixed policy turns the results into one of three outcomes, with the reasons." time="Instant" />
          <MobileArrow />
        </li>
        <li>
          <p className="mb-2 text-[13px] font-semibold text-ink-2">One of three outcomes</p>
          <ul className="grid gap-3 sm:grid-cols-3">
            <li>
              <OutcomeNode tone="approved">
                <NextSteps
                  items={[
                    { icon: <ReviewerIcon size={15} />, text: "4 · Reviewer sign-off", hint: "1–2 working days" },
                    { icon: <CatalogueIcon size={15} />, text: "5 · Uploaded to the Azure AI catalogue", hint: "same day" },
                  ]}
                />
              </OutcomeNode>
            </li>
            <li>
              <OutcomeNode tone="review">
                <NextSteps items={[{ icon: <ReviewerIcon size={15} />, text: "4 · Reviewer sign-off", hint: "approves or asks for changes" }]} />
              </OutcomeNode>
            </li>
            <li>
              <OutcomeNode tone="blocked">
                <NextSteps
                  items={[
                    { icon: <ArrowRightIcon size={15} />, text: "Fix the issues in the report" },
                    { icon: <LoopIcon size={15} />, text: "Resubmit", hint: "back to step 1" },
                  ]}
                />
              </OutcomeNode>
            </li>
          </ul>
        </li>
      </ol>

      <p className="sr-only">
        Summary of the outcomes: Approved goes to reviewer sign-off and is then published in the Azure AI catalogue. Needs review also goes to reviewer
        sign-off, where the reviewer accepts the remaining risk or asks for changes. Blocked means you fix the issues listed in the report and submit a new
        version, starting again at step 1, Provide the code.
      </p>
    </div>
  );
}
