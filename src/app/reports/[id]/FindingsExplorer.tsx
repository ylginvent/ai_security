"use client";

import { memo, useCallback, useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import { flushSync } from "react-dom";
import { btn } from "@/components/Card";
import { ChevronDownIcon, ExternalLinkIcon, InfoIcon, SearchIcon, XIcon } from "@/components/icons";
import { SEV_BG, SEV_TEXT, SeverityChip } from "@/components/SeverityChip";
import {
  SCANNER_HELP,
  SEVERITY_LABEL,
  SEVERITY_MEANING,
  SUPPRESSED_REF,
  refInfo,
  shortPath,
  suppressionInfo,
  type SuppressionInfo,
} from "@/lib/format";
import { SEVERITIES, type Finding, type ScannerId, type Severity } from "@/lib/types";
import { REVEAL_EVENT, findingAnchor, parseFindingAnchor } from "./anchors";

type GroupBy = "severity" | "scanner" | "file" | "rule";
type SevFilter = "all" | Severity;

interface Item {
  f: Finding;
  /** DOM id of the row; also the React key. Based on the index in the findings array. */
  key: string;
  /** Set when the finding was downgraded to info by an exception or because it is in test code. */
  sup: SuppressionInfo | null;
  /** Lower-cased text the search box matches against. */
  haystack: string;
}

interface Group {
  key: string;
  label: string;
  /** Monospace label (file path, rule id) instead of plain text. */
  mono: boolean;
  hint: string | null;
  sev: Severity | null;
  items: Item[];
}

const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

/** Fixed locale so the server-rendered and the hydrated order are identical. */
const collator = new Intl.Collator("en", { numeric: true, sensitivity: "base" });

const NO_FILE = "\u0000no-file";

function location(f: Finding): string | null {
  if (!f.file) return null;
  return f.line ? `${f.file}:${f.line}` : f.file;
}

const selectCls =
  "h-10 rounded-lg border border-line-strong bg-white px-3 text-sm font-medium text-ink-2 shadow-xs focus:border-brand focus:outline-none focus:ring-4 focus:ring-brand/15";

export default function FindingsExplorer({
  findings,
  scanners,
  incomplete = false,
}: {
  findings: Finding[];
  scanners: { id: ScannerId; label: string }[];
  /** True when a scanner failed, so "no findings" must not read as "clean". */
  incomplete?: boolean;
}) {
  const items: Item[] = useMemo(
    () =>
      findings.map((f, i) => ({
        f,
        key: findingAnchor(i),
        sup: suppressionInfo(f),
        haystack: [f.title, f.description, f.file ?? "", f.ruleId, f.remediation, f.snippet ?? "", ...f.refs, ...f.refs.map((r) => refInfo(r).meaning ?? "")]
          .join("\n")
          .toLowerCase(),
      })),
    [findings],
  );
  const scannerLabel = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of scanners) m.set(s.id, s.label);
    return m;
  }, [scanners]);

  const [sev, setSev] = useState<SevFilter>("all");
  const [scanner, setScanner] = useState<"all" | ScannerId>("all");
  const [query, setQuery] = useState("");
  const deferredQuery = useDeferredValue(query);
  const [hideSuppressed, setHideSuppressed] = useState(false);
  const [groupBy, setGroupBy] = useState<GroupBy>("severity");
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  /** True while the browser prints: every finding's details are rendered. */
  const [printing, setPrinting] = useState(false);
  /** Row to scroll to once it is rendered. */
  const [target, setTarget] = useState<string | null>(null);
  /** Row that is briefly highlighted after a jump. */
  const [flash, setFlash] = useState<string | null>(null);

  const suppressedCount = useMemo(() => items.filter((it) => it.sup).length, [items]);

  // Filtered by scanner + search + suppression: the base for the severity counts.
  const base = useMemo(() => {
    const q = deferredQuery.trim().toLowerCase();
    return items.filter((it) => {
      if (scanner !== "all" && it.f.scanner !== scanner) return false;
      if (hideSuppressed && it.sup) return false;
      return !q || it.haystack.includes(q);
    });
  }, [items, scanner, deferredQuery, hideSuppressed]);

  const sevCounts = useMemo(() => {
    const c = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
    for (const { f } of base) c[f.severity]++;
    return c;
  }, [base]);

  const visible = useMemo(() => {
    const list = sev === "all" ? base : base.filter(({ f }) => f.severity === sev);
    return [...list].sort((a, b) => {
      if (groupBy === "file") {
        const fa = a.f.file ?? "";
        const fb = b.f.file ?? "";
        // Findings without a file (questionnaire, answers vs. code) go last.
        if (!fa !== !fb) return fa ? -1 : 1;
        if (fa !== fb) return collator.compare(fa, fb);
        if ((a.f.line ?? 0) !== (b.f.line ?? 0)) return (a.f.line ?? 0) - (b.f.line ?? 0);
      }
      return SEV_RANK[a.f.severity] - SEV_RANK[b.f.severity] || collator.compare(a.f.title, b.f.title) || collator.compare(a.key, b.key);
    });
  }, [base, sev, groupBy]);

  const groups = useMemo((): Group[] => {
    const map = new Map<string, Group>();
    for (const it of visible) {
      const f = it.f;
      let key: string;
      if (groupBy === "severity") key = f.severity;
      else if (groupBy === "scanner") key = f.scanner;
      else if (groupBy === "file") key = f.file ?? NO_FILE;
      else key = `${f.scanner}:${f.ruleId}`;
      let g = map.get(key);
      if (!g) {
        const sLabel = scannerLabel.get(f.scanner) ?? f.scanner;
        if (groupBy === "severity") g = { key, label: SEVERITY_LABEL[f.severity], mono: false, hint: SEVERITY_MEANING[f.severity], sev: f.severity, items: [] };
        else if (groupBy === "scanner") g = { key, label: sLabel, mono: false, hint: SCANNER_HELP[f.scanner] ?? null, sev: null, items: [] };
        else if (groupBy === "file")
          g = f.file
            ? { key, label: f.file, mono: true, hint: null, sev: f.severity, items: [] }
            : { key, label: "Not tied to a file", mono: false, hint: "Questionnaire answers and project-wide findings.", sev: f.severity, items: [] };
        else g = { key, label: f.title, mono: false, hint: `${sLabel} · rule ${f.ruleId}`, sev: f.severity, items: [] };
        map.set(key, g);
      }
      if (g.sev && SEV_RANK[f.severity] < SEV_RANK[g.sev]) g.sev = f.severity;
      g.items.push(it);
    }
    const out = [...map.values()];
    if (groupBy === "severity") return out.sort((a, b) => SEV_RANK[a.key as Severity] - SEV_RANK[b.key as Severity]);
    if (groupBy === "scanner") return out.sort((a, b) => collator.compare(a.label, b.label));
    if (groupBy === "file") return out; // already in path order (no-file group last)
    // rule: worst first, then the rules that fire most often
    return out.sort((a, b) => SEV_RANK[a.sev ?? "info"] - SEV_RANK[b.sev ?? "info"] || b.items.length - a.items.length || collator.compare(a.label, b.label));
  }, [visible, groupBy, scannerLabel]);

  const scannerCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const { f } of items) m.set(f.scanner, (m.get(f.scanner) ?? 0) + 1);
    return m;
  }, [items]);

  const visibleKeys = useMemo(() => new Set(visible.map((v) => v.key)), [visible]);

  const allOpen = visible.length > 0 && visible.every((it) => open.has(it.key));
  const filtersActive = sev !== "all" || scanner !== "all" || query.trim() !== "" || hideSuppressed;

  const toggle = useCallback((key: string) => {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);
  function setAll(expand: boolean) {
    setOpen(expand ? new Set(visible.map((v) => v.key)) : new Set());
  }
  function reset() {
    setSev("all");
    setScanner("all");
    setQuery("");
    setHideSuppressed(false);
  }

  /** Expand a finding (by index in `findings`), clearing filters that hide it, then scroll to it. */
  const reveal = useCallback(
    (index: number) => {
      const it = items[index];
      if (!it) return;
      if (!visibleKeys.has(it.key)) {
        setSev("all");
        setScanner("all");
        setQuery("");
        setHideSuppressed(false);
      }
      setOpen((prev) => {
        if (prev.has(it.key)) return prev;
        const next = new Set(prev);
        next.add(it.key);
        return next;
      });
      setTarget(it.key);
    },
    [items, visibleKeys],
  );

  // "Fix first" links in the hero dispatch REVEAL_EVENT; plain hash changes work too.
  useEffect(() => {
    const onHash = () => {
      const i = parseFindingAnchor(window.location.hash);
      if (i !== null) reveal(i);
    };
    const onReveal = (e: Event) => {
      const detail: unknown = (e as CustomEvent<unknown>).detail;
      if (typeof detail === "number") reveal(detail);
    };
    window.addEventListener("hashchange", onHash);
    window.addEventListener(REVEAL_EVENT, onReveal);
    return () => {
      window.removeEventListener("hashchange", onHash);
      window.removeEventListener(REVEAL_EVENT, onReveal);
    };
  }, [reveal]);

  // Details are rendered lazily; render all of them while printing so the PDF is complete.
  useEffect(() => {
    const before = () => flushSync(() => setPrinting(true));
    const after = () => setPrinting(false);
    window.addEventListener("beforeprint", before);
    window.addEventListener("afterprint", after);
    return () => {
      window.removeEventListener("beforeprint", before);
      window.removeEventListener("afterprint", after);
    };
  }, []);

  // Deep link on first load (e.g. /reports/abc#finding-3).
  const initialised = useRef(false);
  useEffect(() => {
    if (initialised.current) return;
    initialised.current = true;
    const i = parseFindingAnchor(window.location.hash);
    if (i !== null) reveal(i);
  }, [reveal]);

  // Scroll once the target row is in the DOM (filters may have to re-render first).
  useEffect(() => {
    if (!target) return;
    const el = document.getElementById(target);
    if (!el) return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    el.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
    el.querySelector<HTMLButtonElement>("button[aria-controls]")?.focus({ preventScroll: true });
    setFlash(target);
    setTarget(null);
  }, [target, visible]);

  useEffect(() => {
    if (!flash) return;
    const t = window.setTimeout(() => setFlash(null), 2400);
    return () => window.clearTimeout(t);
  }, [flash]);

  if (items.length === 0) {
    return incomplete ? (
      <p className="flex justify-center gap-2 px-6 py-10 text-center text-sm text-muted">
        <InfoIcon size={18} className="mt-0.5 shrink-0 text-warn" />
        <span>No findings were reported, but at least one scanner did not finish (see the scan notice above). This is not a clean result yet.</span>
      </p>
    ) : (
      <p className="px-6 py-10 text-center text-sm text-muted">No findings. All scanners and the questionnaire came back clean.</p>
    );
  }

  const scannerPills = scanners.filter((s) => (scannerCounts.get(s.id) ?? 0) > 0 || s.id === scanner);
  const searching = query !== deferredQuery;

  return (
    <div>
      {/* Toolbar */}
      <div className="space-y-4 border-b border-line px-5 py-4 sm:px-6 print:hidden">
        <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
          <div className="max-w-full overflow-x-auto">
            <div role="group" aria-label="Filter by severity" className="inline-flex overflow-hidden rounded-lg border border-line-strong shadow-xs">
              <SegButton pressed={sev === "all"} onClick={() => setSev("all")} label="All" count={base.length} />
              {SEVERITIES.map((s) => (
                <SegButton
                  key={s}
                  pressed={sev === s}
                  onClick={() => setSev(sev === s ? "all" : s)}
                  label={SEVERITY_LABEL[s]}
                  count={sevCounts[s]}
                  dot={SEV_BG[s]}
                  title={SEVERITY_MEANING[s]}
                  disabled={sevCounts[s] === 0 && sev !== s}
                />
              ))}
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label className="flex items-center gap-2 text-sm text-muted">
              <span className="whitespace-nowrap">Group by</span>
              <select value={groupBy} onChange={(e) => setGroupBy(e.target.value as GroupBy)} className={selectCls}>
                <option value="severity">Severity</option>
                <option value="file">File</option>
                <option value="rule">Issue type (rule)</option>
                <option value="scanner">Scanner</option>
              </select>
            </label>
            <button type="button" onClick={() => setAll(!allOpen)} className={btn.secondary} disabled={visible.length === 0}>
              <ChevronDownIcon size={16} className={`transition-transform ${allOpen ? "rotate-180" : ""}`} />
              {allOpen ? "Collapse all" : "Expand all"}
            </button>
          </div>
        </div>

        <label className="flex h-10 items-center gap-2 rounded-lg border border-line-strong bg-white px-3 shadow-xs focus-within:border-brand focus-within:ring-4 focus-within:ring-brand/15">
          <SearchIcon size={16} className="shrink-0 text-subtle" />
          <span className="sr-only">Search findings</span>
          <input
            id="finding-search"
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search by title, file, package, rule or reference"
            className="h-full min-w-0 flex-1 bg-transparent text-sm text-ink placeholder:text-subtle focus:outline-none focus-visible:outline-none"
          />
          {query && (
            <button type="button" onClick={() => setQuery("")} className="-mr-1 rounded-md p-1 text-subtle hover:bg-surface-2 hover:text-ink" aria-label="Clear search">
              <XIcon size={14} />
            </button>
          )}
        </label>

        {scannerPills.length > 1 && (
          <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Filter by scanner">
            <span className="mr-1 text-[13px] font-medium text-subtle">Scanner</span>
            <ScannerPill pressed={scanner === "all"} onClick={() => setScanner("all")} label="All" count={items.length} />
            {scannerPills.map((s) => (
              <ScannerPill
                key={s.id}
                pressed={scanner === s.id}
                onClick={() => setScanner(scanner === s.id ? "all" : s.id)}
                label={s.label}
                title={SCANNER_HELP[s.id]}
                count={scannerCounts.get(s.id) ?? 0}
              />
            ))}
          </div>
        )}

        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <details className="group min-w-0 text-[13px] text-muted">
            <summary className="inline-flex items-center gap-1.5 rounded font-semibold text-brand hover:text-brand-strong">
              <InfoIcon size={15} />
              How to read this list
              <ChevronDownIcon size={14} className="transition-transform group-open:rotate-180" />
            </summary>
            <div className="mt-3 max-w-3xl space-y-3 rounded-lg border border-line bg-surface-2 px-4 py-3 leading-5">
              <dl className="grid gap-x-4 gap-y-1.5 sm:grid-cols-[auto_minmax(0,1fr)]">
                {SEVERITIES.map((s) => (
                  <div key={s} className="contents">
                    <dt className={`font-semibold ${SEV_TEXT[s]}`}>{SEVERITY_LABEL[s]}</dt>
                    <dd className="text-ink-2">{SEVERITY_MEANING[s]}</dd>
                  </div>
                ))}
              </dl>
              <p className="text-ink-2">
                <span className="font-semibold">References</span> point to public catalogues: <strong>CWE</strong> is a list of common software
                weakness types, <strong>OWASP LLM</strong> the ten biggest risks for LLM applications, <strong>CVE / GHSA</strong> a published
                vulnerability in a package, and <strong>MITRE ATLAS</strong> known attack techniques against AI systems. Each reference shows what it
                means in plain words.
              </p>
              <p className="text-ink-2">
                <span className="font-semibold">Suppressed</span> findings are in test or example code, or were marked as an exception with an
                inline comment (<code className="font-mono text-xs">nosec</code>, <code className="font-mono text-xs">aigate:ignore</code>) or{" "}
                <code className="font-mono text-xs">.aigateignore</code>. They are shown as Info, don&apos;t count towards the decision, and a reviewer
                checks that the exception is justified. Blocking findings (critical findings and exposed credentials) can&apos;t be waived this way.
              </p>
            </div>
          </details>
          {suppressedCount > 0 && (
            <label className="inline-flex shrink-0 items-center gap-2 text-[13px] font-medium text-ink-2">
              <input
                type="checkbox"
                checked={hideSuppressed}
                onChange={(e) => setHideSuppressed(e.target.checked)}
                className="size-4 rounded border-line-strong accent-brand"
              />
              Hide {suppressedCount} suppressed
            </label>
          )}
        </div>
      </div>

      {scanner === "consistency" && (
        <p className="flex gap-2 border-b border-line bg-tint px-5 py-3 text-[13px] leading-5 text-ink-2 sm:px-6 print:hidden">
          <InfoIcon size={16} className="mt-0.5 shrink-0 text-brand" />
          <span>
            <span className="font-semibold">Answers vs. code</span> compares your questionnaire answers with what the scan found in the code, for example
            &ldquo;no external AI API&rdquo; while the code calls one. Correct the answer or change the code.
          </span>
        </p>
      )}

      <div className="flex flex-wrap items-center justify-between gap-2 px-5 py-3 text-[13px] text-subtle sm:px-6 print:hidden">
        <p aria-live="polite" aria-busy={searching}>
          Showing <span className="tabular font-semibold text-ink-2">{visible.length}</span> of <span className="tabular">{items.length}</span> findings
          {groupBy !== "severity" && groups.length > 0 && (
            <>
              {" "}
              in <span className="tabular">{groups.length}</span> {groupBy === "file" ? (groups.length === 1 ? "file" : "files") : "groups"}
            </>
          )}
        </p>
        {filtersActive && (
          <button type="button" onClick={reset} className="font-semibold text-brand hover:text-brand-strong">
            Clear filters
          </button>
        )}
      </div>

      {visible.length === 0 ? (
        <div className="border-t border-line px-6 py-12 text-center text-sm text-muted">
          No findings match the current filters.{" "}
          <button type="button" onClick={reset} className="font-semibold text-brand hover:text-brand-strong">
            Clear filters
          </button>
        </div>
      ) : (
        <div className="overflow-hidden rounded-b-xl border-t border-line">
          {groups.map((g, gi) => {
            const headingId = `findings-group-${gi}`;
            return (
              <section key={g.key} aria-labelledby={headingId}>
                <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 border-b border-line bg-surface-2 px-5 py-2.5 sm:px-6">
                  <h3 id={headingId} className="flex min-w-0 items-center gap-2 font-sans text-xs font-semibold text-ink-2">
                    {g.sev && <span className={`size-2 shrink-0 rounded-full ${SEV_BG[g.sev]}`} aria-hidden="true" />}
                    <span className={`min-w-0 break-all ${g.mono ? "font-mono font-medium" : ""}`}>{g.label}</span>
                    <span className="tabular shrink-0 rounded-full bg-white px-1.5 font-medium text-subtle ring-1 ring-inset ring-line">
                      {g.items.length}
                      <span className="sr-only"> {g.items.length === 1 ? "finding" : "findings"}</span>
                    </span>
                  </h3>
                  {g.hint && <span className="min-w-0 text-xs text-subtle">{g.hint}</span>}
                </div>
                <ul>
                  {g.items.map((it) => (
                    <FindingRow
                      key={it.key}
                      item={it}
                      open={open.has(it.key)}
                      printing={printing}
                      flash={flash === it.key}
                      onToggle={toggle}
                      scannerLabel={scannerLabel.get(it.f.scanner) ?? it.f.scanner}
                    />
                  ))}
                </ul>
              </section>
            );
          })}
        </div>
      )}
    </div>
  );
}

function SegButton({
  pressed,
  onClick,
  label,
  count,
  dot,
  title,
  disabled = false,
}: {
  pressed: boolean;
  onClick: () => void;
  label: string;
  count: number;
  dot?: string;
  title?: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={`inline-flex h-10 shrink-0 items-center gap-2 whitespace-nowrap border-r border-line-strong px-3.5 text-sm font-semibold transition-colors last:border-r-0 focus-visible:-outline-offset-2 disabled:cursor-default disabled:text-faint ${
        pressed ? "bg-surface-2 text-ink" : "bg-white text-ink-2 hover:bg-surface-2"
      }`}
    >
      {dot && <span className={`size-2 rounded-full ${disabled ? "bg-line-strong" : dot}`} aria-hidden="true" />}
      {label}
      <span
        className={`tabular rounded-full px-1.5 text-xs font-medium leading-5 ${pressed ? "bg-white text-ink-2 ring-1 ring-inset ring-line" : "bg-surface-2 text-subtle"}`}
      >
        {count}
      </span>
    </button>
  );
}

function ScannerPill({ pressed, onClick, label, count, title }: { pressed: boolean; onClick: () => void; label: string; count: number; title?: string }) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      onClick={onClick}
      title={title}
      className={`inline-flex h-8 items-center gap-1.5 rounded-full border px-3 text-[13px] font-medium transition-colors ${
        pressed ? "border-brand bg-brand-soft text-brand-strong" : "border-line bg-white text-ink-2 hover:bg-surface-2"
      }`}
    >
      {label}
      <span className={`tabular text-xs ${pressed ? "text-brand-strong" : "text-subtle"}`}>{count}</span>
    </button>
  );
}

const FindingRow = memo(function FindingRow({
  item,
  open,
  printing,
  flash,
  onToggle,
  scannerLabel,
}: {
  item: Item;
  open: boolean;
  printing: boolean;
  flash: boolean;
  onToggle: (key: string) => void;
  scannerLabel: string;
}) {
  const { f, key, sup } = item;
  const loc = location(f);
  const panelId = `${key}-details`;
  return (
    <li id={key} className={`avoid-break scroll-mt-24 border-b border-line transition-colors duration-700 last:border-b-0 ${flash ? "bg-brand-soft/60" : ""}`}>
      <button
        type="button"
        onClick={() => onToggle(key)}
        aria-expanded={open}
        aria-controls={panelId}
        className={`flex w-full items-start gap-3 px-5 py-4 text-left transition-colors focus-visible:-outline-offset-2 sm:items-center sm:gap-4 sm:px-6 ${
          open ? "bg-surface-2/60" : "hover:bg-surface-2"
        }`}
      >
        <SeverityChip severity={f.severity} className="mt-px w-[88px] justify-start sm:mt-0" />
        <span className="min-w-0 flex-1">
          <span className="block break-words text-sm font-medium leading-5 text-ink">{f.title}</span>
          <span className="mt-1 flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-[13px] text-subtle">
            {sup && (
              <span className="inline-flex h-5 items-center rounded-md bg-white px-1.5 text-[11px] font-semibold text-ink-2 ring-1 ring-inset ring-line-strong">
                {sup.testCode ? "Test code" : "Suppressed"}
                {sup.originalSeverity ? ` · was ${SEVERITY_LABEL[sup.originalSeverity]}` : ""}
              </span>
            )}
            <span className="whitespace-nowrap">{scannerLabel}</span>
            <span aria-hidden="true" className="text-faint">
              ·
            </span>
            <span className="min-w-0 break-all font-mono text-xs text-muted" title={loc ?? undefined}>
              {loc ? shortPath(loc) : `rule ${f.ruleId}`}
            </span>
          </span>
        </span>
        <ChevronDownIcon size={18} className={`mt-0.5 shrink-0 text-subtle transition-transform sm:mt-0 print:hidden ${open ? "rotate-180" : ""}`} />
      </button>
      <div id={panelId} className={`${open ? "block" : "hidden print:block"} px-5 pb-5 sm:pl-[128px] sm:pr-6`}>
        {(open || printing) && <FindingDetails f={f} sup={sup} loc={loc} scannerLabel={scannerLabel} />}
      </div>
    </li>
  );
});

function DetailHeading({ children }: { children: string }) {
  return <h4 className="font-sans text-[13px] font-semibold text-ink">{children}</h4>;
}

function FindingDetails({ f, sup, loc, scannerLabel }: { f: Finding; sup: SuppressionInfo | null; loc: string | null; scannerLabel: string }) {
  const refs = f.refs.filter((r) => r.trim() && r.trim().toLowerCase() !== SUPPRESSED_REF);
  return (
    <div className="space-y-4 text-sm leading-6 text-ink-2">
      <div>
        <DetailHeading>What we found</DetailHeading>
        <p className="mt-1 whitespace-pre-line break-words">{sup ? sup.description : f.description}</p>
        <p className={`mt-1.5 text-[13px] leading-5 ${SEV_TEXT[f.severity]}`}>
          <span className="font-semibold">{SEVERITY_LABEL[f.severity]}:</span> <span className="text-muted">{SEVERITY_MEANING[f.severity]}</span>
        </p>
      </div>

      {sup && (
        <div className="rounded-lg border border-line-strong bg-surface-2 px-4 py-3 text-[13px] leading-5">
          <div className="font-semibold text-ink">
            {sup.testCode ? "Not counted: this is test, example or demo code" : "Not counted: marked as an exception"}
          </div>
          <p className="mt-1 text-ink-2">
            {sup.reason ? `${sup.reason} ` : ""}
            {sup.originalSeverity ? `Without the exception this would be ${SEVERITY_LABEL[sup.originalSeverity].toLowerCase()} severity. ` : ""}A
            reviewer checks that the exception is justified. If this code ships with the asset, fix it anyway.
          </p>
        </div>
      )}

      {(loc || f.snippet) && (
        <div>
          <DetailHeading>Where</DetailHeading>
          {loc && (
            <p className="mt-1 break-all font-mono text-xs leading-5 text-ink">
              {f.file}
              {f.line ? <span className="font-sans text-[13px] text-muted"> · line {f.line}</span> : null}
            </p>
          )}
          {f.snippet && (
            <pre
              tabIndex={0}
              aria-label={loc ? `Code at ${loc}` : "Code snippet"}
              className="mt-2 max-h-64 max-w-full overflow-auto rounded-lg border border-line bg-surface-2 px-4 py-3 font-mono text-xs leading-5 text-ink print:max-h-none print:whitespace-pre-wrap print:break-all"
            >
              <code>{f.snippet}</code>
            </pre>
          )}
        </div>
      )}

      {f.remediation && (
        <div className="rounded-lg border border-brand/20 bg-brand-soft px-4 py-3">
          <DetailHeading>How to fix</DetailHeading>
          <p className="mt-1 whitespace-pre-line break-words text-ink">{f.remediation}</p>
        </div>
      )}

      {refs.length > 0 && (
        <div>
          <DetailHeading>Learn more</DetailHeading>
          <ul className="mt-1.5 flex flex-wrap gap-2">
            {refs.map((r, i) => {
              const info = refInfo(r);
              const cls = "inline-flex min-h-7 max-w-full items-center gap-1.5 rounded-full border border-line bg-white px-2.5 py-1 text-xs font-medium text-ink-2";
              const body = (
                <>
                  {info.meaning && <span className="text-ink">{info.meaning}</span>}
                  <span className={`break-all ${info.meaning ? "text-subtle" : ""}`}>{info.id}</span>
                </>
              );
              return (
                <li key={`${r}-${i}`} className="max-w-full">
                  {info.href ? (
                    <a href={info.href} target="_blank" rel="noopener noreferrer" title={info.kind} className={`${cls} transition-colors hover:border-brand hover:text-brand`}>
                      {body}
                      <ExternalLinkIcon size={12} className="shrink-0 print:hidden" />
                      <span className="sr-only">({info.kind}, opens in a new tab)</span>
                    </a>
                  ) : (
                    <span className={cls} title={info.kind}>
                      {body}
                      <span className="sr-only">({info.kind})</span>
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      )}

      <p className="text-xs leading-5 text-subtle">
        Found by {scannerLabel} · rule <span className="break-all font-mono">{f.ruleId}</span>
      </p>
    </div>
  );
}
