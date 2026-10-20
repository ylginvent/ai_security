"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { btn } from "@/components/Card";
import { ChevronDownIcon, ExternalLinkIcon, InfoIcon, SearchIcon, XIcon } from "@/components/icons";
import { SEV_BG, SeverityChip } from "@/components/SeverityChip";
import { SEVERITY_LABEL, refHref } from "@/lib/format";
import { SEVERITIES, type Finding, type ScannerId, type Severity } from "@/lib/types";
import { REVEAL_EVENT, findingAnchor, parseFindingAnchor } from "./anchors";

type GroupBy = "severity" | "scanner" | "file";
type SevFilter = "all" | Severity;

interface Item {
  f: Finding;
  /** DOM id of the row; also the React key. Based on the index in the findings array. */
  key: string;
}

const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function location(f: Finding): string | null {
  if (!f.file) return null;
  return f.line ? `${f.file}:${f.line}` : f.file;
}

const selectCls =
  "h-10 rounded-lg border border-line-strong bg-white px-3 text-sm font-medium text-ink-2 shadow-xs focus:border-brand focus:outline-none focus:ring-4 focus:ring-brand/15";

export default function FindingsExplorer({ findings, scanners }: { findings: Finding[]; scanners: { id: ScannerId; label: string }[] }) {
  const items: Item[] = useMemo(() => findings.map((f, i) => ({ f, key: findingAnchor(i) })), [findings]);
  const scannerLabel = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of scanners) m.set(s.id, s.label);
    return m;
  }, [scanners]);

  const [sev, setSev] = useState<SevFilter>("all");
  const [scanner, setScanner] = useState<"all" | ScannerId>("all");
  const [query, setQuery] = useState("");
  const [groupBy, setGroupBy] = useState<GroupBy>("severity");
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  /** Row to scroll to once it is rendered. */
  const [target, setTarget] = useState<string | null>(null);
  /** Row that is briefly highlighted after a jump. */
  const [flash, setFlash] = useState<string | null>(null);

  // Filtered by scanner + search: the base for the severity counts.
  const base = useMemo(() => {
    const q = query.trim().toLowerCase();
    return items.filter(({ f }) => {
      if (scanner !== "all" && f.scanner !== scanner) return false;
      if (!q) return true;
      return [f.title, f.description, f.file ?? "", f.ruleId, f.remediation, ...f.refs].some((s) => s.toLowerCase().includes(q));
    });
  }, [items, scanner, query]);

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
        if (fa !== fb) return fa.localeCompare(fb);
        if ((a.f.line ?? 0) !== (b.f.line ?? 0)) return (a.f.line ?? 0) - (b.f.line ?? 0);
      }
      if (groupBy === "scanner" && a.f.scanner !== b.f.scanner) {
        return (scannerLabel.get(a.f.scanner) ?? a.f.scanner).localeCompare(scannerLabel.get(b.f.scanner) ?? b.f.scanner);
      }
      return SEV_RANK[a.f.severity] - SEV_RANK[b.f.severity] || a.f.title.localeCompare(b.f.title);
    });
  }, [base, sev, groupBy, scannerLabel]);

  const groups = useMemo(() => {
    if (groupBy === "file") return [{ key: "all", label: null as string | null, sev: null as Severity | null, items: visible }];
    const out: { key: string; label: string | null; sev: Severity | null; items: Item[] }[] = [];
    for (const it of visible) {
      const key = groupBy === "severity" ? it.f.severity : it.f.scanner;
      let g = out.find((x) => x.key === key);
      if (!g) {
        g = {
          key,
          label: groupBy === "severity" ? SEVERITY_LABEL[it.f.severity] : (scannerLabel.get(it.f.scanner) ?? it.f.scanner),
          sev: groupBy === "severity" ? it.f.severity : null,
          items: [],
        };
        out.push(g);
      }
      g.items.push(it);
    }
    return out;
  }, [visible, groupBy, scannerLabel]);

  const scannerCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const { f } of items) m.set(f.scanner, (m.get(f.scanner) ?? 0) + 1);
    return m;
  }, [items]);

  const visibleKeys = useMemo(() => new Set(visible.map((v) => v.key)), [visible]);

  const allOpen = visible.length > 0 && visible.every((it) => open.has(it.key));
  const filtersActive = sev !== "all" || scanner !== "all" || query.trim() !== "";

  function toggle(key: string) {
    setOpen((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }
  function setAll(expand: boolean) {
    setOpen(expand ? new Set(visible.map((v) => v.key)) : new Set());
  }
  function reset() {
    setSev("all");
    setScanner("all");
    setQuery("");
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
    return <p className="px-6 py-10 text-center text-sm text-muted">No findings. All scanners and the questionnaire came back clean.</p>;
  }

  const scannerPills = scanners.filter((s) => (scannerCounts.get(s.id) ?? 0) > 0 || s.id === scanner);

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
                <option value="scanner">Scanner</option>
                <option value="file">None (sort by file)</option>
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
            placeholder="Search by title, file, rule or reference"
            className="h-full min-w-0 flex-1 bg-transparent text-sm text-ink placeholder:text-faint focus:outline-none focus-visible:outline-none"
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
                count={scannerCounts.get(s.id) ?? 0}
              />
            ))}
          </div>
        )}
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
        <p aria-live="polite">
          Showing <span className="tabular font-semibold text-ink-2">{visible.length}</span> of <span className="tabular">{items.length}</span> findings
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
          {groups.map((g) => (
            <section key={g.key} aria-label={g.label ?? "Findings"}>
              {g.label && (
                <h3 className="flex items-center gap-2 border-b border-line bg-surface-2 px-5 py-2.5 font-sans text-xs font-semibold text-muted sm:px-6">
                  {g.sev && <span className={`size-2 rounded-full ${SEV_BG[g.sev]}`} aria-hidden="true" />}
                  {g.label}
                  <span className="tabular rounded-full bg-white px-1.5 font-medium text-subtle ring-1 ring-inset ring-line">{g.items.length}</span>
                </h3>
              )}
              <ul>
                {g.items.map((it) => (
                  <FindingRow
                    key={it.key}
                    item={it}
                    open={open.has(it.key)}
                    flash={flash === it.key}
                    onToggle={() => toggle(it.key)}
                    scannerLabel={scannerLabel.get(it.f.scanner) ?? it.f.scanner}
                  />
                ))}
              </ul>
            </section>
          ))}
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
  disabled = false,
}: {
  pressed: boolean;
  onClick: () => void;
  label: string;
  count: number;
  dot?: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex h-10 shrink-0 items-center gap-2 whitespace-nowrap border-r border-line-strong px-3.5 text-sm font-semibold transition-colors last:border-r-0 disabled:cursor-default disabled:text-faint ${
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

function ScannerPill({ pressed, onClick, label, count }: { pressed: boolean; onClick: () => void; label: string; count: number }) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      onClick={onClick}
      className={`inline-flex h-8 items-center gap-1.5 rounded-full border px-3 text-[13px] font-medium transition-colors ${
        pressed ? "border-brand bg-brand-soft text-brand-strong" : "border-line bg-white text-ink-2 hover:bg-surface-2"
      }`}
    >
      {label}
      <span className={`tabular text-xs ${pressed ? "text-brand-strong" : "text-subtle"}`}>{count}</span>
    </button>
  );
}

function FindingRow({
  item,
  open,
  flash,
  onToggle,
  scannerLabel,
}: {
  item: Item;
  open: boolean;
  flash: boolean;
  onToggle: () => void;
  scannerLabel: string;
}) {
  const { f, key } = item;
  const loc = location(f);
  const panelId = `${key}-details`;
  return (
    <li id={key} className={`avoid-break scroll-mt-24 border-b border-line transition-colors duration-700 last:border-b-0 ${flash ? "bg-brand-soft/60" : ""}`}>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls={panelId}
        className={`flex w-full items-start gap-3 px-5 py-4 text-left transition-colors focus-visible:-outline-offset-2 sm:items-center sm:gap-4 sm:px-6 ${
          open ? "bg-surface-2/60" : "hover:bg-surface-2"
        }`}
      >
        <SeverityChip severity={f.severity} className="mt-px w-[88px] justify-start sm:mt-0" />
        <span className="min-w-0 flex-1">
          <span className="block text-sm font-medium leading-5 text-ink">{f.title}</span>
          <span className="mt-1 flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5 text-[13px] text-subtle">
            <span className="whitespace-nowrap">{scannerLabel}</span>
            <span aria-hidden="true" className="text-faint">
              ·
            </span>
            <span className="min-w-0 truncate font-mono text-xs text-muted">{loc ?? f.ruleId}</span>
          </span>
        </span>
        <ChevronDownIcon size={18} className={`mt-0.5 shrink-0 text-subtle transition-transform sm:mt-0 print:hidden ${open ? "rotate-180" : ""}`} />
      </button>
      <div id={panelId} className={`${open ? "block" : "hidden print:block"} px-5 pb-5 sm:pl-[128px] sm:pr-6`}>
        <div className="space-y-4 text-sm leading-6 text-ink-2">
          <p className="whitespace-pre-line">{f.description}</p>
          <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-[13px]">
            <dt className="text-subtle">Rule</dt>
            <dd className="break-all font-mono text-xs leading-5 text-ink-2">{f.ruleId}</dd>
            {loc && (
              <>
                <dt className="text-subtle">Location</dt>
                <dd className="break-all font-mono text-xs leading-5 text-ink-2">{loc}</dd>
              </>
            )}
            <dt className="text-subtle">Scanner</dt>
            <dd className="text-ink-2">{scannerLabel}</dd>
          </dl>
          {f.snippet && (
            <pre className="max-h-64 overflow-auto rounded-lg border border-line bg-surface-2 px-4 py-3 font-mono text-xs leading-5 text-ink print:max-h-none print:whitespace-pre-wrap print:break-all">
              <code>{f.snippet}</code>
            </pre>
          )}
          {f.remediation && (
            <div className="rounded-lg border border-brand/20 bg-brand-soft px-4 py-3">
              <div className="text-[13px] font-semibold text-brand-strong">How to fix</div>
              <p className="mt-1 text-ink">{f.remediation}</p>
            </div>
          )}
          {f.refs.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[13px] text-subtle">References</span>
              {f.refs.map((r, i) => {
                const href = refHref(r);
                const cls = "inline-flex h-7 items-center gap-1.5 rounded-full border border-line bg-white px-2.5 text-xs font-medium text-ink-2";
                return href ? (
                  <a key={`${r}-${i}`} href={href} target="_blank" rel="noopener noreferrer" className={`${cls} transition-colors hover:border-brand hover:text-brand`}>
                    {r}
                    <ExternalLinkIcon size={12} className="print:hidden" />
                    <span className="sr-only">(opens in a new tab)</span>
                  </a>
                ) : (
                  <span key={`${r}-${i}`} className={cls}>
                    {r}
                  </span>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </li>
  );
}
