"use client";

import { useMemo, useState } from "react";
import { btn } from "@/components/Card";
import { ChevronRightIcon, ExternalLinkIcon, SearchIcon } from "@/components/icons";
import { SEV_BG, SEV_CHIP, SeverityChip } from "@/components/SeverityChip";
import { SEVERITY_LABEL, refHref } from "@/lib/format";
import { SEVERITIES, type Finding, type ScannerId, type Severity } from "@/lib/types";

type GroupBy = "severity" | "scanner" | "file";

interface Item {
  f: Finding;
  key: string;
}

const SEV_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function location(f: Finding): string | null {
  if (!f.file) return null;
  return f.line ? `${f.file}:${f.line}` : f.file;
}

export default function FindingsExplorer({ findings, scanners }: { findings: Finding[]; scanners: { id: ScannerId; label: string }[] }) {
  const items: Item[] = useMemo(() => findings.map((f, i) => ({ f, key: `${f.id}-${i}` })), [findings]);
  const scannerLabel = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of scanners) m.set(s.id, s.label);
    return m;
  }, [scanners]);

  const [sevFilter, setSevFilter] = useState<Severity[]>([]);
  const [scanner, setScanner] = useState<"all" | ScannerId>("all");
  const [query, setQuery] = useState("");
  const [groupBy, setGroupBy] = useState<GroupBy>("severity");
  const [open, setOpen] = useState<Set<string>>(() => new Set());

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
    const list = sevFilter.length ? base.filter(({ f }) => sevFilter.includes(f.severity)) : base;
    return [...list].sort((a, b) => {
      if (groupBy === "file") {
        const fa = a.f.file ?? "";
        const fb = b.f.file ?? "";
        // Findings without a file (questionnaire) go last.
        if (!fa !== !fb) return fa ? -1 : 1;
        if (fa !== fb) return fa.localeCompare(fb);
        if ((a.f.line ?? 0) !== (b.f.line ?? 0)) return (a.f.line ?? 0) - (b.f.line ?? 0);
      }
      if (groupBy === "scanner" && a.f.scanner !== b.f.scanner) {
        return (scannerLabel.get(a.f.scanner) ?? a.f.scanner).localeCompare(scannerLabel.get(b.f.scanner) ?? b.f.scanner);
      }
      return SEV_RANK[a.f.severity] - SEV_RANK[b.f.severity] || a.f.title.localeCompare(b.f.title);
    });
  }, [base, sevFilter, groupBy, scannerLabel]);

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

  const allOpen = visible.length > 0 && visible.every((it) => open.has(it.key));
  const filtersActive = sevFilter.length > 0 || scanner !== "all" || query.trim() !== "";

  function toggleSev(s: Severity) {
    setSevFilter((prev) => (prev.includes(s) ? prev.filter((x) => x !== s) : [...prev, s]));
  }
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
    setSevFilter([]);
    setScanner("all");
    setQuery("");
  }

  if (items.length === 0) {
    return <p className="px-5 py-8 text-center text-sm text-slate-500">No findings. All scanners and the questionnaire came back clean.</p>;
  }

  return (
    <div>
      {/* Toolbar */}
      <div className="space-y-3 border-b border-slate-200 px-4 py-3 sm:px-5 print:hidden">
        <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter by severity">
          {SEVERITIES.map((s) => {
            const pressed = sevFilter.includes(s);
            const n = sevCounts[s];
            return (
              <button
                key={s}
                type="button"
                aria-pressed={pressed}
                onClick={() => toggleSev(s)}
                disabled={n === 0 && !pressed}
                className={`inline-flex h-7 items-center gap-1.5 rounded-md border px-2 text-xs font-medium transition-colors disabled:cursor-default disabled:opacity-50 ${
                  pressed ? `border-transparent ${SEV_CHIP[s]} ring-1 ring-inset ring-current/30` : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
                }`}
              >
                <span className={`size-2 rounded-full ${SEV_BG[s]}`} aria-hidden="true" />
                {SEVERITY_LABEL[s]}
                <span className="tabular text-slate-500">{n}</span>
              </button>
            );
          })}
          {filtersActive && (
            <button type="button" onClick={reset} className="ml-1 text-xs font-medium text-brand hover:underline">
              Reset filters
            </button>
          )}
        </div>
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
          <div className="relative min-w-0 flex-1">
            <label htmlFor="finding-search" className="sr-only">
              Search findings
            </label>
            <SearchIcon size={15} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              id="finding-search"
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search title, file, rule or reference"
              className="h-8 w-full rounded-md border border-slate-300 bg-white pl-8 pr-2.5 text-[13px] placeholder:text-slate-400 focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/20"
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <label className="flex items-center gap-1.5 text-xs text-slate-500">
              Scanner
              <select
                value={scanner}
                onChange={(e) => setScanner(e.target.value as "all" | ScannerId)}
                className="h-8 rounded-md border border-slate-300 bg-white px-2 text-[13px] text-slate-800 focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/20"
              >
                <option value="all">All ({items.length})</option>
                {scanners.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.label} ({scannerCounts.get(s.id) ?? 0})
                  </option>
                ))}
              </select>
            </label>
            <label className="flex items-center gap-1.5 text-xs text-slate-500">
              Group by
              <select
                value={groupBy}
                onChange={(e) => setGroupBy(e.target.value as GroupBy)}
                className="h-8 rounded-md border border-slate-300 bg-white px-2 text-[13px] text-slate-800 focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/20"
              >
                <option value="severity">Severity</option>
                <option value="scanner">Scanner</option>
                <option value="file">None (sort by file)</option>
              </select>
            </label>
            <button type="button" onClick={() => setAll(!allOpen)} className={`${btn.ghost} h-8 border border-slate-200 bg-white`} disabled={visible.length === 0}>
              {allOpen ? "Collapse all" : "Expand all"}
            </button>
          </div>
        </div>
      </div>

      <p className="px-4 pt-3 text-xs text-slate-500 sm:px-5 print:hidden" aria-live="polite">
        Showing <span className="tabular font-medium text-slate-700">{visible.length}</span> of <span className="tabular">{items.length}</span> findings
      </p>

      {visible.length === 0 ? (
        <div className="px-5 py-10 text-center text-sm text-slate-500">
          No findings match the current filters.{" "}
          <button type="button" onClick={reset} className="font-medium text-brand hover:underline">
            Reset filters
          </button>
        </div>
      ) : (
        <div className="pb-2 pt-2">
          {groups.map((g) => (
            <section key={g.key} aria-label={g.label ?? "Findings"}>
              {g.label && (
                <h3 className="flex items-center gap-2 px-4 pb-1.5 pt-3 text-[11px] font-semibold uppercase tracking-[0.06em] text-slate-500 sm:px-5">
                  {g.sev && <span className={`size-2 rounded-full ${SEV_BG[g.sev]}`} aria-hidden="true" />}
                  {g.label}
                  <span className="tabular font-medium text-slate-400">{g.items.length}</span>
                </h3>
              )}
              <ul className="border-y border-slate-100">
                {g.items.map((it) => (
                  <FindingRow
                    key={it.key}
                    item={it}
                    open={open.has(it.key)}
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

function FindingRow({ item, open, onToggle, scannerLabel }: { item: Item; open: boolean; onToggle: () => void; scannerLabel: string }) {
  const { f, key } = item;
  const loc = location(f);
  const panelId = `finding-${key}`;
  return (
    <li className="avoid-break border-b border-slate-100 last:border-b-0">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls={panelId}
        className="flex w-full items-start gap-3 px-4 py-2.5 text-left transition-colors hover:bg-slate-50 focus-visible:-outline-offset-2 sm:px-5"
      >
        <ChevronRightIcon size={14} className={`mt-[3px] shrink-0 text-slate-400 transition-transform print:hidden ${open ? "rotate-90" : ""}`} />
        <SeverityChip severity={f.severity} className="mt-px w-[86px] justify-start" />
        <span className="min-w-0 flex-1">
          <span className="block text-[13px] font-medium leading-5 text-slate-900">{f.title}</span>
          <span className="mt-0.5 block truncate font-mono text-xs text-slate-500">{loc ?? f.ruleId}</span>
        </span>
        <span className="hidden shrink-0 whitespace-nowrap pt-0.5 text-xs text-slate-500 sm:block">{scannerLabel}</span>
      </button>
      <div id={panelId} className={`${open ? "block" : "hidden print:block"} pb-4 pl-4 pr-4 sm:pl-[144px] sm:pr-5`}>
        <div className="space-y-3 text-[13px] leading-6 text-slate-700">
          <p className="whitespace-pre-line">{f.description}</p>
          <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-0.5 text-xs">
            <dt className="text-slate-500">Rule</dt>
            <dd className="break-all font-mono text-slate-700">{f.ruleId}</dd>
            {loc && (
              <>
                <dt className="text-slate-500">Location</dt>
                <dd className="break-all font-mono text-slate-700">{loc}</dd>
              </>
            )}
            <dt className="text-slate-500 sm:hidden">Scanner</dt>
            <dd className="text-slate-700 sm:hidden">{scannerLabel}</dd>
          </dl>
          {f.snippet && (
            <pre className="max-h-64 overflow-auto rounded-md border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-xs leading-5 text-slate-800 print:max-h-none print:whitespace-pre-wrap print:break-all">
              <code>{f.snippet}</code>
            </pre>
          )}
          {f.remediation && (
            <div className="rounded-md border-l-2 border-brand bg-brand-soft/50 px-3 py-2">
              <div className="text-[11px] font-semibold uppercase tracking-[0.06em] text-brand-strong">Remediation</div>
              <p className="mt-0.5 text-slate-800">{f.remediation}</p>
            </div>
          )}
          {f.refs.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-xs text-slate-500">References</span>
              {f.refs.map((r, i) => {
                const href = refHref(r);
                const cls = "inline-flex h-6 items-center gap-1 rounded border border-slate-200 bg-white px-1.5 font-mono text-[11px] text-slate-700";
                return href ? (
                  <a key={`${r}-${i}`} href={href} target="_blank" rel="noopener noreferrer" className={`${cls} hover:border-brand hover:text-brand`}>
                    {r}
                    <ExternalLinkIcon size={11} className="print:hidden" />
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
