"use client";

import { useState } from "react";
import { td, th } from "@/components/Card";
import { SeverityChip } from "@/components/SeverityChip";
import type { PackageRef, Severity } from "@/lib/types";

export interface DependencyRow {
  pkg: PackageRef;
  /** Highest severity and number of dependency findings that mention this package, or null. */
  vuln: { severity: Severity; count: number } | null;
}

const COLLAPSED_ROWS = 15;

export default function DependencyTable({ rows }: { rows: DependencyRow[] }) {
  const [expanded, setExpanded] = useState(false);
  const collapsible = rows.length > COLLAPSED_ROWS;

  return (
    <div>
      <div className="overflow-x-auto print:overflow-visible" role="region" aria-label="Dependencies table" tabIndex={0}>
        <table className="w-full min-w-[720px] text-[13px]">
          <thead className="border-b border-slate-200 bg-slate-50/70">
            <tr>
              <th scope="col" className={th}>Package</th>
              <th scope="col" className={th}>Version</th>
              <th scope="col" className={th}>Ecosystem</th>
              <th scope="col" className={th}>Source</th>
              <th scope="col" className={th}>Known vulnerabilities</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {rows.map((r, i) => {
              const hidden = collapsible && !expanded && i >= COLLAPSED_ROWS;
              return (
                <tr key={`${r.pkg.ecosystem}:${r.pkg.name}@${r.pkg.version}:${i}`} className={`${hidden ? "hidden print:table-row" : ""} avoid-break`}>
                  <td className={`${td} py-2 font-mono text-slate-900`}>{r.pkg.name}</td>
                  <td className={`${td} py-2 font-mono text-slate-700`}>
                    {r.pkg.version}
                    {r.pkg.approximate && (
                      <span className="ml-1.5 font-sans text-[11px] text-slate-500" title="Derived from a version range, not a lockfile">
                        (range)
                      </span>
                    )}
                  </td>
                  <td className={`${td} py-2 whitespace-nowrap text-slate-700`}>{r.pkg.ecosystem}</td>
                  <td className={`${td} py-2 font-mono text-xs text-slate-500`}>
                    <span className="block max-w-[260px] truncate print:max-w-none print:whitespace-normal print:break-all" title={r.pkg.source}>
                      {r.pkg.source}
                    </span>
                  </td>
                  <td className={`${td} py-2 whitespace-nowrap`}>
                    {r.vuln ? (
                      <span className="inline-flex items-center gap-2">
                        <SeverityChip severity={r.vuln.severity} />
                        <span className="tabular text-xs text-slate-600">
                          {r.vuln.count} {r.vuln.count === 1 ? "advisory" : "advisories"}
                        </span>
                      </span>
                    ) : (
                      <span className="text-xs text-slate-500">None known</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {collapsible && (
        <div className="border-t border-slate-200 px-4 py-2.5 sm:px-5 print:hidden">
          <button type="button" onClick={() => setExpanded((v) => !v)} aria-expanded={expanded} className="text-[13px] font-medium text-brand hover:underline">
            {expanded ? `Show first ${COLLAPSED_ROWS} only` : `Show all ${rows.length} packages`}
          </button>
        </div>
      )}
    </div>
  );
}
