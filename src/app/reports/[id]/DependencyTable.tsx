"use client";

import { useState } from "react";
import { thead } from "@/components/Card";
import { CheckIcon, ChevronDownIcon } from "@/components/icons";
import { SeverityChip } from "@/components/SeverityChip";
import type { PackageRef, Severity } from "@/lib/types";

export interface DependencyRow {
  pkg: PackageRef;
  /** Highest severity and number of dependency findings that mention this package, or null. */
  vuln: { severity: Severity; count: number } | null;
}

const COLLAPSED_ROWS = 15;

// Local cell styles (A table style: grey header band, sentence-case headers, 14px rows).
const thCls = "whitespace-nowrap px-4 py-3 text-left text-xs font-medium text-muted first:pl-5 last:pr-5 sm:first:pl-6 sm:last:pr-6";
const tdCls = "px-4 py-3.5 align-middle text-sm text-muted first:pl-5 last:pr-5 sm:first:pl-6 sm:last:pr-6";

/**
 * Strong copyleft or non-commercial licences (GPL, AGPL, SSPL, CC-BY-NC, BUSL, Commons Clause) are worth a reviewer's look.
 * LGPL (weak copyleft) is not highlighted: "GPL" preceded by "L" does not match.
 */
const RESTRICTIVE = /(^|[^L])GPL|SSPL|CC-BY-NC|BUSL|Commons-Clause/i;

function isRestrictive(id: string): boolean {
  return RESTRICTIVE.test(id);
}

function LicenceCell({ licenses }: { licenses: string[] | undefined }) {
  if (!Array.isArray(licenses)) return <span className="text-faint">—</span>;
  if (licenses.length === 0) {
    return (
      <span className="text-[13px] font-medium text-warn" title="deps.dev reports no licence for this version">
        None found
      </span>
    );
  }
  return (
    <span className="flex flex-wrap gap-1">
      {licenses.map((l, i) => {
        const restrictive = isRestrictive(l);
        return (
          <span
            key={`${l}-${i}`}
            title={restrictive ? "Copyleft or restrictive licence: check before commercial reuse" : undefined}
            className={`inline-flex h-6 items-center rounded-md px-2 font-mono text-[11px] font-medium ring-1 ring-inset ${
              restrictive ? "bg-warn-soft text-warn ring-[#FEDF89]" : "bg-white text-ink-2 ring-line"
            }`}
          >
            {l}
          </span>
        );
      })}
    </span>
  );
}

export default function DependencyTable({ rows }: { rows: DependencyRow[] }) {
  const [expanded, setExpanded] = useState(false);
  const collapsible = rows.length > COLLAPSED_ROWS;
  // The column only appears when licence data was looked up (deps.dev) for at least one package.
  const showLicences = rows.some((r) => Array.isArray(r.pkg.licenses));

  return (
    <div>
      <div className="overflow-x-auto print:overflow-visible" role="region" aria-label="Dependencies table" tabIndex={0}>
        <table className={`w-full border-collapse ${showLicences ? "min-w-[860px]" : "min-w-[720px]"}`}>
          <thead className={thead}>
            <tr>
              <th scope="col" className={thCls}>Package</th>
              <th scope="col" className={thCls}>Version</th>
              <th scope="col" className={thCls}>Ecosystem</th>
              {showLicences && <th scope="col" className={thCls}>Licence</th>}
              <th scope="col" className={thCls}>Found in</th>
              <th scope="col" className={thCls}>Known vulnerabilities</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {rows.map((r, i) => {
              const hidden = collapsible && !expanded && i >= COLLAPSED_ROWS;
              return (
                <tr
                  key={`${r.pkg.ecosystem}:${r.pkg.name}@${r.pkg.version}:${i}`}
                  className={`${hidden ? "hidden print:table-row" : ""} avoid-break`}
                >
                  <td className={`${tdCls} font-medium text-ink`}>
                    <span className="break-all">{r.pkg.name}</span>
                  </td>
                  <td className={`${tdCls} whitespace-nowrap`}>
                    <span className="font-mono text-[13px] text-ink-2">{r.pkg.version}</span>
                    {r.pkg.approximate && (
                      <span className="ml-1.5 text-xs text-subtle" title="Derived from a version range, not a lockfile">
                        (range)
                      </span>
                    )}
                  </td>
                  <td className={`${tdCls} whitespace-nowrap`}>
                    <span className="inline-flex h-6 items-center rounded-md bg-surface-2 px-2 text-xs font-medium text-ink-2 ring-1 ring-inset ring-line">
                      {r.pkg.ecosystem}
                    </span>
                  </td>
                  {showLicences && (
                    <td className={`${tdCls} max-w-[200px]`}>
                      <LicenceCell licenses={r.pkg.licenses} />
                    </td>
                  )}
                  <td className={tdCls}>
                    <span
                      className="block max-w-[260px] truncate font-mono text-xs text-subtle print:max-w-none print:whitespace-normal print:break-all"
                      title={r.pkg.source}
                    >
                      {r.pkg.source}
                    </span>
                  </td>
                  <td className={`${tdCls} whitespace-nowrap`}>
                    {r.vuln ? (
                      <span className="inline-flex items-center gap-2">
                        <SeverityChip severity={r.vuln.severity} />
                        <span className="tabular text-[13px] text-ink-2">
                          {r.vuln.count} {r.vuln.count === 1 ? "advisory" : "advisories"}
                        </span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-[13px] text-subtle">
                        <CheckIcon size={14} className="text-ok" />
                        None known
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {collapsible && (
        <div className="flex items-center justify-between gap-3 border-t border-line px-5 py-3 text-[13px] text-subtle sm:px-6 print:hidden">
          <span className="tabular">
            Showing {expanded ? rows.length : COLLAPSED_ROWS} of {rows.length}
          </span>
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            aria-expanded={expanded}
            className="inline-flex items-center gap-1.5 font-semibold text-brand hover:text-brand-strong"
          >
            {expanded ? `Show first ${COLLAPSED_ROWS} only` : `Show all ${rows.length} packages`}
            <ChevronDownIcon size={16} className={`transition-transform ${expanded ? "rotate-180" : ""}`} />
          </button>
        </div>
      )}
    </div>
  );
}
