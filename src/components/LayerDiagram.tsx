import type { ReactNode } from "react";
import { FileIcon, ShieldIcon, UploadIcon } from "./icons";
import { CatalogueIcon, LoopIcon, ReviewerIcon } from "./icons-extra";

/**
 * "Where the gate sits": the gate is a layer in front of the Azure AI catalogue database, not a separate portal.
 * Asset owners only see the questionnaire, the upload and their report; this overview is an optional admin console.
 * Server component, no client JavaScript. Desktop: three zones side by side; mobile: stacked.
 */

function Step({ icon, title, line }: { icon: ReactNode; title: string; line: string }) {
  return (
    <li className="flex items-start gap-2.5">
      <span className="flex size-7 shrink-0 items-center justify-center rounded-md bg-white text-brand ring-1 ring-inset ring-line">{icon}</span>
      <span className="min-w-0">
        <span className="block text-[13px] font-semibold leading-5 text-ink">{title}</span>
        <span className="block text-xs leading-[18px] text-muted">{line}</span>
      </span>
    </li>
  );
}

function Zone({ eyebrow, title, className, children }: { eyebrow: string; title: string; className: string; children: ReactNode }) {
  return (
    <div className={`flex h-full flex-col rounded-xl p-4 ${className}`}>
      <p className="text-[11px] font-semibold uppercase tracking-[0.06em] opacity-80">{eyebrow}</p>
      <p className="mt-0.5 font-display text-[15px] font-bold leading-5">{title}</p>
      {children}
    </div>
  );
}

/** Arrow between zones with a short label; horizontal on desktop, vertical on mobile. */
function Hand({ label }: { label: string }) {
  return (
    <div aria-hidden="true" className="flex items-center justify-center gap-2 py-1 lg:flex-col lg:gap-1 lg:py-0">
      <svg width="40" height="12" viewBox="0 0 40 12" focusable="false" className="hidden text-faint lg:block">
        <path d="M0 6h31" stroke="currentColor" strokeWidth="1.5" />
        <path d="M30 1.5L38.5 6 30 10.5z" fill="currentColor" />
      </svg>
      <svg width="12" height="28" viewBox="0 0 12 28" focusable="false" className="text-faint lg:hidden">
        <path d="M6 0v19" stroke="currentColor" strokeWidth="1.5" />
        <path d="M1.5 18.5L6 26.5l4.5-8z" fill="currentColor" />
      </svg>
      <span className="text-center text-[11px] font-semibold leading-4 text-subtle lg:max-w-[84px]">{label}</span>
    </div>
  );
}

export default function LayerDiagram({ className = "" }: { className?: string }) {
  return (
    <figure className={className} aria-labelledby="layer-caption">
      <div className="grid gap-0 lg:grid-cols-[minmax(0,1fr)_96px_minmax(0,1.25fr)_96px_minmax(0,1fr)] lg:items-stretch">
        <Zone eyebrow="What the asset owner sees" title="Questionnaire, upload and report" className="border border-brand/30 bg-white text-ink shadow-xs">
          <ol className="mt-3 space-y-2.5">
            <Step icon={<FileIcon size={15} />} title="Questionnaire" line="The entry point: opened from the catalogue's publish flow." />
            <Step icon={<UploadIcon size={15} />} title="Upload code or Git link" line="Last step of the same form." />
            <Step icon={<LoopIcon size={15} />} title="Report with fixes" line="Fix, submit a new version, see what improved." />
          </ol>
          <p className="mt-auto pt-3 text-xs leading-[18px] text-muted">No dashboard, no portal to learn: just the form and the result.</p>
        </Zone>

        <Hand label="Submission" />

        <Zone eyebrow="Pre-upload layer · no UI of its own" title="AI Asset Gate" className="border border-dashed border-brand/50 bg-brand-soft/60 text-ink">
          <ul className="mt-3 space-y-2.5">
            <Step icon={<ShieldIcon size={15} />} title="Automated scan + gate decision" line="Runs in front of the catalogue database, read-only." />
          </ul>
          <div className="mt-3 rounded-lg border border-line bg-white p-3 shadow-xs">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="flex items-center gap-2 text-[13px] font-semibold text-ink">
                <ReviewerIcon size={16} className="text-brand" />
                Admin &amp; reviewer console
              </p>
              <span className="inline-flex h-5 items-center rounded-full bg-brand px-2 text-[11px] font-semibold text-white">You are here</span>
            </div>
            <p className="mt-1 text-xs leading-[18px] text-muted">
              Optional. This overview lists every submission for admins and reviewers, who sign off and publish. Asset owners never see it.
            </p>
          </div>
        </Zone>

        <Hand label="Approved only" />

        <Zone eyebrow="Azure" title="AI catalogue database" className="bg-navy text-white">
          <span className="mt-3 flex size-9 items-center justify-center rounded-lg bg-white/10 text-white">
            <CatalogueIcon size={18} />
          </span>
          <p className="mt-3 text-xs leading-[18px] text-white/80">
            Only reviewed and approved assets are written here, with their report and SBOM. Blocked assets never reach the database.
          </p>
        </Zone>
      </div>
      <figcaption id="layer-caption" className="mt-3 text-[13px] leading-5 text-muted">
        <span className="font-semibold text-ink-2">Where the gate sits.</span> The gate is a layer in front of the upload to the Azure AI catalogue, not a
        separate portal. Asset owners start at the questionnaire; everything else on this page is the admin view.
      </figcaption>
    </figure>
  );
}
