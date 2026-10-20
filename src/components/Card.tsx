import type { ReactNode } from "react";

/** Shared button styles (class strings so they work on <button>, <a> and <Link>). */
export const btn = {
  primary:
    "inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-brand bg-brand px-4 text-sm font-semibold text-white shadow-xs transition-colors hover:border-brand-strong hover:bg-brand-strong disabled:cursor-not-allowed disabled:border-line-strong disabled:bg-line disabled:text-subtle disabled:shadow-none",
  secondary:
    "inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-line-strong bg-white px-4 text-sm font-semibold text-ink-2 shadow-xs transition-colors hover:bg-surface-2 disabled:cursor-not-allowed disabled:text-faint disabled:hover:bg-white",
  ghost:
    "inline-flex h-9 items-center justify-center gap-1.5 rounded-lg px-3 text-sm font-semibold text-muted transition-colors hover:bg-surface-2 hover:text-ink disabled:cursor-not-allowed disabled:text-faint",
  danger:
    "inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-[#FDA29B] bg-white px-4 text-sm font-semibold text-sev-critical shadow-xs transition-colors hover:bg-sev-critical-soft disabled:cursor-not-allowed disabled:border-line disabled:text-faint disabled:hover:bg-white",
  /** Large call to action for single-task screens. */
  hero:
    "inline-flex h-12 items-center justify-center gap-2 rounded-xl bg-brand px-6 text-[15px] font-bold text-white shadow-xs transition-colors hover:bg-brand-strong disabled:cursor-not-allowed disabled:bg-line disabled:text-subtle disabled:shadow-none",
};

export function Card({ children, className = "", as = "section", id, labelledBy }: {
  children: ReactNode;
  className?: string;
  as?: "section" | "div" | "aside";
  id?: string;
  labelledBy?: string;
}) {
  const Tag = as;
  return (
    <Tag id={id} aria-labelledby={labelledBy} className={`rounded-xl border border-line bg-white shadow-xs ${className}`}>
      {children}
    </Tag>
  );
}

/** Header row inside a Card: title, optional description, optional right-aligned actions. */
export function CardHeader({
  title,
  id,
  description,
  actions,
  meta,
}: {
  title: ReactNode;
  id?: string;
  description?: ReactNode;
  actions?: ReactNode;
  meta?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-3 border-b border-line px-5 py-4 sm:px-6 sm:py-5">
      <div className="min-w-0">
        <h2 id={id} className="flex items-center gap-2 text-[17px] font-semibold text-ink">
          {title}
          {meta !== undefined && (
            <span className="tabular rounded-full bg-brand-soft px-2 py-0.5 font-sans text-xs font-medium text-brand-strong">{meta}</span>
          )}
        </h2>
        {description && <p className="mt-1 text-sm text-muted">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/** Small label used above values (KPIs, definition lists). */
export function Eyebrow({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`text-[13px] font-medium text-subtle ${className}`}>{children}</div>;
}

export function PageHeader({ title, description, actions, eyebrow }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; eyebrow?: ReactNode }) {
  return (
    <div className="flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        {eyebrow && <div className="mb-2 text-sm text-muted">{eyebrow}</div>}
        <h1 className="text-[28px] font-bold leading-tight tracking-tight text-ink sm:text-[32px]">{title}</h1>
        {description && <p className="mt-2 max-w-3xl text-base leading-7 text-muted">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-3 print:hidden">{actions}</div>}
    </div>
  );
}

/** Wrapper that lets wide tables scroll horizontally inside their card instead of the page. */
export function TableScroll({ children, label }: { children: ReactNode; label?: string }) {
  return (
    <div className="overflow-x-auto print:overflow-visible" role={label ? "region" : undefined} aria-label={label} tabIndex={label ? 0 : undefined}>
      {children}
    </div>
  );
}

/** Table header cell: light grey band, sentence case. Use with <thead className={thead}>. */
export const thead = "border-b border-line bg-surface-2";
export const th = "whitespace-nowrap px-4 py-3 text-left text-xs font-medium text-muted first:pl-5 last:pr-5 sm:first:pl-6 sm:last:pr-6";
export const td = "px-4 py-4 align-middle text-sm text-muted first:pl-5 last:pr-5 sm:first:pl-6 sm:last:pr-6";

const TILE_TONES = [
  "bg-brand-soft text-brand-strong",
  "bg-[#ECFDF3] text-[#067647]",
  "bg-[#FFF6E5] text-[#8A4B00]",
  "bg-[#F4F3FF] text-[#5925DC]",
  "bg-[#FDF2FA] text-[#C11574]",
  "bg-[#EFF8FF] text-[#175CD3]",
];

/** Rounded initials tile for an asset, colour derived from the name. */
export function InitialsTile({ name, size = "md" }: { name: string; size?: "sm" | "md" | "lg" }) {
  const words = name.replace(/[^A-Za-z0-9 ]+/g, " ").trim().split(/\s+/).filter(Boolean);
  const initials = ((words[0]?.[0] ?? "?") + (words[1]?.[0] ?? words[0]?.[1] ?? "")).toUpperCase();
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  const tone = TILE_TONES[h % TILE_TONES.length];
  const dim = size === "sm" ? "size-8 rounded-lg text-xs" : size === "lg" ? "size-14 rounded-2xl text-lg" : "size-10 rounded-xl text-sm";
  return (
    <span aria-hidden="true" className={`flex shrink-0 items-center justify-center font-display font-bold ${dim} ${tone}`}>
      {initials}
    </span>
  );
}

const FILE_TONES: Record<string, string> = {
  ZIP: "bg-brand-soft text-brand-strong",
  GZ: "bg-brand-soft text-brand-strong",
  TAR: "bg-brand-soft text-brand-strong",
  PKL: "bg-[#F4F3FF] text-[#5925DC]",
  PT: "bg-[#F4F3FF] text-[#5925DC]",
  PY: "bg-[#ECFDF3] text-[#067647]",
  IPYNB: "bg-[#FFF6E5] text-[#8A4B00]",
};

/** File-type badge used in upload rows (e.g. ZIP, PY). Pass `error` for rejected files. */
export function FileTypeBadge({ fileName, error = false }: { fileName: string; error?: boolean }) {
  const ext = (fileName.split(".").pop() ?? "").toUpperCase().slice(0, 5) || "FILE";
  const tone = error ? "bg-[#FEE4E2] text-sev-critical" : FILE_TONES[ext] ?? "bg-surface-2 text-ink-2 ring-1 ring-inset ring-line";
  return (
    <span aria-hidden="true" className={`flex size-10 shrink-0 items-center justify-center rounded-lg text-[10px] font-bold tracking-wide ${tone}`}>
      {ext}
    </span>
  );
}
