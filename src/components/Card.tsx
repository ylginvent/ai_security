import type { ReactNode } from "react";

/** Shared button styles (class strings so they work on <button>, <a> and <Link>). */
export const btn = {
  primary:
    "inline-flex h-9 items-center justify-center gap-2 rounded-md bg-brand px-3.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-brand-strong disabled:cursor-not-allowed disabled:bg-slate-300 disabled:text-slate-600 disabled:shadow-none",
  secondary:
    "inline-flex h-9 items-center justify-center gap-2 rounded-md border border-slate-300 bg-white px-3 text-sm font-medium text-slate-800 shadow-sm transition-colors hover:bg-slate-50 hover:border-slate-400 disabled:cursor-not-allowed disabled:text-slate-400 disabled:hover:bg-white",
  ghost:
    "inline-flex h-8 items-center justify-center gap-1.5 rounded-md px-2.5 text-sm font-medium text-slate-600 transition-colors hover:bg-slate-100 hover:text-slate-900 disabled:cursor-not-allowed disabled:text-slate-400",
  danger:
    "inline-flex h-9 items-center justify-center gap-2 rounded-md border border-sev-critical/40 bg-white px-3 text-sm font-medium text-sev-critical shadow-sm transition-colors hover:bg-sev-critical-soft disabled:cursor-not-allowed disabled:border-slate-200 disabled:text-slate-400 disabled:hover:bg-white",
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
    <Tag id={id} aria-labelledby={labelledBy} className={`rounded-lg border border-slate-200 bg-white shadow-[0_1px_2px_rgba(15,23,42,0.04)] ${className}`}>
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
    <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2 border-b border-slate-200 px-4 py-3 sm:px-5">
      <div className="min-w-0">
        <h2 id={id} className="flex items-center gap-2 text-[15px] font-semibold text-slate-900">
          {title}
          {meta !== undefined && <span className="tabular rounded bg-slate-100 px-1.5 py-0.5 text-xs font-medium text-slate-600">{meta}</span>}
        </h2>
        {description && <p className="mt-0.5 text-[13px] text-slate-500">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/** Small uppercase label used above values (KPIs, definition lists). */
export function Eyebrow({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`text-[11px] font-medium uppercase tracking-[0.06em] text-slate-500 ${className}`}>{children}</div>;
}

export function PageHeader({ title, description, actions, eyebrow }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; eyebrow?: ReactNode }) {
  return (
    <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        {eyebrow && <div className="mb-1.5">{eyebrow}</div>}
        <h1 className="text-[22px] font-semibold tracking-tight text-slate-900 sm:text-2xl">{title}</h1>
        {description && <p className="mt-1.5 max-w-3xl text-sm leading-6 text-slate-600">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2 print:hidden">{actions}</div>}
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

export const th = "whitespace-nowrap px-3 py-2 text-left text-[11px] font-medium uppercase tracking-[0.06em] text-slate-500 first:pl-4 last:pr-4 sm:first:pl-5 sm:last:pr-5";
export const td = "px-3 py-2.5 align-middle first:pl-4 last:pr-4 sm:first:pl-5 sm:last:pr-5";
