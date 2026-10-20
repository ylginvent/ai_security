"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const LINKS = [
  { href: "/", label: "Overview" },
  { href: "/submit", label: "Submit asset" },
  { href: "/methodology", label: "Methodology" },
] as const;

export function NavLinks() {
  const pathname = usePathname() ?? "/";
  return (
    <nav aria-label="Main" className="flex min-w-0 items-center gap-1 overflow-x-auto">
      {LINKS.map((l) => {
        const active = l.href === "/" ? pathname === "/" || pathname.startsWith("/reports") : pathname.startsWith(l.href);
        return (
          <Link
            key={l.href}
            href={l.href}
            aria-current={active ? "page" : undefined}
            className={`whitespace-nowrap rounded-md px-3 py-2 text-sm font-medium transition-colors ${
              active ? "bg-surface-2 text-ink ring-1 ring-inset ring-line" : "text-muted hover:bg-surface-2 hover:text-ink"
            }`}
          >
            {l.label}
          </Link>
        );
      })}
    </nav>
  );
}
