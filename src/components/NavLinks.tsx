"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const LINKS = [
  { href: "/", label: "Overview" },
  { href: "/submit", label: "New submission" },
  { href: "/methodology", label: "Methodology" },
] as const;

export function NavLinks() {
  const pathname = usePathname() ?? "/";
  return (
    <nav aria-label="Main" className="-mb-px flex h-full items-stretch gap-1 overflow-x-auto">
      {LINKS.map((l) => {
        const active = l.href === "/" ? pathname === "/" || pathname.startsWith("/reports") : pathname.startsWith(l.href);
        return (
          <Link
            key={l.href}
            href={l.href}
            aria-current={active ? "page" : undefined}
            className={`flex items-center whitespace-nowrap border-b-2 px-3 text-[13px] font-medium transition-colors focus-visible:outline-white focus-visible:-outline-offset-2 ${
              active ? "border-[#4FA3D9] text-white" : "border-transparent text-slate-300 hover:text-white"
            }`}
          >
            {l.label}
          </Link>
        );
      })}
    </nav>
  );
}
