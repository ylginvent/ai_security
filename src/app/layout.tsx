import type { Metadata, Viewport } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import Link from "next/link";
import type { ReactNode } from "react";
import { GateMark } from "@/components/icons";
import { NavLinks } from "@/components/NavLinks";
import { getStore } from "@/lib/store";
import "./globals.css";

const plex = IBM_Plex_Sans({ variable: "--font-plex", subsets: ["latin"], weight: ["400", "500", "600", "700"], display: "swap" });
const plexMono = IBM_Plex_Mono({ variable: "--font-plex-mono", subsets: ["latin"], weight: ["400", "500", "600"], display: "swap" });

// The demo-mode notice depends on runtime environment variables.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: { default: "AI Asset Gate", template: "%s · AI Asset Gate" },
  description: "Security and governance intake for AI assets before publication in the Azure AI product catalogue.",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = { themeColor: "#0B1F33" };

export default function RootLayout({ children }: { children: ReactNode }) {
  const demoMode = getStore().kind === "memory";
  return (
    <html lang="en" className={`${plex.variable} ${plexMono.variable}`}>
      <body className="flex min-h-screen flex-col text-sm antialiased">
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded focus:bg-white focus:px-3 focus:py-2 focus:text-sm focus:font-medium focus:text-slate-900 focus:shadow"
        >
          Skip to content
        </a>
        <header className="bg-navy text-white print:hidden">
          <div className="mx-auto flex max-w-[1280px] flex-col px-4 sm:h-14 sm:flex-row sm:items-stretch sm:justify-between sm:px-6 lg:px-8">
            <Link
              href="/"
              className="flex items-center gap-3 py-3 focus-visible:outline-white sm:py-0"
              aria-label="AI Asset Gate, overview"
            >
              <GateMark size={24} />
              <span className="flex min-w-0 flex-col leading-tight sm:flex-row sm:items-baseline sm:gap-3">
                <span className="text-[15px] font-semibold tracking-tight">AI Asset Gate</span>
                <span className="hidden truncate text-xs text-slate-400 md:inline">Azure AI Catalogue · Security &amp; Governance Intake</span>
              </span>
            </Link>
            <div className="-mx-4 h-11 border-t border-white/10 px-1 sm:mx-0 sm:h-auto sm:border-0 sm:px-0">
              <NavLinks />
            </div>
          </div>
        </header>
        {demoMode && (
          <div className="border-b border-amber-200 bg-amber-50 text-amber-900 print:hidden" role="status">
            <div className="mx-auto max-w-[1280px] px-4 py-2 text-xs sm:px-6 lg:px-8">
              <span className="font-semibold">Demo mode:</span> storage not configured — submissions are kept in memory only.
            </div>
          </div>
        )}
        <main id="main" className="mx-auto w-full max-w-[1280px] flex-1 px-4 py-6 sm:px-6 sm:py-8 lg:px-8 print:max-w-none print:p-0">
          {children}
        </main>
        <footer className="border-t border-slate-200 bg-white print:hidden">
          <div className="mx-auto flex max-w-[1280px] flex-col gap-1 px-4 py-4 text-xs text-slate-500 sm:flex-row sm:items-center sm:justify-between sm:px-6 lg:px-8">
            <span>Demo environment · scanners use open-source rulesets and OSV.dev data</span>
            <span>Capgemini · Azure AI product catalogue intake</span>
          </div>
        </footer>
      </body>
    </html>
  );
}
