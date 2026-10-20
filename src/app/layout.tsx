import type { Metadata, Viewport } from "next";
import { IBM_Plex_Mono, Inter, Plus_Jakarta_Sans } from "next/font/google";
import Link from "next/link";
import type { ReactNode } from "react";
import { GateMark, PlusIcon } from "@/components/icons";
import { NavLinks } from "@/components/NavLinks";
import { getStore } from "@/lib/store";
import "./globals.css";

const inter = Inter({ variable: "--font-inter", subsets: ["latin"], display: "swap" });
const jakarta = Plus_Jakarta_Sans({ variable: "--font-jakarta", subsets: ["latin"], weight: ["500", "600", "700"], display: "swap" });
const plexMono = IBM_Plex_Mono({ variable: "--font-plex-mono", subsets: ["latin"], weight: ["400", "500", "600"], display: "swap" });

// De demo-melding hangt af van runtime environment variables.
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: { default: "AI Asset Gate", template: "%s · AI Asset Gate" },
  description: "Security and governance intake for AI assets before publication in the Azure AI product catalogue.",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = { themeColor: "#FFFFFF" };

export default function RootLayout({ children }: { children: ReactNode }) {
  const demoMode = getStore().kind === "memory";
  return (
    <html lang="en" className={`${inter.variable} ${jakarta.variable} ${plexMono.variable}`}>
      <body className="flex min-h-screen flex-col text-sm antialiased">
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded-lg focus:bg-white focus:px-3 focus:py-2 focus:text-sm focus:font-medium focus:text-ink focus:shadow"
        >
          Skip to content
        </a>
        <header className="sticky top-0 z-30 border-b border-line bg-white/95 backdrop-blur print:hidden">
          <div className="mx-auto flex h-16 max-w-[1280px] items-center gap-4 px-4 sm:gap-8 sm:px-6 lg:px-8">
            <Link href="/" className="flex shrink-0 items-center gap-2.5" aria-label="AI Asset Gate, overview">
              <GateMark size={30} />
              <span className="hidden flex-col leading-tight sm:flex">
                <span className="font-display text-[15px] font-bold tracking-tight text-ink">AI Asset Gate</span>
                <span className="text-[11px] font-medium text-subtle">Azure AI catalogue intake</span>
              </span>
            </Link>
            <NavLinks />
            <Link
              href="/submit"
              className="ml-auto inline-flex h-10 shrink-0 items-center gap-2 rounded-lg bg-brand px-3.5 text-sm font-semibold text-white shadow-xs transition-colors hover:bg-brand-strong"
            >
              <PlusIcon size={16} />
              <span className="hidden sm:inline">New submission</span>
              <span className="sm:hidden">New</span>
            </Link>
          </div>
        </header>
        {demoMode && (
          <div className="border-b border-amber-200 bg-amber-50 text-amber-900 print:hidden" role="status">
            <div className="mx-auto max-w-[1280px] px-4 py-2 text-[13px] sm:px-6 lg:px-8">
              <span className="font-semibold">Demo mode:</span> storage is not configured, so submissions are kept in memory only.
            </div>
          </div>
        )}
        <main id="main" className="mx-auto w-full max-w-[1280px] flex-1 px-4 py-8 sm:px-6 sm:py-10 lg:px-8 print:max-w-none print:p-0">
          {children}
        </main>
        <footer className="border-t border-line bg-white print:hidden">
          <div className="mx-auto flex max-w-[1280px] flex-col gap-1 px-4 py-5 text-[13px] text-subtle sm:flex-row sm:items-center sm:justify-between sm:px-6 lg:px-8">
            <span>Scanners use open-source rulesets and OSV.dev vulnerability data. Uploaded code is never executed.</span>
            <span>Demo environment</span>
          </div>
        </footer>
      </body>
    </html>
  );
}
