import type { Metadata } from "next";
import Link from "next/link";
import { btn } from "@/components/Card";

export const metadata: Metadata = { title: "Not found" };

export default function NotFound() {
  return (
    <div className="mx-auto max-w-lg py-16 text-center">
      <p className="font-mono text-xs font-medium text-brand">404</p>
      <h1 className="mt-2 text-xl font-semibold tracking-tight text-slate-900">Page or submission not found</h1>
      <p className="mt-2 text-sm leading-6 text-slate-600">
        The link may be incorrect, or the submission no longer exists. In demo mode, submissions are kept in memory and disappear when the server
        restarts.
      </p>
      <div className="mt-6 flex justify-center gap-2">
        <Link href="/" className={btn.primary}>
          Go to overview
        </Link>
        <Link href="/submit" className={btn.secondary}>
          New submission
        </Link>
      </div>
    </div>
  );
}
