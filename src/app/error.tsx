"use client";

import Link from "next/link";
import { useEffect } from "react";
import { btn } from "@/components/Card";

export default function ErrorPage({
  error,
  retry,
  reset,
}: {
  error: Error & { digest?: string };
  retry?: () => void;
  reset?: () => void;
}) {
  useEffect(() => {
    console.error(error);
  }, [error]);

  const tryAgain = () => {
    if (retry) retry();
    else if (reset) reset();
    else window.location.reload();
  };

  return (
    <div className="mx-auto max-w-lg py-16 text-center" role="alert">
      <p className="font-mono text-xs font-medium text-sev-critical">Error</p>
      <h1 className="mt-2 text-xl font-semibold tracking-tight text-ink">Something went wrong</h1>
      <p className="mt-2 text-sm leading-6 text-muted">
        The page could not be loaded. This is usually temporary — try again, or return to the overview.
      </p>
      {error.digest && (
        <p className="mt-3 text-xs text-subtle">
          Reference <span className="font-mono">{error.digest}</span>
        </p>
      )}
      <div className="mt-6 flex justify-center gap-2">
        <button type="button" onClick={tryAgain} className={btn.primary}>
          Try again
        </button>
        <Link href="/" className={btn.secondary}>
          Go to overview
        </Link>
      </div>
    </div>
  );
}
