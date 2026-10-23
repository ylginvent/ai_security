"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

/**
 * Re-renders the (server) report page every few seconds while the scan is running.
 * Unmounts as soon as the page no longer renders it (scan completed or failed), which stops the polling.
 */
export default function AutoRefresh({ intervalMs = 4000 }: { intervalMs?: number }) {
  const router = useRouter();
  useEffect(() => {
    const t = window.setInterval(() => {
      if (document.visibilityState === "visible") router.refresh();
    }, intervalMs);
    return () => window.clearInterval(t);
  }, [router, intervalMs]);
  return null;
}
