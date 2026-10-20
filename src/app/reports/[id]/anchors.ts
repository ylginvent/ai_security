/**
 * Shared between the server-rendered report page and the client-side findings explorer.
 * Deliberately has no "use client" directive so the server can call these helpers.
 */

/** Window event the "Fix first" links dispatch; detail is the finding index in report.findings. */
export const REVEAL_EVENT = "aag:reveal-finding";

/** DOM id (and URL hash) of a finding row in the explorer, by its index in report.findings. */
export function findingAnchor(index: number): string {
  return `finding-${index}`;
}

/** Parses "#finding-12" (or "finding-12") back to 12; null for any other hash. */
export function parseFindingAnchor(hash: string): number | null {
  const m = /^#?finding-(\d+)$/.exec(hash);
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isSafeInteger(n) ? n : null;
}
