"use client";

import type { MouseEvent, ReactNode } from "react";
import { REVEAL_EVENT, findingAnchor } from "./anchors";

/**
 * Link from the hero's "Fix first" list to a finding in the explorer.
 * Works as a plain hash link without JavaScript; with JavaScript it asks the explorer to
 * clear filters if needed, expand the finding and scroll to it (also on repeated clicks).
 */
export default function FixFirstLink({ index, className, children }: { index: number; className?: string; children: ReactNode }) {
  const hash = `#${findingAnchor(index)}`;

  function onClick(e: MouseEvent<HTMLAnchorElement>) {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    try {
      window.history.replaceState(window.history.state, "", hash);
    } catch {
      /* ignore */
    }
    window.dispatchEvent(new CustomEvent<number>(REVEAL_EVENT, { detail: index }));
  }

  return (
    <a href={hash} onClick={onClick} className={className}>
      {children}
    </a>
  );
}
