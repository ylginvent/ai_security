import type { AiActTier, ScannerId, Severity } from "./types";

/**
 * Pure formatting helpers, safe for server and client components.
 * Dates are always formatted in UTC so server- and client-rendered output is identical.
 */

export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined || !Number.isFinite(bytes)) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let v = bytes / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

const DATE_FMT = new Intl.DateTimeFormat("en-GB", { day: "2-digit", month: "short", year: "numeric", timeZone: "UTC" });
const DATETIME_FMT = new Intl.DateTimeFormat("en-GB", {
  day: "2-digit",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
  timeZone: "UTC",
});
const TIME_FMT = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false, timeZone: "UTC" });

function toDate(iso: string | null | undefined): Date | null {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** e.g. "20 Oct 2026" */
export function formatDate(iso: string | null | undefined): string {
  const d = toDate(iso);
  return d ? DATE_FMT.format(d) : "—";
}

/** e.g. "20 Oct 2026, 09:14 UTC" */
export function formatDateTime(iso: string | null | undefined): string {
  const d = toDate(iso);
  return d ? `${DATETIME_FMT.format(d)} UTC` : "—";
}

/** e.g. "09:14:03" (UTC) */
export function formatTime(iso: string | null | undefined): string {
  const d = toDate(iso);
  return d ? TIME_FMT.format(d) : "—";
}

/** Relative time ("3 min ago"). Only call from server components or client code after mount. */
export function formatRelative(iso: string | null | undefined, now: number = Date.now()): string {
  const d = toDate(iso);
  if (!d) return "";
  const s = Math.round((now - d.getTime()) / 1000);
  if (s < 45) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h} h ago`;
  const days = Math.round(h / 24);
  if (days < 30) return `${days} d ago`;
  return formatDate(iso);
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return "—";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(ms < 10_000 ? 2 : 1)} s`;
}

const NUM_FMT = new Intl.NumberFormat("en-GB");
export function formatNumber(n: number | null | undefined): string {
  return n === null || n === undefined || !Number.isFinite(n) ? "—" : NUM_FMT.format(n);
}

export function shortHash(hash: string | null | undefined, len = 12): string {
  if (!hash) return "—";
  return hash.length > len ? `${hash.slice(0, len)}…` : hash;
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export const SCANNER_LABEL: Record<ScannerId, string> = {
  secrets: "Secrets",
  dependencies: "Dependencies",
  sast: "Static analysis",
  ai: "AI / LLM rules",
  model: "Model artefacts",
  config: "Configuration & IaC",
  skill: "Agent skill review",
  questionnaire: "Questionnaire",
  consistency: "Answers vs. code",
};

export const AI_ACT_SHORT: Record<AiActTier, string> = {
  prohibited: "Prohibited",
  high: "High risk",
  limited: "Limited risk",
  minimal: "Minimal risk",
};

const BU_SHORT: Record<string, string> = {
  invent: "Capgemini Invent",
  ind: "Insights & Data",
  cis: "Cloud Infra Services",
  apps: "Apps & Technology",
  "er&d": "Engineering & R&D",
  fs: "Financial Services",
  other: "Other",
};

const TYPE_SHORT: Record<string, string> = {
  llm_app: "LLM application",
  rag: "RAG assistant",
  agent: "Agentic system",
  ml_model: "ML model",
  cv_speech: "Vision / speech",
  library: "SDK / library",
  prompts: "Prompt library",
};

export function businessUnitLabel(v: string | null | undefined): string {
  if (!v) return "—";
  return BU_SHORT[v] ?? v;
}

export function assetTypeLabel(v: string | null | undefined): string {
  if (!v) return "—";
  return TYPE_SHORT[v] ?? v;
}

/** External documentation link for a finding reference (CVE/GHSA, CWE, OWASP LLM Top 10), or null. */
export function refHref(ref: string): string | null {
  const r = ref.trim();
  const vuln = r.match(/^(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|RUSTSEC-\d{4}-\d+)$/i);
  if (vuln) {
    const id = /^ghsa/i.test(vuln[1]) ? `GHSA${vuln[1].slice(4).toLowerCase()}` : vuln[1].toUpperCase();
    return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
  }
  const cwe = r.match(/^CWE-(\d+)$/i);
  if (cwe) return `https://cwe.mitre.org/data/definitions/${cwe[1]}.html`;
  if (/^(OWASP\s+)?LLM\d{2}(:\d{4})?$/i.test(r)) return "https://genai.owasp.org/llm-top-10/";
  return null;
}

/** "review_approved" -> "Review approved" */
export function humanize(s: string): string {
  const t = s.replace(/[_.]+/g, " ").trim();
  return t ? t[0].toUpperCase() + t.slice(1) : s;
}
