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

/** What each severity means for the decision, in plain words (shown next to findings and in the legend). */
export const SEVERITY_MEANING: Record<Severity, string> = {
  critical: "Blocks publication. Fix it before you submit again.",
  high: "Needs a fix or a reviewer's documented risk acceptance. A high-severity exposed secret also blocks publication.",
  medium: "Lowers the trust score. Fix it when you can.",
  low: "Minor issue with a small effect on the trust score.",
  info: "For your information only. Does not affect the score or the decision.",
};

/** One-line plain-language description of what each scanner looks for. */
export const SCANNER_HELP: Record<ScannerId, string> = {
  secrets: "Passwords, API keys, tokens and private keys written into the code or config.",
  dependencies: "Third-party packages with known vulnerabilities, licence problems or no maintenance.",
  sast: "Risky code patterns such as injection, unsafe deserialisation or disabled TLS checks.",
  ai: "LLM-specific risks such as prompt injection, unsafe output handling or too much agent autonomy.",
  model: "Model files (pickle, Keras, NumPy) that can run code when they are loaded.",
  config: "Dockerfiles, infrastructure-as-code and CI pipeline settings.",
  skill: "Format, quality and safety of the agent skill (SKILL.md and its scripts).",
  questionnaire: "Risks that follow from your intake answers.",
  consistency: "Intake answers that contradict what the scan found in the code.",
};

/** OWASP Top 10 for LLM Applications 2025. */
const OWASP_LLM: Record<string, string> = {
  "01": "Prompt injection",
  "02": "Sensitive information disclosure",
  "03": "Supply chain risk",
  "04": "Data and model poisoning",
  "05": "Improper output handling",
  "06": "Excessive agency (too much autonomy)",
  "07": "System prompt leakage",
  "08": "Vector and embedding weaknesses",
  "09": "Misinformation",
  "10": "Unbounded consumption (cost / denial of service)",
};

/** Short plain-language names for the CWE weakness types the scanners use most. */
const CWE_NAMES: Record<string, string> = {
  "78": "OS command injection",
  "79": "Cross-site scripting (XSS)",
  "89": "SQL injection",
  "94": "Code injection",
  "95": "Eval injection",
  "200": "Exposure of sensitive information",
  "250": "Running with more privileges than needed",
  "347": "Signature not verified",
  "284": "Missing or weak access control",
  "287": "Improper authentication",
  "295": "TLS certificate not validated",
  "306": "Missing authentication",
  "319": "Sensitive data sent unencrypted",
  "326": "Encryption too weak",
  "327": "Broken or risky cryptography",
  "377": "Insecure temporary file",
  "400": "Uncontrolled resource consumption",
  "489": "Debug code left enabled",
  "494": "Code downloaded without an integrity check",
  "502": "Unsafe deserialisation of untrusted data",
  "506": "Embedded malicious code",
  "522": "Credentials not protected well enough",
  "532": "Sensitive data written to logs",
  "538": "Sensitive data in a publicly reachable file",
  "668": "Resource exposed to the wrong audience",
  "770": "No limit on resource use",
  "798": "Hard-coded credentials",
  "829": "Code included from an untrusted source",
  "918": "Server-side request forgery (SSRF)",
  "942": "Overly permissive CORS policy",
  "1007": "Look-alike or hidden characters",
  "1104": "Unmaintained third-party component",
  "1327": "Service listening on all network interfaces",
  "1357": "Relying on a component that isn't trustworthy enough",
};

/** MITRE ATLAS techniques referenced by the AI rules. */
const ATLAS: Record<string, string> = {
  "AML.T0010": "ML supply chain compromise",
  "AML.T0011": "Unsafe ML artefact executed by a user",
  "AML.T0024": "Data exfiltration through the model API",
  "AML.T0051": "LLM prompt injection",
  "AML.T0053": "LLM plugin / tool compromise",
  "AML.T0057": "LLM data leakage",
};

export interface RefInfo {
  /** The reference exactly as stored, e.g. "CWE-798". */
  id: string;
  /** Plain-language meaning, e.g. "Hard-coded credentials". Null when we don't have one. */
  meaning: string | null;
  /** Which catalogue the reference comes from, in plain words. */
  kind: string;
  /** External documentation, or null. */
  href: string | null;
}

/** Marker the suppression step adds to `refs`; not a real reference. */
export const SUPPRESSED_REF = "suppressed";

/**
 * Explains a finding reference (CWE, OWASP LLM, CVE/GHSA, MITRE ATLAS, EU AI Act, GDPR, Hadolint …) for developers
 * who don't know the catalogues by heart.
 */
export function refInfo(ref: string): RefInfo {
  const r = ref.trim();
  const vuln = r.match(/^(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|PYSEC-\d{4}-\d+|GO-\d{4}-\d+|RUSTSEC-\d{4}-\d+)$/i);
  if (vuln) {
    const id = /^ghsa/i.test(vuln[1]) ? `GHSA${vuln[1].slice(4).toLowerCase()}` : vuln[1].toUpperCase();
    return { id: r, meaning: null, kind: "Published security advisory", href: `https://osv.dev/vulnerability/${encodeURIComponent(id)}` };
  }
  const cwe = r.match(/^CWE-(\d+)$/i);
  if (cwe) return { id: r, meaning: CWE_NAMES[cwe[1]] ?? null, kind: "Weakness type (CWE)", href: `https://cwe.mitre.org/data/definitions/${cwe[1]}.html` };
  const llm = r.match(/^(?:OWASP\s+)?LLM(\d{2})(?::\d{4})?$/i);
  if (llm) return { id: r, meaning: OWASP_LLM[llm[1]] ?? null, kind: "OWASP Top 10 risk for LLM apps", href: "https://genai.owasp.org/llm-top-10/" };
  const atlas = r.match(/^(?:MITRE\s+)?ATLAS\s+(AML\.T\d{4}(?:\.\d{3})?)$/i);
  if (atlas) {
    const id = atlas[1].toUpperCase();
    return { id: r, meaning: ATLAS[id] ?? null, kind: "AI attack technique (MITRE ATLAS)", href: `https://atlas.mitre.org/techniques/${id}` };
  }
  if (/^(?:MITRE\s+)?ATLAS$/i.test(r)) return { id: r, meaning: null, kind: "AI attack techniques (MITRE ATLAS)", href: "https://atlas.mitre.org/" };
  const aiAct = r.match(/^EU AI Act Art\.?\s*(\d+)/i);
  if (aiAct) return { id: r, meaning: null, kind: "EU AI Act article", href: `https://artificialintelligenceact.eu/article/${aiAct[1]}/` };
  const gdpr = r.match(/^GDPR Art\.?\s*(\d+)/i);
  if (gdpr) return { id: r, meaning: null, kind: "GDPR (EU privacy law) article", href: `https://gdpr-info.eu/art-${gdpr[1]}-gdpr/` };
  if (/^GDPR Chapter V$/i.test(r)) return { id: r, meaning: "Transfers of personal data outside the EU", kind: "GDPR (EU privacy law)", href: "https://gdpr-info.eu/chapter-5/" };
  const hado = r.match(/^Hadolint (DL\d{4})$/i);
  if (hado) return { id: r, meaning: null, kind: "Dockerfile best practice (Hadolint)", href: `https://github.com/hadolint/hadolint/wiki/${hado[1].toUpperCase()}` };
  if (/^Checkov\b/i.test(r)) return { id: r, meaning: null, kind: "Infrastructure-as-code policy (Checkov)", href: null };
  if (/^NIST AI RMF\b/i.test(r)) return { id: r, meaning: null, kind: "NIST AI Risk Management Framework", href: null };
  if (/^ISO\/IEC 42001\b/i.test(r)) return { id: r, meaning: null, kind: "AI management system standard (ISO/IEC 42001)", href: null };
  if (/^ISO\/IEC 27001\b/i.test(r)) return { id: r, meaning: null, kind: "Information security standard (ISO/IEC 27001)", href: null };
  if (/^SPDX\b/i.test(r)) return { id: r, meaning: null, kind: "Software licence", href: null };
  if (/^OpenSSF\b/i.test(r)) return { id: r, meaning: null, kind: "Open-source security practice (OpenSSF)", href: null };
  return { id: r, meaning: null, kind: "Reference", href: null };
}

/** External documentation link for a finding reference (CVE/GHSA, CWE, OWASP LLM Top 10, ATLAS, …), or null. */
export function refHref(ref: string): string | null {
  return refInfo(ref).href;
}

export interface SuppressionInfo {
  /** The finding description without the suppression note. */
  description: string;
  /** Why the finding was downgraded, in the scanner's words, or null if unknown. */
  reason: string | null;
  /** Severity before the downgrade, if known. */
  originalSeverity: Severity | null;
  /** True when the reason is "test, example or demo code". */
  testCode: boolean;
}

/**
 * Detects findings that were downgraded to "info" by an exception (.aigateignore, inline nosec / nosemgrep comment)
 * or because they are in test/example code, and splits the explanation off the description.
 */
export function suppressionInfo(f: { refs: string[]; description: string }): SuppressionInfo | null {
  const marked = f.refs.some((r) => r.trim().toLowerCase() === SUPPRESSED_REF);
  const m = /\s*[—–-]+\s*Suppressed:\s*/i.exec(f.description);
  if (!marked && !m) return null;
  const description = m ? f.description.slice(0, m.index).trim() : f.description;
  let rest = m ? f.description.slice(m.index + m[0].length) : "";
  const sev = /Original severity:\s*(critical|high|medium|low)\b\.?/i.exec(rest);
  const originalSeverity = sev ? (sev[1].toLowerCase() as Severity) : null;
  rest = rest
    .replace(/Original severity:\s*\w+\.?/i, "")
    .replace(/The reviewer should confirm this exception\.?/i, "")
    .trim();
  return {
    description: description || f.description,
    reason: rest ? rest[0].toUpperCase() + rest.slice(1) : null,
    originalSeverity,
    testCode: /\b(?:test|example|demo|sample)s?\b[^.]*\bcode\b/i.test(rest),
  };
}

/** Shortens a long path for one-line display, keeping the file name: "…/services/chat/handler.py". */
export function shortPath(path: string, max = 56): string {
  if (path.length <= max) return path;
  const parts = path.split("/");
  let out = parts.pop() ?? path;
  while (parts.length && out.length + parts[parts.length - 1].length + 1 <= max - 2) out = `${parts.pop()}/${out}`;
  return parts.length ? `…/${out}` : out;
}

/** "review_approved" -> "Review approved" */
export function humanize(s: string): string {
  const t = s.replace(/[_.]+/g, " ").trim();
  return t ? t[0].toUpperCase() + t.slice(1) : s;
}
