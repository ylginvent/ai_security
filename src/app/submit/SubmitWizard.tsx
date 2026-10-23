"use client";

import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState, type DragEvent, type ReactNode, type RefObject } from "react";
import { Card, FileTypeBadge, InitialsTile, btn } from "@/components/Card";
import {
  AlertIcon,
  ArrowLeftIcon,
  ArrowRightIcon,
  CheckIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  ShieldIcon,
  SpinnerIcon,
  UploadIcon,
  XIcon,
} from "@/components/icons";
import { AppIcon, GitBranchIcon, SkillIcon } from "@/components/icons-extra";
import { StatusPill } from "@/components/StatusPill";
import { nextVersion } from "@/lib/compare";
import { DEMO_ANSWERS, DEMO_SKILL_ANSWERS } from "@/lib/demo-answers";
import { formatBytes, formatDate } from "@/lib/format";
import { ALL_QUESTIONS, answerLabel, isSkill, isVisible, sectionsFor, validateAnswers, type Question, type Section } from "@/lib/questionnaire";
import { DECISION_LABEL } from "@/lib/scoring";
import type { Answers, Decision } from "@/lib/types";

/* ------------------------------------------------------------------ constants */

type Kind = "app" | "skill";
type SourceMode = "file" | "git";

const DRAFT_KEY = "aag.submission-draft.v1";
const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;
const DEMO: Record<Kind, { url: string; fileName: string; label: string }> = {
  app: { url: "/api/sample", fileName: "contoso-rag-assistant.zip", label: "demo application" },
  skill: { url: "/api/sample?kind=skill", fileName: "invoice-summariser-skill.zip", label: "demo skill" },
};
const ACCEPT =
  ".zip,.py,.ipynb,.js,.mjs,.cjs,.ts,.tsx,.jsx,.java,.kt,.cs,.go,.rb,.php,.rs,.json,.yaml,.yml,.toml,.tf,.bicep,.cfg,.ini,.txt,.md,.sh,.ps1";

/** Short labels for the segmented step bar (full titles are used everywhere else). */
const SHORT_TITLES: Record<string, string> = {
  asset: "Asset & owner",
  data: "Data & privacy",
  model: "Model",
  architecture: "Architecture",
  controls: "Controls",
  governance: "Governance",
};

/** Friendly display heading per step. */
const STEP_HEADINGS: Record<string, string> = {
  asset: "Tell us about your AI asset",
  data: "What data does it handle?",
  model: "Which models does it rely on?",
  architecture: "How is it built and exposed?",
  controls: "Which safeguards are in place?",
  governance: "How will it be used?",
};
const SKILL_HEADING = "Tell us about your agent skill";
const SKILL_INTRO = "Who owns this skill and what does it do? This is the only questionnaire step: the review itself comes from the skill's files.";

const UPLOAD_COPY: Record<Kind, { heading: string; intro: string }> = {
  app: {
    heading: "Last step: share your code",
    intro: "Upload an archive or link a public Git repository. We check the code, its dependencies and any model files, and you get a clear report with what to fix, usually within a minute.",
  },
  skill: {
    heading: "Last step: add your skill",
    intro: "Upload the skill folder as a .zip, or link a public Git repository that contains a SKILL.md. We review its structure, quality and security and tell you what to improve.",
  },
};

const KIND_OPTIONS: { value: Kind; title: string; text: string; meta: string[] }[] = [
  {
    value: "app",
    title: "AI application or model",
    text: "LLM apps, RAG assistants, agents, ML models and SDKs. Full intake covering data, model, architecture, controls and governance.",
    meta: ["6 sections", "About 10 minutes"],
  },
  {
    value: "skill",
    title: "Agent skill",
    text: "A SKILL.md folder that teaches an AI agent a task. Quick intake: we review the structure, quality and security of the skill and give you feedback.",
    meta: ["1 section", "About 2 minutes"],
  },
];

const FORMAT_CHIPS = [".zip", ".py", ".ipynb", ".ts", ".js", ".tf"];

/** Archive formats the scanner cannot unpack: without this check they would be scanned as one opaque file and pass "clean". */
const OTHER_ARCHIVES = new Set([".tar", ".gz", ".tgz", ".bz2", ".xz", ".zst", ".7z", ".rar"]);
/** Documents, media and executables that contain no source code to scan. */
const NOT_CODE = new Set([
  ".exe", ".dll", ".msi", ".dmg", ".iso", ".apk",
  ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3", ".mp4", ".mov",
]);

function extensionOf(name: string): string {
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(dot).toLowerCase() : "";
}

/** Explains why a file cannot be scanned for this kind of submission, or returns null when it is fine. */
function unsupportedFileReason(f: File, kind: Kind): string | null {
  const ext = extensionOf(f.name);
  if (OTHER_ARCHIVES.has(ext)) return `${ext} archives cannot be scanned. Compress the folder as a .zip file and upload that instead.`;
  if (NOT_CODE.has(ext)) return "This file type contains no source code to scan. Upload a .zip of your project, or a single source file.";
  if (kind === "skill" && ext !== ".zip" && ext !== ".md") return "Upload the skill folder as a .zip file (or only its SKILL.md), so the review can see all of its files.";
  return null;
}

const AFTER_SUBMIT_REST = [
  {
    title: "Gate decision",
    text: "Approved, needs review or blocked, with the exact reasons and how to fix them.",
    time: "Instant",
  },
  {
    title: "Reviewer sign-off",
    text: "A security reviewer checks the report and approves or asks for changes.",
    time: "1–2 working days",
  },
  {
    title: "In the catalogue",
    text: "Your asset is published in the Azure AI catalogue with its report and SBOM.",
    time: "Same day",
  },
];
const AFTER_SUBMIT_FIRST: Record<Kind, { title: string; text: string; time: string }> = {
  app: {
    title: "Automated scan",
    text: "Scanners check secrets, dependencies and licences, code, AI risks, model files, infrastructure and whether the code matches your answers.",
    time: "Under a minute",
  },
  skill: {
    title: "Skill review",
    text: "We check the structure, quality and security of your SKILL.md and its scripts, plus secrets and dependencies.",
    time: "Under a minute",
  },
};

interface ScanStep {
  label: string;
  /** Indicative time spent on this simulated step before moving on; the last step waits for the server. */
  ms: number;
}

function scanSteps(mode: SourceMode, kind: Kind): ScanStep[] {
  const steps: ScanStep[] = [
    { label: mode === "git" ? "Downloading repository" : "Uploading", ms: mode === "git" ? 2500 : 0 },
    { label: mode === "git" ? "Extracting snapshot" : "Extracting archive", ms: 1200 },
    { label: "Secret detection", ms: 1600 },
    { label: "Dependencies & licences (OSV.dev, deps.dev)", ms: 5200 },
    { label: "Static analysis", ms: 3000 },
    { label: "AI / LLM rules", ms: 2400 },
    { label: "Model artefacts", ms: 1800 },
    { label: "Configuration & IaC", ms: 1800 },
  ];
  steps.push(kind === "skill" ? { label: "Agent skill review", ms: 1800 } : { label: "Answers vs. code", ms: 1500 });
  steps.push({ label: "Evaluating gate", ms: 0 });
  return steps;
}

/** Large secondary button that pairs with btn.hero on single-task screens. */
const bigSecondary =
  "inline-flex h-12 items-center justify-center gap-2 rounded-xl border border-line-strong bg-white px-5 text-[15px] font-semibold text-ink-2 shadow-xs transition-colors hover:bg-surface-2";

/* ------------------------------------------------------------------ API helpers */

type UploadInfo =
  | { mode: "storage"; supabaseUrl: string; publishableKey: string; bucket: string; path: string; token: string }
  | { mode: "inline"; maxBytes: number };

/** Idempotency-Key for POST /api/submissions (16-100 characters of [A-Za-z0-9_-]). */
function newIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") return crypto.randomUUID();
  return `k${Date.now().toString(36)}${Math.random().toString(36).slice(2)}${Math.random().toString(36).slice(2)}`;
}

class ApiError extends Error {
  fields?: Record<string, string>;
  /** HTTP status of the failed request (0 when the error was detected in the browser). */
  status: number;
  constructor(message: string, fields?: Record<string, string>, status = 0) {
    super(message);
    this.name = "ApiError";
    this.fields = fields;
    this.status = status;
  }
}

async function readBody(res: Response): Promise<Record<string, unknown>> {
  try {
    const v: unknown = await res.json();
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function parseFields(v: unknown): Record<string, string> | undefined {
  if (!v || typeof v !== "object" || Array.isArray(v)) return undefined;
  const out: Record<string, string> = {};
  for (const [k, msg] of Object.entries(v as Record<string, unknown>)) if (typeof msg === "string") out[k] = msg;
  return Object.keys(out).length ? out : undefined;
}

function errorMessage(data: Record<string, unknown>, status: number, fallback: string): string {
  if (typeof data.error === "string" && data.error) return data.error;
  if (status === 504) return "The scan took too long and timed out. Try again, or submit a smaller archive (leave out data files, model weights and vendored libraries).";
  if (status === 413) return "The file is too large for this environment.";
  if (status >= 500) return `${fallback}: the server had a temporary problem (HTTP ${status}). Your answers are kept; please try again.`;
  return `${fallback} (HTTP ${status}).`;
}

async function requestUploadTarget(file: File): Promise<UploadInfo> {
  const res = await fetch("/api/uploads", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ fileName: file.name, size: file.size }),
  });
  const d = await readBody(res);
  if (!res.ok) throw new ApiError(errorMessage(d, res.status, "The upload could not be prepared"), undefined, res.status);
  if (d.mode === "inline" && typeof d.maxBytes === "number") return { mode: "inline", maxBytes: d.maxBytes };
  if (
    d.mode === "storage" &&
    typeof d.supabaseUrl === "string" &&
    typeof d.publishableKey === "string" &&
    typeof d.bucket === "string" &&
    typeof d.path === "string" &&
    typeof d.token === "string"
  ) {
    return { mode: "storage", supabaseUrl: d.supabaseUrl, publishableKey: d.publishableKey, bucket: d.bucket, path: d.path, token: d.token };
  }
  throw new ApiError("Unexpected response from the upload service.");
}

/* ------------------------------------------------------------------ Git helpers */

const GIT_SEGMENT = /^[A-Za-z0-9._-]{1,100}$/;
const GIT_REF = /^[A-Za-z0-9._\/-]{1,200}$/;
const GIT_EXAMPLE = "for example https://github.com/owner/repository or https://gitlab.com/group/project";

interface RepoInput {
  /**
   * Normalised repository URL (or the trimmed input when it cannot be parsed). Links to a branch, tag, commit or file
   * (/tree/, /blob/, /commit/, /releases/tag/) are kept whole when no ref was typed: the server works out which part is the ref.
   */
  url: string;
  /** Ref from the input field. */
  ref: string;
  urlError: string | null;
  refError: string | null;
}

/** Same normalisation as the server: "github.com/o/r" and "git@github.com:o/r.git" become https links. */
function normaliseRepoInput(raw: string): string {
  const ssh = /^git@(github\.com|gitlab\.com):(.+)$/i.exec(raw);
  if (ssh) return `https://${ssh[1]}/${ssh[2]}`;
  if (/^(www\.)?(github\.com|gitlab\.com)\//i.test(raw)) return `https://${raw}`;
  return raw;
}

/** Client-side mirror of the server's parser: public github.com / gitlab.com over https only. */
function parseRepoInput(rawUrl: string, rawRef: string): RepoInput {
  const input = rawUrl.trim();
  const ref = rawRef.trim();
  const fail = (urlError: string): RepoInput => ({ url: input, ref, urlError, refError: null });
  if (!input) return fail("Enter the link to a public GitHub or GitLab repository.");
  let u: URL;
  try {
    u = new URL(normaliseRepoInput(input));
  } catch {
    return fail(`Enter a complete link, ${GIT_EXAMPLE}.`);
  }
  if (u.protocol !== "https:" || u.username || u.password || u.port) return fail("Use an https link to github.com or gitlab.com.");
  const host = u.hostname.toLowerCase().replace(/^www\./, "");
  const parts = u.pathname.split("/").filter(Boolean);
  let url: string;
  if (host === "github.com") {
    if (parts.length < 2) return fail(`Use the repository's own link, ${GIT_EXAMPLE}.`);
    const owner = parts[0];
    const repo = parts[1].replace(/\.git$/i, "");
    if (!GIT_SEGMENT.test(owner) || !GIT_SEGMENT.test(repo)) return fail("The repository link contains unsupported characters.");
    url = `https://github.com/${owner}/${repo}`;
    // /tree/feature/x/src can be branch "feature/x" with folder "src": leave splitting it to the server.
    if (!ref && parts.length > 2) url = `https://github.com/${parts.join("/")}`;
  } else if (host === "gitlab.com") {
    const dash = parts.indexOf("-");
    const segs = (dash >= 0 ? parts.slice(0, dash) : parts).map((s, i, all) => (i === all.length - 1 ? s.replace(/\.git$/i, "") : s));
    if (segs.length < 2 || !segs.every((s) => GIT_SEGMENT.test(s))) return fail(`Use the project's own link, ${GIT_EXAMPLE}.`);
    url = `https://gitlab.com/${segs.join("/")}`;
    if (!ref && dash >= 0 && parts.length > dash + 1) url = `https://gitlab.com/${parts.join("/")}`;
  } else {
    return fail("Only public repositories on github.com or gitlab.com are supported.");
  }
  const refError = ref && (!GIT_REF.test(ref) || ref.includes("..")) ? "Use a branch, tag or commit hash without spaces or special characters." : null;
  return { url, ref, urlError: null, refError };
}

/* ------------------------------------------------------------------ answer helpers */

const hasValue = (v: string | string[] | undefined) => (Array.isArray(v) ? v.length > 0 : typeof v === "string" && v.trim() !== "");

/** True when the user typed or picked anything besides the asset type chosen on the first screen. */
const hasOwnAnswers = (a: Answers) => Object.keys(a).some((k) => k !== "asset_type" && hasValue(a[k]));

/** Only answers of visible questions are submitted. */
function visibleAnswers(a: Answers): Answers {
  const out: Answers = {};
  for (const q of ALL_QUESTIONS) {
    if (!isVisible(q, a)) continue;
    const v = a[q.id];
    if (Array.isArray(v)) {
      if (v.length) out[q.id] = [...v];
    } else if (typeof v === "string" && v.trim() !== "") {
      out[q.id] = v.trim();
    }
  }
  return out;
}

/** Restores only well-formed values for known questions from a stored draft. */
function sanitizeDraft(raw: unknown): Answers {
  const out: Answers = {};
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return out;
  const r = raw as Record<string, unknown>;
  for (const q of ALL_QUESTIONS) {
    const v = r[q.id];
    if (typeof v === "string") out[q.id] = v;
    else if (Array.isArray(v)) out[q.id] = v.filter((x): x is string => typeof x === "string");
  }
  return out;
}

function cloneAnswers(a: Answers): Answers {
  const out: Answers = {};
  for (const [k, v] of Object.entries(a)) out[k] = Array.isArray(v) ? [...v] : v;
  return out;
}

/* ------------------------------------------------------------------ new version of an earlier submission */

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

interface PreviousRef {
  id: string;
  name: string;
  version: string | null;
  submittedAt: string;
  decision: Decision | null;
  score: number | null;
}

/** Validates a previous-version reference from the API or a stored draft. */
function parsePreviousRef(v: unknown): PreviousRef | null {
  if (!v || typeof v !== "object" || Array.isArray(v)) return null;
  const r = v as Record<string, unknown>;
  if (typeof r.id !== "string" || !UUID_RE.test(r.id) || typeof r.name !== "string" || typeof r.submittedAt !== "string") return null;
  return {
    id: r.id,
    name: r.name.slice(0, 200),
    version: typeof r.version === "string" && r.version ? r.version.slice(0, 50) : null,
    submittedAt: r.submittedAt,
    decision: r.decision === "approved" || r.decision === "conditional" || r.decision === "blocked" ? r.decision : null,
    score: typeof r.score === "number" ? r.score : null,
  };
}

/** The asset_type question without the "skill" option (skills have their own path). */
function withoutSkillOption(q: Question): Question {
  return { ...q, options: q.options?.filter((o) => o.value !== "skill") };
}

function sectionTitle(s: Section, kind: Kind): string {
  return kind === "skill" && s.id === "asset" ? "Skill & ownership" : s.title;
}

type StepState = "complete" | "attention" | "started" | "todo";

/* ------------------------------------------------------------------ component */

type Phase = "idle" | "uploading" | "scanning" | "redirecting";
type FocusTarget = { kind: "heading" } | { kind: "field"; id: string } | { kind: "element"; id: string } | { kind: "input"; id: string };
type Probe = { status: "idle" } | { status: "checking" } | { status: "ok"; info: UploadInfo } | { status: "error"; message: string };
interface Run {
  mode: SourceMode;
  kind: Kind;
  /** File name or repository link shown on the progress screen. */
  name: string;
  /** File size or ref shown next to it. */
  detail: string;
}

export default function SubmitWizard() {
  const router = useRouter();
  const [answers, setAnswers] = useState<Answers>({});
  const [step, setStep] = useState(0);
  const [chosen, setChosen] = useState(false);
  const [pick, setPick] = useState<Kind | null>(null);
  const [pickError, setPickError] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [attempted, setAttempted] = useState<Record<string, boolean>>({});
  const [hydrated, setHydrated] = useState(false);
  const [restored, setRestored] = useState(false);

  const [source, setSource] = useState<SourceMode>("file");
  const [gitUrl, setGitUrl] = useState("");
  const [gitRef, setGitRef] = useState("");
  const [gitError, setGitError] = useState<string | null>(null);
  const [gitRefError, setGitRefError] = useState<string | null>(null);

  const [file, setFile] = useState<File | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [probe, setProbe] = useState<Probe>({ status: "idle" });
  const [demoLoading, setDemoLoading] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [confirmError, setConfirmError] = useState(false);

  const [phase, setPhase] = useState<Phase>("idle");
  const [run, setRun] = useState<Run | null>(null);
  const [simStep, setSimStep] = useState(0);
  const [startedAt, setStartedAt] = useState(0);
  const [nowTick, setNowTick] = useState(0);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [focusTarget, setFocusTarget] = useState<FocusTarget | null>(null);
  /** Earlier submission this one is a new version of; the report then compares the two. */
  const [previousOf, setPreviousOf] = useState<PreviousRef | null>(null);
  const [previousError, setPreviousError] = useState<string | null>(null);

  const headingRef = useRef<HTMLHeadingElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const probeSeq = useRef(0);
  const submittedName = useRef("");
  const submitting = useRef(false);
  const idempotencyKey = useRef<string | null>(null);
  // Changed answers make it a different submission, not a retry of the previous one.
  useEffect(() => {
    idempotencyKey.current = null;
  }, [answers]);

  useEffect(() => {
    idempotencyKey.current = null;
  }, [previousOf]);

  /* draft persistence --------------------------------------------- */
  useEffect(() => {
    let cancelled = false;
    let draftPrevious: PreviousRef | null = null;
    let draftHasAnswers = false;
    try {
      const raw = window.localStorage.getItem(DRAFT_KEY);
      if (raw) {
        const d: unknown = JSON.parse(raw);
        if (d && typeof d === "object") {
          const draft = d as {
            answers?: unknown;
            step?: unknown;
            chosen?: unknown;
            source?: unknown;
            gitUrl?: unknown;
            gitRef?: unknown;
            previous?: unknown;
          };
          const restoredAnswers = sanitizeDraft(draft.answers);
          const any = Object.keys(restoredAnswers).length > 0;
          draftHasAnswers = hasOwnAnswers(restoredAnswers);
          if (any) {
            setAnswers(restoredAnswers);
            setRestored(true);
          }
          if (draft.chosen === true || any) setChosen(true);
          const maxStep = sectionsFor(restoredAnswers).length;
          if (typeof draft.step === "number" && draft.step >= 0 && draft.step <= maxStep) setStep(Math.floor(draft.step));
          if (draft.source === "file" || draft.source === "git") setSource(draft.source);
          if (typeof draft.gitUrl === "string") setGitUrl(draft.gitUrl.slice(0, 500));
          if (typeof draft.gitRef === "string") setGitRef(draft.gitRef.slice(0, 200));
          draftPrevious = parsePreviousRef(draft.previous);
          if (draftPrevious) setPreviousOf(draftPrevious);
        }
      }
    } catch {
      /* storage unavailable or corrupt draft: start empty */
    }

    // "Submit a new version" on a report links here with ?previous=<id>.
    const wanted = new URLSearchParams(window.location.search).get("previous");
    if (!wanted || !UUID_RE.test(wanted) || draftPrevious?.id === wanted) {
      setHydrated(true);
      return;
    }
    void (async () => {
      try {
        const res = await fetch(`/api/submissions/${encodeURIComponent(wanted)}`, { cache: "no-store" });
        const d = await readBody(res);
        if (cancelled) return;
        if (!res.ok) throw new ApiError(errorMessage(d, res.status, "The previous version could not be loaded"), undefined, res.status);
        const ref = parsePreviousRef({
          id: d.id,
          name: d.asset_name,
          version: d.asset_version,
          submittedAt: d.created_at,
          decision: d.decision,
          score: d.score,
        });
        if (!ref) throw new ApiError("The previous version could not be loaded.");
        if (draftHasAnswers && !window.confirm(`Replace your unsent draft with the answers of “${ref.name}” to submit a new version of it?`)) return;
        const next = sanitizeDraft(d.answers);
        const bumped = nextVersion(ref.version);
        if (bumped) next.asset_version = bumped;
        else delete next.asset_version;
        setAnswers(next);
        setPreviousOf(ref);
        setErrors({});
        setAttempted({});
        setChosen(true);
        setRestored(false);
        // The answers were complete last time, so go straight to the upload; the step bar still allows edits.
        setStep(Object.keys(validateAnswers(next)).length === 0 ? sectionsFor(next).length : 0);
        const src = d.source && typeof d.source === "object" ? (d.source as { type?: unknown; url?: unknown; ref?: unknown }) : null;
        if (src && src.type === "git" && typeof src.url === "string") {
          setSource("git");
          setGitUrl(src.url.slice(0, 500));
          setGitRef(typeof src.ref === "string" ? src.ref.slice(0, 200) : "");
        } else {
          setSource("file");
        }
      } catch (e) {
        if (!cancelled) setPreviousError(e instanceof ApiError ? e.message : "The previous version could not be loaded.");
      } finally {
        if (!cancelled) setHydrated(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!hydrated) return;
    try {
      window.localStorage.setItem(DRAFT_KEY, JSON.stringify({ answers, step, chosen, source, gitUrl, gitRef, previous: previousOf }));
    } catch {
      /* ignore quota / privacy mode */
    }
  }, [answers, step, chosen, source, gitUrl, gitRef, previousOf, hydrated]);

  /* simulated scan progress ---------------------------------------- */
  useEffect(() => {
    if (phase !== "scanning" || !run) return;
    const steps = scanSteps(run.mode, run.kind);
    // File uploads already finished step 0 ("Uploading"); a Git download happens server-side, so it starts at step 0.
    let i = run.mode === "git" ? 0 : 1;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setSimStep(i);
    const next = () => {
      if (i >= steps.length - 1) return;
      timer = setTimeout(() => {
        i += 1;
        setSimStep(i);
        next();
      }, steps[i]?.ms ?? 2000);
    };
    next();
    return () => {
      if (timer) clearTimeout(timer);
    };
  }, [phase, run]);

  useEffect(() => {
    if (phase === "idle") return;
    setNowTick(Date.now());
    const t = setInterval(() => setNowTick(Date.now()), 1000);
    const warn = (e: BeforeUnloadEvent) => {
      e.preventDefault();
    };
    window.addEventListener("beforeunload", warn);
    return () => {
      clearInterval(t);
      window.removeEventListener("beforeunload", warn);
    };
  }, [phase]);

  /* focus management: runs after the target step has been committed to the DOM */
  useEffect(() => {
    if (!focusTarget) return;
    if (focusTarget.kind === "heading") {
      const h = headingRef.current;
      if (h) {
        const top = h.getBoundingClientRect().top + window.scrollY - 96;
        if (window.scrollY > top) window.scrollTo({ top: Math.max(0, top), behavior: "smooth" });
        h.focus({ preventScroll: true });
      }
    } else if (focusTarget.kind === "element") {
      document.getElementById(focusTarget.id)?.scrollIntoView({ behavior: "smooth", block: "center" });
    } else if (focusTarget.kind === "input") {
      const el = document.getElementById(focusTarget.id);
      if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "center" });
        el.focus({ preventScroll: true });
      }
    } else {
      const el = document.getElementById(`field-${focusTarget.id}`);
      if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "center" });
        const input = el.querySelector<HTMLElement>("input:checked, input, textarea, button");
        input?.focus({ preventScroll: true });
      }
    }
    setFocusTarget(null);
  }, [focusTarget]);

  /* derived state ---------------------------------------------------- */
  const kind: Kind = isSkill(answers) ? "skill" : "app";
  const sections = useMemo(() => sectionsFor(answers), [answers]);
  const uploadStep = sections.length;
  const currentStep = Math.min(step, uploadStep);
  const stepTitles = useMemo(() => [...sections.map((s) => sectionTitle(s, kind)), "Upload & scan"], [sections, kind]);
  const stepShort = useMemo(
    () => [...sections.map((s) => (kind === "skill" && s.id === "asset" ? "Skill & owner" : (SHORT_TITLES[s.id] ?? s.title))), "Upload & scan"],
    [sections, kind],
  );

  const sectionErrors = useMemo(() => sections.map((s) => validateAnswers(answers, s.id)), [sections, answers]);
  const stepStates: StepState[] = useMemo(
    () =>
      sections.map((s, i): StepState => {
        const valid = Object.keys(sectionErrors[i] ?? {}).length === 0;
        if (valid) return "complete";
        if (attempted[s.id]) return "attention";
        return s.questions.some((q) => q.id !== "asset_type" && hasValue(answers[q.id])) ? "started" : "todo";
      }),
    [sections, sectionErrors, attempted, answers],
  );
  const incomplete = sections.filter((_, i) => stepStates[i] !== "complete");
  const allValid = incomplete.length === 0;

  /* navigation ------------------------------------------------------- */
  function goTo(i: number) {
    setStep(i);
    setRestored(false);
    setFocusTarget({ kind: "heading" });
  }

  function focusFirstError(section: Section, errs: Record<string, string>) {
    const first = section.questions.find((q) => errs[q.id]);
    if (first) setFocusTarget({ kind: "field", id: first.id });
  }

  function continueFrom(i: number) {
    const section = sections[i];
    if (!section) return;
    const errs = validateAnswers(answers, section.id);
    if (Object.keys(errs).length) {
      setErrors((prev) => ({ ...prev, ...errs }));
      setAttempted((prev) => ({ ...prev, [section.id]: true }));
      focusFirstError(section, errs);
      return;
    }
    goTo(i + 1);
  }

  /** Shows validation errors (client or server) and jumps to the first affected section. */
  function showErrors(errs: Record<string, string>) {
    const idx = sections.findIndex((s) => s.questions.some((q) => errs[q.id]));
    if (idx < 0) return false;
    setErrors((prev) => ({ ...prev, ...errs }));
    setAttempted((prev) => {
      const next = { ...prev };
      for (const s of sections) if (s.questions.some((q) => errs[q.id])) next[s.id] = true;
      return next;
    });
    setStep(idx);
    focusFirstError(sections[idx], errs);
    return true;
  }

  /* kind ------------------------------------------------------------- */
  function openChooser() {
    setPick(kind);
    setPickError(false);
    setChosen(false);
    setFocusTarget({ kind: "heading" });
  }

  function chooseKind(k: Kind) {
    if (k !== kind) {
      setErrors({});
      setAttempted({});
      setStep(0);
    }
    setAnswers((prev) => {
      const next = { ...prev };
      if (k === "skill") next.asset_type = "skill";
      else if (next.asset_type === "skill") delete next.asset_type;
      return next;
    });
    setChosen(true);
    setPickError(false);
    setFocusTarget({ kind: "heading" });
  }

  /* answers ---------------------------------------------------------- */
  function setAnswer(id: string, value: string | string[]) {
    setAnswers((prev) => ({ ...prev, [id]: value }));
    setErrors((prev) => {
      if (!(id in prev)) return prev;
      const next = { ...prev };
      delete next[id];
      return next;
    });
  }

  function fillExample() {
    const label = DEMO[kind].label;
    if (hasOwnAnswers(answers) && !window.confirm(`Replace the current answers with the example answers for the ${label}?`)) return;
    setAnswers(cloneAnswers(kind === "skill" ? DEMO_SKILL_ANSWERS : DEMO_ANSWERS));
    setErrors({});
    setAttempted({});
  }

  function clearForm() {
    if (!window.confirm("Clear all answers and the selected file or repository? This cannot be undone.")) return;
    setAnswers({});
    setErrors({});
    setAttempted({});
    setFile(null);
    setFileError(null);
    setProbe({ status: "idle" });
    setSource("file");
    setGitUrl("");
    setGitRef("");
    setGitError(null);
    setGitRefError(null);
    setConfirmed(false);
    setSubmitError(null);
    setRestored(false);
    setChosen(false);
    setPick(null);
    setPickError(false);
    setPreviousOf(null);
    setPreviousError(null);
    try {
      window.localStorage.removeItem(DRAFT_KEY);
    } catch {
      /* ignore */
    }
    goTo(0);
  }

  /* source ----------------------------------------------------------- */
  function changeSource(m: SourceMode) {
    setSource(m);
    setSubmitError(null);
  }

  function onGitUrlChange(v: string) {
    setGitUrl(v);
    idempotencyKey.current = null;
    if (gitError) setGitError(null);
  }

  function onGitRefChange(v: string) {
    setGitRef(v);
    idempotencyKey.current = null;
    if (gitRefError) setGitRefError(null);
  }

  /** On blur: normalise the link (e.g. add https://) and show errors early. */
  function onGitUrlBlur() {
    if (!gitUrl.trim()) return;
    const r = parseRepoInput(gitUrl, gitRef);
    if (!r.urlError && r.url !== gitUrl) setGitUrl(r.url);
    setGitError(r.urlError);
  }

  /* file ------------------------------------------------------------- */
  async function probeUpload(f: File) {
    const seq = ++probeSeq.current;
    setProbe({ status: "checking" });
    try {
      const info = await requestUploadTarget(f);
      if (seq === probeSeq.current) setProbe({ status: "ok", info });
    } catch (e) {
      if (seq !== probeSeq.current) return;
      // Only definitive rejections (4xx, e.g. file too large) block the submit; network hiccups and server errors are retried on submit.
      const definitive = e instanceof ApiError && e.status >= 400 && e.status < 500;
      setProbe(definitive ? { status: "error", message: e.message } : { status: "idle" });
    }
  }

  function selectFile(f: File | null) {
    probeSeq.current++;
    idempotencyKey.current = null;
    setFile(f);
    setFileError(null);
    setProbe({ status: "idle" });
    setSubmitError(null);
    if (!f) return;
    if (f.size === 0) {
      setFileError("The selected file is empty.");
      return;
    }
    if (f.size > MAX_UPLOAD_BYTES) {
      setFileError(`The file is ${formatBytes(f.size)}. The maximum upload size is ${formatBytes(MAX_UPLOAD_BYTES)}.`);
      return;
    }
    const unsupported = unsupportedFileReason(f, kind);
    if (unsupported) {
      setFileError(unsupported);
      return;
    }
    void probeUpload(f);
  }

  async function loadDemo() {
    const demo = DEMO[kind];
    setSource("file");
    setDemoLoading(true);
    setFileError(null);
    try {
      const res = await fetch(demo.url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      selectFile(new File([blob], demo.fileName, { type: "application/zip" }));
    } catch {
      setFileError(`The ${demo.label} could not be downloaded. Please try again.`);
    } finally {
      setDemoLoading(false);
    }
  }

  function onDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files?.[0];
    if (f) selectFile(f);
  }

  /* submit ----------------------------------------------------------- */
  async function submit() {
    // A second click (or Enter) while a submission is underway must not start a second scan.
    if (submitting.current) return;
    setSubmitError(null);
    const allErrors = validateAnswers(answers);
    if (Object.keys(allErrors).length) {
      showErrors(allErrors);
      return;
    }

    let target: { mode: "file"; file: File } | { mode: "git"; url: string; ref: string };
    if (source === "file") {
      if (!file) {
        setFileError("Select a file to scan.");
        setFocusTarget({ kind: "input", id: "file-input" });
        return;
      }
      // The kind may have changed after the file was picked (e.g. a .py file, then switching to "Agent skill").
      const unsupported = unsupportedFileReason(file, kind);
      if (unsupported) {
        setFileError(unsupported);
        setFocusTarget({ kind: "input", id: "file-input" });
        return;
      }
      if (fileError || probe.status === "error") {
        setFocusTarget({ kind: "input", id: "file-input" });
        return;
      }
      target = { mode: "file", file };
    } else {
      const r = parseRepoInput(gitUrl, gitRef);
      if (!r.urlError && r.url !== gitUrl) setGitUrl(r.url);
      setGitError(r.urlError);
      setGitRefError(r.refError);
      if (r.urlError || r.refError) {
        setFocusTarget({ kind: "input", id: r.urlError ? "git-url" : "git-ref" });
        return;
      }
      target = { mode: "git", url: r.url, ref: r.ref };
    }

    if (!confirmed) {
      setConfirmError(true);
      setFocusTarget({ kind: "input", id: "confirm-check" });
      return;
    }

    submitting.current = true;
    // Reused when the user retries after a network error or time-out, so the server returns the submission it
    // may already have created instead of scanning twice. Reset when the file, link or answers change.
    const key = idempotencyKey.current ?? newIdempotencyKey();
    idempotencyKey.current = key;
    const jsonHeaders = { "content-type": "application/json", "idempotency-key": key };
    const clean = visibleAnswers(answers);
    const link = previousOf ? { previousId: previousOf.id } : {};
    submittedName.current = String(clean.asset_name ?? "asset");
    setRun(
      target.mode === "file"
        ? { mode: "file", kind, name: target.file.name, detail: formatBytes(target.file.size) }
        : { mode: "git", kind, name: target.url.replace(/^https:\/\//, ""), detail: target.ref || "default branch" },
    );
    setStartedAt(Date.now());
    setSimStep(0);
    window.scrollTo({ top: 0, behavior: "smooth" });

    try {
      let res: Response;
      if (target.mode === "git") {
        setPhase("scanning");
        res = await fetch("/api/submissions", {
          method: "POST",
          headers: jsonHeaders,
          body: JSON.stringify({ answers: clean, ...link, source: { type: "git", url: target.url, ...(target.ref ? { ref: target.ref } : {}) } }),
        });
      } else {
        const f = target.file;
        setPhase("uploading");
        const upload = await requestUploadTarget(f);
        if (upload.mode === "storage") {
          const { createClient } = await import("@supabase/supabase-js");
          const supabase = createClient(upload.supabaseUrl, upload.publishableKey, {
            auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
          });
          const { error } = await supabase.storage
            .from(upload.bucket)
            .uploadToSignedUrl(upload.path, upload.token, f, { contentType: f.type || "application/octet-stream" });
          if (error) throw new ApiError(`The upload failed: ${error.message}`);
          setPhase("scanning");
          res = await fetch("/api/submissions", {
            method: "POST",
            headers: jsonHeaders,
            body: JSON.stringify({ answers: clean, ...link, upload: { path: upload.path, fileName: f.name, size: f.size } }),
          });
        } else {
          if (f.size > upload.maxBytes) {
            throw new ApiError(`This environment accepts files up to ${formatBytes(upload.maxBytes)}. Upload a smaller archive.`);
          }
          const form = new FormData();
          form.append("answers", JSON.stringify(clean));
          if (previousOf) form.append("previousId", previousOf.id);
          form.append("file", f, f.name);
          setPhase("scanning");
          res = await fetch("/api/submissions", { method: "POST", headers: { "idempotency-key": key }, body: form });
        }
      }

      const data = await readBody(res);
      if (!res.ok) throw new ApiError(errorMessage(data, res.status, "The submission failed"), parseFields(data.fields), res.status);
      const id = typeof data.id === "string" ? data.id : "";
      if (!id) throw new ApiError("The server returned an unexpected response.");

      setPhase("redirecting");
      // A scan that could not complete still creates a submission (decision null). Keep the draft then, so the
      // "submit again" link on the report brings the answers back instead of an empty form.
      if (typeof data.decision === "string") {
        try {
          window.localStorage.removeItem(DRAFT_KEY);
        } catch {
          /* ignore */
        }
      }
      router.push(`/reports/${encodeURIComponent(id)}`);
    } catch (e) {
      submitting.current = false;
      // A definitive rejection (4xx) created nothing on the server; the next attempt is a new submission.
      if (e instanceof ApiError && e.status >= 400 && e.status < 500) idempotencyKey.current = null;
      setPhase("idle");
      const message = e instanceof ApiError ? e.message : "The server could not be reached. Check your connection and try again.";
      setSubmitError(message);
      const fields = e instanceof ApiError ? e.fields : undefined;
      // Repository problems are shown next to the inputs as well.
      if (fields && (fields.gitUrl || fields.gitRef)) {
        if (fields.gitUrl) setGitError(message);
        if (fields.gitRef) setGitRefError(message);
        setFocusTarget({ kind: "input", id: fields.gitUrl ? "git-url" : "git-ref" });
        return;
      }
      const jumped = fields ? showErrors(fields) : false;
      if (!jumped) setFocusTarget({ kind: "element", id: "submit-error" });
    }
  }

  /* render ------------------------------------------------------------ */
  if (phase !== "idle") {
    return (
      <ScanProgress
        assetName={submittedName.current}
        run={run}
        phase={phase}
        simStep={simStep}
        elapsedMs={Math.max(0, nowTick - startedAt)}
      />
    );
  }

  // Avoid flashing the first screen before a stored draft has been read.
  if (!hydrated) return <div className="min-h-[60vh]" aria-busy="true" />;

  if (!chosen) {
    return (
      <KindChooser
        headingRef={headingRef}
        pick={pick}
        error={pickError}
        canClear={hasOwnAnswers(answers)}
        onPick={(k) => {
          setPick(k);
          setPickError(false);
        }}
        onContinue={() => {
          if (!pick) {
            setPickError(true);
            return;
          }
          chooseKind(pick);
        }}
        onClear={clearForm}
      />
    );
  }

  const section = currentStep < uploadStep ? sections[currentStep] : null;
  const heading = section ? (kind === "skill" && section.id === "asset" ? SKILL_HEADING : (STEP_HEADINGS[section.id] ?? section.title)) : UPLOAD_COPY[kind].heading;
  const intro = section ? (kind === "skill" && section.id === "asset" ? SKILL_INTRO : section.intro) : UPLOAD_COPY[kind].intro;
  // Only disabled while the file is being checked. Otherwise a click explains what is missing (no file, invalid link, …)
  // instead of leaving a silently disabled button.
  const submitDisabled = source === "file" && !!file && probe.status === "checking";

  return (
    <div className="mx-auto max-w-[1136px]">
      <div className="mx-auto max-w-[860px]">
        {/* Utility row */}
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
          <div className="flex min-w-0 flex-wrap items-center gap-x-2.5 gap-y-1">
            <p className="text-sm font-semibold text-ink-2">{previousOf ? "New version" : "New submission"}</p>
            <span className="inline-flex h-6 items-center gap-1.5 rounded-full bg-white px-2.5 text-xs font-medium text-ink-2 ring-1 ring-inset ring-line">
              {kind === "skill" ? <SkillIcon size={13} className="text-brand" /> : <AppIcon size={13} className="text-brand" />}
              {kind === "skill" ? "Agent skill" : "AI application or model"}
            </span>
            <button type="button" onClick={openChooser} className="text-[13px] font-semibold text-brand hover:text-brand-strong hover:underline">
              Change
            </button>
          </div>
          <div className="-mr-3 flex items-center gap-1">
            <button type="button" onClick={fillExample} className={btn.ghost}>
              Fill with example answers
            </button>
            <span aria-hidden="true" className="h-5 w-px bg-line" />
            <button type="button" onClick={clearForm} className={btn.ghost}>
              Clear form
            </button>
          </div>
        </div>

        {previousOf ? (
          <PreviousVersionBanner previous={previousOf} newVersion={typeof answers.asset_version === "string" ? answers.asset_version : ""} onUnlink={() => setPreviousOf(null)} />
        ) : previousError ? (
          <p className="mt-4 flex items-start gap-2 rounded-xl border border-[#FEDF89] bg-warn-soft px-4 py-3 text-[13px] leading-5 text-ink-2" role="status">
            <AlertIcon size={16} className="mt-0.5 shrink-0 text-warn" />
            <span>{previousError} This submission will be scanned on its own, without a comparison.</span>
          </p>
        ) : null}

        <StepProgress step={currentStep} titles={stepTitles} short={stepShort} states={stepStates} onSelect={goTo} />

        {/* Step heading */}
        <div className="mt-10 text-center sm:mt-12">
          {section ? (
            <span
              className="inline-flex h-7 items-center rounded-full bg-white px-3 text-xs font-medium text-muted ring-1 ring-inset ring-line"
              title="Reference framework"
            >
              <span className="sr-only">Reference framework: </span>
              {section.framework}
            </span>
          ) : (
            <span className="inline-flex h-7 items-center gap-1.5 rounded-full bg-brand-soft px-3 text-xs font-medium text-brand-strong">
              <ShieldIcon size={14} />
              Your code is analysed, never executed
            </span>
          )}
          <h1
            id="step-title"
            ref={headingRef}
            tabIndex={-1}
            className="mt-4 text-[30px] font-bold leading-[1.2] tracking-[-0.025em] text-ink focus:outline-none sm:text-[38px]"
          >
            {heading}
          </h1>
          <p className="mx-auto mt-3 max-w-[620px] text-base leading-7 text-muted sm:text-[17px]">{intro}</p>
        </div>

        {restored && (
          <p
            className="mx-auto mt-6 flex w-fit max-w-full items-center gap-2 rounded-xl border border-line bg-white px-3.5 py-1.5 text-[13px] text-muted shadow-xs"
            role="status"
          >
            <span className="size-1.5 shrink-0 rounded-full bg-brand" aria-hidden="true" />
            <span>
              Your draft was restored from this browser.
              {!section && source === "file" && !file ? " Files are not saved, so select your file again." : ""}
            </span>
          </p>
        )}

        {section ? (
          <>
            <Card labelledBy="step-title" className="mt-8">
              <div className="divide-y divide-line">
                {section.questions
                  .filter((q) => isVisible(q, answers))
                  .map((q) =>
                    q.id === "asset_type" && kind === "skill" ? (
                      <FixedField key={q.id} id={q.id} label={q.label} value="Agent skill" onChange={openChooser} />
                    ) : (
                      <QuestionField
                        key={q.id}
                        q={q.id === "asset_type" ? withoutSkillOption(q) : q}
                        value={answers[q.id]}
                        error={errors[q.id]}
                        onChange={(v) => setAnswer(q.id, v)}
                      />
                    ),
                  )}
              </div>
            </Card>

            <FooterBar>
              {currentStep > 0 ? (
                <button type="button" onClick={() => goTo(currentStep - 1)} className={bigSecondary}>
                  <ArrowLeftIcon size={18} />
                  Back
                </button>
              ) : (
                <button type="button" onClick={openChooser} className={bigSecondary}>
                  <ArrowLeftIcon size={18} />
                  Back
                </button>
              )}
              <div className="flex items-center gap-4">
                <span className="hidden text-[13px] text-subtle sm:inline">Draft saved in this browser</span>
                <button type="button" onClick={() => continueFrom(currentStep)} className={`${btn.hero} min-w-[148px]`}>
                  Continue
                  <ArrowRightIcon size={18} />
                </button>
              </div>
            </FooterBar>
          </>
        ) : (
          <>
            <UploadStep
              kind={kind}
              source={source}
              onSource={changeSource}
              gitUrl={gitUrl}
              gitRef={gitRef}
              gitError={gitError}
              gitRefError={gitRefError}
              onGitUrl={onGitUrlChange}
              onGitRef={onGitRefChange}
              onGitUrlBlur={onGitUrlBlur}
              file={file}
              fileError={fileError}
              probe={probe}
              dragging={dragging}
              demoLoading={demoLoading}
              fileInputRef={fileInputRef}
              answers={answers}
              sections={sections}
              stepStates={stepStates}
              incomplete={incomplete}
              confirmed={confirmed}
              confirmError={confirmError}
              onConfirm={(v) => {
                setConfirmed(v);
                if (v) setConfirmError(false);
              }}
              onSelectFile={selectFile}
              onDemo={loadDemo}
              onDragState={setDragging}
              onDrop={onDrop}
              onEdit={goTo}
              onFillExample={fillExample}
            />

            {submitError && (
              <div
                id="submit-error"
                className="mt-6 flex scroll-mt-24 flex-wrap items-start gap-3 rounded-xl border border-[#FDA29B] bg-[#FFFBFA] px-4 py-4 sm:flex-nowrap sm:px-5"
                role="alert"
              >
                <AlertIcon size={20} className="mt-0.5 shrink-0 text-sev-critical" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-sev-critical">Submission failed</p>
                  <p className="mt-0.5 text-sm text-ink-2">{submitError}</p>
                </div>
                <button type="button" onClick={submit} className={`${btn.secondary} shrink-0`}>
                  Retry
                </button>
              </div>
            )}

            <FooterBar note={allValid ? undefined : "Submitting takes you to the first incomplete section."}>
              <button type="button" onClick={() => goTo(currentStep - 1)} className={bigSecondary}>
                <ArrowLeftIcon size={18} />
                Back
              </button>
              <button type="button" onClick={submit} disabled={submitDisabled} className={btn.hero}>
                Submit and start scan
              </button>
            </FooterBar>
          </>
        )}
      </div>

      {!section && <AfterSubmit kind={kind} />}
    </div>
  );
}

/* ------------------------------------------------------------------ new version banner */

function PreviousVersionBanner({ previous, newVersion, onUnlink }: { previous: PreviousRef; newVersion: string; onUnlink: () => void }) {
  const was = previous.version ? `v${previous.version.replace(/^v/i, "")}` : "the previous version";
  const now = newVersion.trim() ? `v${newVersion.trim().replace(/^v/i, "")}` : null;
  return (
    <div className="mt-4 flex flex-col gap-3 rounded-xl border border-brand/25 bg-brand-soft px-4 py-3.5 sm:flex-row sm:items-center sm:justify-between sm:px-5">
      <div className="min-w-0 text-[13px] leading-5 text-ink-2">
        <p className="text-sm font-semibold text-ink">
          New version of <span className="break-words">{previous.name}</span>
          {now ? <span className="font-medium text-muted"> · {was} → {now}</span> : null}
        </p>
        <p className="mt-0.5">
          Your answers from {was} (submitted {formatDate(previous.submittedAt)}
          {previous.decision ? `, ${DECISION_LABEL[previous.decision]}` : ""}
          {typeof previous.score === "number" ? `, score ${previous.score}` : ""}) are filled in. The report will show what you fixed, what is new and
          what is still open.
        </p>
      </div>
      <div className="flex shrink-0 items-center gap-1">
        <a href={`/reports/${previous.id}`} target="_blank" rel="noopener noreferrer" className={btn.ghost}>
          Previous report
        </a>
        <button type="button" onClick={onUnlink} className={btn.ghost} title="Scan this submission on its own, without comparing it">
          Don&apos;t compare
        </button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ first screen: what are you submitting? */

function KindChooser({
  headingRef,
  pick,
  error,
  canClear,
  onPick,
  onContinue,
  onClear,
}: {
  headingRef: RefObject<HTMLHeadingElement | null>;
  pick: Kind | null;
  error: boolean;
  canClear: boolean;
  onPick: (k: Kind) => void;
  onContinue: () => void;
  onClear: () => void;
}) {
  return (
    <div className="mx-auto max-w-[860px]">
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
        <p className="text-sm font-semibold text-ink-2">New submission</p>
        {canClear && (
          <button type="button" onClick={onClear} className={`${btn.ghost} -mr-3`}>
            Clear form
          </button>
        )}
      </div>

      <div className="mt-10 text-center sm:mt-12">
        <h1
          id="kind-title"
          ref={headingRef}
          tabIndex={-1}
          className="text-[30px] font-bold leading-[1.2] tracking-[-0.025em] text-ink focus:outline-none sm:text-[38px]"
        >
          What are you submitting?
        </h1>
        <p className="mx-auto mt-3 max-w-[620px] text-base leading-7 text-muted sm:text-[17px]">
          Pick the path that fits. Both end in the same scan and gate decision; you can change your choice later and keep your answers.
        </p>
      </div>

      <div
        role="radiogroup"
        aria-labelledby="kind-title"
        aria-required="true"
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? "kind-error" : undefined}
        className="mt-8 grid gap-4 sm:grid-cols-2"
      >
        {KIND_OPTIONS.map((o) => {
          const checked = pick === o.value;
          return (
            <label
              key={o.value}
              className={`relative flex cursor-pointer flex-col rounded-2xl border bg-white p-6 shadow-xs transition-colors has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-brand sm:p-7 ${
                checked ? "border-brand ring-1 ring-inset ring-brand" : `${error ? "border-sev-critical/50" : "border-line"} hover:border-line-strong hover:bg-surface-2`
              }`}
            >
              <input
                type="radio"
                name="submission-kind"
                value={o.value}
                checked={checked}
                onChange={() => onPick(o.value)}
                className="sr-only"
              />
              <span className="flex items-start justify-between gap-4">
                <span
                  aria-hidden="true"
                  className={`flex size-12 items-center justify-center rounded-xl ${checked ? "bg-brand text-white" : "bg-brand-soft text-brand"}`}
                >
                  {o.value === "skill" ? <SkillIcon size={24} /> : <AppIcon size={24} />}
                </span>
                <span
                  aria-hidden="true"
                  className={`mt-1 flex size-5 shrink-0 items-center justify-center rounded-full border-2 bg-white transition-colors ${
                    checked ? "border-brand" : "border-line-strong"
                  }`}
                >
                  {checked && <span className="size-2.5 rounded-full bg-brand" />}
                </span>
              </span>
              <span className="mt-5 font-display text-[19px] font-bold text-ink">{o.title}</span>
              <span className="mt-2 text-[15px] leading-6 text-muted">{o.text}</span>
              <span className="mt-5 flex flex-wrap gap-2 pt-1">
                {o.meta.map((m) => (
                  <span key={m} className="inline-flex h-6 items-center rounded-full bg-surface-2 px-2.5 text-xs font-medium text-ink-2 ring-1 ring-inset ring-line">
                    {m}
                  </span>
                ))}
              </span>
            </label>
          );
        })}
      </div>
      {error && (
        <p id="kind-error" className="mt-3 flex items-center gap-1.5 text-[13px] font-medium text-sev-critical" role="alert">
          <AlertIcon size={15} />
          Choose what you are submitting to continue.
        </p>
      )}
      <p className="mt-4 text-sm text-muted">Not sure? Choose AI application or model: it covers every kind of AI asset.</p>

      <FooterBar>
        <span />
        <button type="button" onClick={onContinue} className={`${btn.hero} min-w-[148px]`}>
          Continue
          <ArrowRightIcon size={18} />
        </button>
      </FooterBar>
    </div>
  );
}

/** Read-only answer (the asset type in the skill path). */
function FixedField({ id, label, value, onChange }: { id: string; label: string; value: string; onChange: () => void }) {
  return (
    <div id={`field-${id}`} className="scroll-mt-24 px-5 py-6 sm:px-8 sm:py-7">
      <p className="text-[15px] font-semibold leading-6 text-ink">{label}</p>
      <div className="mt-3 flex flex-wrap items-center gap-3">
        <span className="inline-flex h-8 items-center gap-2 rounded-full bg-brand-soft px-3 text-sm font-semibold text-brand-strong">
          <SkillIcon size={16} />
          {value}
        </span>
        <button type="button" onClick={onChange} className="text-sm font-semibold text-brand hover:text-brand-strong hover:underline">
          Change what you submit
        </button>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ progress header */

const STATE_TEXT: Record<StepState, string> = { complete: "Complete", attention: "Needs attention", started: "In progress", todo: "Not started" };

function StepProgress({
  step,
  titles,
  short,
  states,
  onSelect,
}: {
  step: number;
  titles: string[];
  short: string[];
  states: StepState[];
  onSelect: (i: number) => void;
}) {
  const total = titles.length;
  const pct = Math.round(((step + 0.5) / total) * 100);
  return (
    <div className="mt-5">
      {/* Overall progress */}
      <div className="flex items-center gap-3 sm:gap-4">
        <span className="tabular shrink-0 text-[13px] font-semibold text-brand">
          Step {step + 1} of {total}
        </span>
        <span
          role="progressbar"
          aria-label="Submission progress"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={pct}
          aria-valuetext={`Step ${step + 1} of ${total}: ${titles[step] ?? ""}`}
          className="h-1.5 min-w-0 flex-1 overflow-hidden rounded-full bg-line"
        >
          <span className="block h-full rounded-full bg-brand transition-[width] duration-500" style={{ width: `${pct}%` }} />
        </span>
        <span className="max-w-[40%] shrink-0 truncate text-[13px] text-muted">{titles[step]}</span>
      </div>

      {/* Segmented step list */}
      <nav aria-label="Submission steps" className="mt-4">
        <ol className="grid gap-1.5 sm:gap-2" style={{ gridTemplateColumns: `repeat(${total}, minmax(0, 1fr))` }}>
          {titles.map((title, i) => {
            const state: StepState | "upload" = i < states.length ? states[i] : "upload";
            const current = i === step;
            const bar =
              state === "attention"
                ? "bg-sev-critical"
                : current || state === "complete"
                  ? "bg-brand"
                  : state === "started"
                    ? "bg-brand/35"
                    : "bg-line-strong";
            const label = current
              ? "font-semibold text-brand"
              : state === "attention"
                ? "font-medium text-sev-critical"
                : state === "complete"
                  ? "font-medium text-ink-2"
                  : "font-medium text-subtle";
            return (
              <li key={title}>
                <button
                  type="button"
                  onClick={() => onSelect(i)}
                  aria-current={current ? "step" : undefined}
                  aria-label={`Step ${i + 1}: ${title}${state !== "upload" ? ` (${STATE_TEXT[state]})` : ""}`}
                  className="group flex w-full flex-col gap-2 rounded-md py-2.5 text-left sm:py-1.5"
                >
                  <span className={`h-1 w-full rounded-full transition-colors ${bar}`} />
                  <span className={`hidden text-xs leading-4 transition-colors group-hover:text-ink sm:block ${label}`}>{short[i]}</span>
                </button>
              </li>
            );
          })}
        </ol>
      </nav>
    </div>
  );
}

/** Action row under the step content; sticks to the bottom of the viewport while the step is taller than the screen. */
function FooterBar({ children, note }: { children: ReactNode; note?: string }) {
  return (
    <div className="sticky bottom-0 z-10 mt-8 border-t border-line bg-canvas/95 py-4 backdrop-blur">
      <div className="flex items-center justify-between gap-3">{children}</div>
      {note && <p className="mt-2 text-right text-[13px] text-subtle">{note}</p>}
    </div>
  );
}

/* ------------------------------------------------------------------ question rendering */

const inputBase =
  "block w-full rounded-xl border bg-white px-4 text-[15px] text-ink shadow-xs placeholder:text-faint focus:border-brand focus:outline-none focus:ring-4 focus:ring-brand/15";

function QuestionField({
  q,
  value,
  error,
  onChange,
}: {
  q: Question;
  value: string | string[] | undefined;
  error?: string;
  onChange: (v: string | string[]) => void;
}) {
  const inputId = `q-${q.id}`;
  const labelId = `${inputId}-label`;
  const helpId = q.help ? `${inputId}-help` : undefined;
  const errorId = error ? `${inputId}-error` : undefined;
  const describedBy = [helpId, errorId].filter(Boolean).join(" ") || undefined;
  const border = error ? "border-sev-critical" : "border-line-strong";
  const isChoice = q.kind === "select" || q.kind === "multi";

  const label = (
    <div className="flex items-start justify-between gap-3">
      {isChoice ? (
        <span id={labelId} className="text-[15px] font-semibold leading-6 text-ink">
          {q.label}
        </span>
      ) : (
        <label id={labelId} htmlFor={inputId} className="text-[15px] font-semibold leading-6 text-ink">
          {q.label}
        </label>
      )}
      {!q.required && (
        <span className="mt-0.5 inline-flex h-5 shrink-0 items-center rounded-full bg-surface-2 px-2 text-xs font-medium text-subtle ring-1 ring-inset ring-line">
          Optional
        </span>
      )}
    </div>
  );

  let control: ReactNode;
  if (q.kind === "text" || q.kind === "email") {
    control = (
      <input
        id={inputId}
        type={q.kind === "email" ? "email" : "text"}
        value={typeof value === "string" ? value : ""}
        onChange={(e) => onChange(e.target.value)}
        placeholder={q.placeholder}
        required={q.required}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        autoComplete={q.kind === "email" ? "email" : q.id === "owner_name" ? "name" : "off"}
        maxLength={200}
        className={`${inputBase} ${border} h-12 sm:max-w-lg`}
      />
    );
  } else if (q.kind === "textarea") {
    control = (
      <textarea
        id={inputId}
        value={typeof value === "string" ? value : ""}
        onChange={(e) => onChange(e.target.value)}
        placeholder={q.placeholder}
        required={q.required}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
        rows={4}
        maxLength={4000}
        className={`${inputBase} ${border} resize-y py-3 leading-6`}
      />
    );
  } else {
    const options = q.options ?? [];
    const selected = q.kind === "multi" ? (Array.isArray(value) ? value : []) : typeof value === "string" ? [value] : [];
    const hasNone = q.kind === "multi" && options.some((o) => o.value === "none");
    const toggle = (v: string) => {
      if (q.kind === "select") return onChange(v);
      if (selected.includes(v)) return onChange(selected.filter((x) => x !== v));
      if (hasNone && v === "none") return onChange(["none"]);
      return onChange([...selected.filter((x) => !(hasNone && x === "none")), v]);
    };
    const short = options.every((o) => o.label.length <= 28);
    const cols =
      short && options.length === 2
        ? "sm:grid-cols-2"
        : short && options.length === 3
          ? "md:grid-cols-3"
          : options.length >= 5
            ? "md:grid-cols-2"
            : "";
    control = (
      <div
        role={q.kind === "select" ? "radiogroup" : "group"}
        aria-labelledby={labelId}
        aria-describedby={describedBy}
        aria-required={q.kind === "select" && q.required ? true : undefined}
        aria-invalid={q.kind === "select" && error ? true : undefined}
        className={`grid gap-2.5 ${cols}`}
      >
        {options.map((o, i) => {
          const checked = selected.includes(o.value);
          return (
            <label
              key={o.value}
              className={`flex cursor-pointer items-start gap-3 rounded-xl border px-4 py-3.5 text-[15px] leading-6 transition-colors has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-brand ${
                checked
                  ? "border-brand bg-brand-soft text-ink ring-1 ring-inset ring-brand"
                  : `${error ? "border-sev-critical/50" : "border-line"} bg-white text-ink-2 hover:border-line-strong hover:bg-surface-2`
              }`}
            >
              <input
                id={i === 0 ? inputId : undefined}
                type={q.kind === "select" ? "radio" : "checkbox"}
                name={q.id}
                value={o.value}
                checked={checked}
                onChange={() => toggle(o.value)}
                className="sr-only"
              />
              {q.kind === "select" ? (
                <span
                  aria-hidden="true"
                  className={`mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full border-2 bg-white transition-colors ${
                    checked ? "border-brand" : "border-line-strong"
                  }`}
                >
                  {checked && <span className="size-2.5 rounded-full bg-brand" />}
                </span>
              ) : (
                <span
                  aria-hidden="true"
                  className={`mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-md border-2 transition-colors ${
                    checked ? "border-brand bg-brand text-white" : "border-line-strong bg-white"
                  }`}
                >
                  {checked && <CheckIcon size={14} strokeWidth={2.5} />}
                </span>
              )}
              <span className={checked ? "font-medium" : undefined}>{o.label}</span>
            </label>
          );
        })}
      </div>
    );
  }

  return (
    <div id={`field-${q.id}`} className="scroll-mt-24 px-5 py-6 sm:px-8 sm:py-7">
      {label}
      {q.help && (
        <p id={helpId} className="mt-1 text-sm leading-6 text-muted">
          {q.help}
        </p>
      )}
      <div className="mt-4">{control}</div>
      {error && (
        <p id={errorId} className="mt-2.5 flex items-center gap-1.5 text-[13px] font-medium text-sev-critical">
          <AlertIcon size={15} />
          {error === "Required" ? (isChoice ? "Select an option." : "This field is required.") : error}
        </p>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ upload step */

/** Stacked-documents illustration for the dropzone. */
function DocumentsIllustration() {
  return (
    <svg width="120" height="84" viewBox="0 0 120 84" aria-hidden="true" focusable="false">
      <rect x="22" y="14" width="60" height="64" rx="10" fill="#DCEAF4" />
      <rect x="38" y="6" width="60" height="64" rx="10" fill="#FFFFFF" stroke="#BCD3E3" strokeWidth="1.5" />
      <rect x="50" y="22" width="30" height="5" rx="2.5" fill="#BCD3E3" />
      <rect x="50" y="33" width="36" height="5" rx="2.5" fill="#DCEAF4" />
      <rect x="50" y="44" width="24" height="5" rx="2.5" fill="#DCEAF4" />
      <circle cx="92" cy="62" r="16" fill="#0070AD" />
      <path d="M92 69V55m-6 6 6-6 6 6" fill="none" stroke="#FFFFFF" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** One selected file: A-style row with type badge, size, status bar and remove action. */
function FileRow({ file, error, probe, onRemove }: { file: File; error: string | null; probe: Probe; onRemove: () => void }) {
  if (error) {
    return (
      <div className="flex items-start gap-3 rounded-xl border border-[#FDA29B] bg-[#FFFBFA] p-4">
        <FileTypeBadge fileName={file.name} error />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-sev-critical">{file.name}</p>
          <p id="file-error" role="alert" className="mt-0.5 text-sm text-sev-critical">
            {error}
          </p>
        </div>
        <button
          type="button"
          onClick={onRemove}
          aria-label={`Remove ${file.name}`}
          className="shrink-0 rounded-md px-1 text-sm font-semibold text-sev-critical hover:underline"
        >
          Remove
        </button>
      </div>
    );
  }

  const checking = probe.status === "checking";
  const ready = probe.status === "ok";
  return (
    <div className="flex gap-3 rounded-xl border border-line bg-white p-4 shadow-xs">
      <FileTypeBadge fileName={file.name} />
      <div className="min-w-0 flex-1">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-ink-2">{file.name}</p>
            <p className="tabular text-sm text-muted">
              {formatBytes(file.size)}
              {!ready && !checking && " · checked when you submit"}
            </p>
          </div>
          <div className="-mr-1.5 -mt-1 flex shrink-0 items-center gap-1">
            {ready && (
              <svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                <circle cx="12" cy="12" r="10" fill="#0070AD" />
                <path d="m7.5 12.5 3 3 6-6" fill="none" stroke="#FFFFFF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            )}
            <button
              type="button"
              onClick={onRemove}
              aria-label={`Remove ${file.name}`}
              className="flex size-8 items-center justify-center rounded-md text-subtle transition-colors hover:bg-surface-2 hover:text-ink"
            >
              <XIcon size={16} />
            </button>
          </div>
        </div>
        <div className="mt-2.5 flex items-center gap-3">
          <span className="relative h-2 min-w-0 flex-1 overflow-hidden rounded-full bg-line" aria-hidden="true">
            {ready ? (
              <span className="absolute inset-0 rounded-full bg-brand" />
            ) : checking ? (
              <span className="absolute inset-y-0 left-0 w-2/5 animate-indeterminate rounded-full bg-brand" />
            ) : null}
          </span>
          <span className="w-16 shrink-0 text-right text-sm font-medium text-ink-2" role="status">
            {ready ? "Ready" : checking ? "Checking" : "Selected"}
          </span>
        </div>
      </div>
    </div>
  );
}

const SOURCE_OPTIONS: { value: SourceMode; label: string }[] = [
  { value: "file", label: "Upload a file" },
  { value: "git", label: "Git repository" },
];

function SourceToggle({ value, onChange }: { value: SourceMode; onChange: (m: SourceMode) => void }) {
  return (
    <div className="flex justify-center">
      <div role="group" aria-label="How do you want to provide the code?" className="inline-flex rounded-xl border border-line-strong bg-white p-1 shadow-xs">
        {SOURCE_OPTIONS.map((o) => {
          const pressed = value === o.value;
          return (
            <button
              key={o.value}
              type="button"
              aria-pressed={pressed}
              onClick={() => onChange(o.value)}
              className={`inline-flex h-10 items-center gap-2 rounded-lg px-4 text-sm font-semibold transition-colors ${
                pressed ? "bg-brand-soft text-brand-strong ring-1 ring-inset ring-brand/30" : "text-ink-2 hover:bg-surface-2"
              }`}
            >
              {o.value === "file" ? <UploadIcon size={16} /> : <GitBranchIcon size={16} />}
              {o.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function DemoLink({ kind, loading, onDemo, prefix }: { kind: Kind; loading: boolean; onDemo: () => void; prefix: string }) {
  return (
    <p className="text-[13px] text-muted">
      {prefix}{" "}
      <button
        type="button"
        onClick={onDemo}
        disabled={loading}
        className="inline-flex items-center gap-1.5 font-semibold text-brand hover:text-brand-strong hover:underline disabled:text-faint disabled:no-underline"
      >
        {loading && <SpinnerIcon size={13} />}
        Use the {DEMO[kind].label}
      </button>
    </p>
  );
}

function GitSourceCard(props: {
  kind: Kind;
  gitUrl: string;
  gitRef: string;
  gitError: string | null;
  gitRefError: string | null;
  onGitUrl: (v: string) => void;
  onGitRef: (v: string) => void;
  onGitUrlBlur: () => void;
  demoLoading: boolean;
  onDemo: () => void;
}) {
  const { gitError, gitRefError } = props;
  return (
    <div className="rounded-[20px] border border-line bg-white px-5 py-6 shadow-xs sm:px-8 sm:py-8">
      <div className="flex items-start gap-4">
        <span aria-hidden="true" className="hidden size-11 shrink-0 items-center justify-center rounded-xl bg-brand-soft text-brand sm:flex">
          <GitBranchIcon size={22} />
        </span>
        <div className="min-w-0 flex-1 space-y-6">
          <div>
            <label htmlFor="git-url" className="text-[15px] font-semibold leading-6 text-ink">
              Repository link
            </label>
            <p id="git-url-help" className="mt-1 text-sm leading-6 text-muted">
              Public repositories only. We download a snapshot; nothing is cloned or executed.
            </p>
            <input
              id="git-url"
              type="url"
              inputMode="url"
              autoComplete="off"
              spellCheck={false}
              value={props.gitUrl}
              onChange={(e) => props.onGitUrl(e.target.value)}
              onBlur={props.onGitUrlBlur}
              placeholder="https://github.com/owner/repository"
              maxLength={500}
              aria-invalid={gitError ? true : undefined}
              aria-describedby={gitError ? "git-url-help git-url-error" : "git-url-help"}
              className={`${inputBase} ${gitError ? "border-sev-critical" : "border-line-strong"} mt-3 h-12 font-mono text-sm`}
            />
            {gitError && (
              <p id="git-url-error" className="mt-2.5 flex items-start gap-1.5 text-[13px] font-medium text-sev-critical">
                <AlertIcon size={15} className="mt-px shrink-0" />
                {gitError}
              </p>
            )}
            <ul className="mt-3 flex flex-wrap items-center gap-2" aria-label="Supported hosts">
              {["github.com", "gitlab.com"].map((h) => (
                <li key={h} className="inline-flex h-[26px] items-center rounded-full bg-surface-2 px-2.5 text-xs font-semibold text-ink-2 ring-1 ring-inset ring-line">
                  {h}
                </li>
              ))}
            </ul>
          </div>

          <div>
            <div className="flex items-start justify-between gap-3">
              <label htmlFor="git-ref" className="text-[15px] font-semibold leading-6 text-ink">
                Branch, tag or commit
              </label>
              <span className="mt-0.5 inline-flex h-5 shrink-0 items-center rounded-full bg-surface-2 px-2 text-xs font-medium text-subtle ring-1 ring-inset ring-line">
                Optional
              </span>
            </div>
            <p id="git-ref-help" className="mt-1 text-sm leading-6 text-muted">
              Leave empty to scan the default branch.
            </p>
            <input
              id="git-ref"
              type="text"
              autoComplete="off"
              spellCheck={false}
              value={props.gitRef}
              onChange={(e) => props.onGitRef(e.target.value)}
              placeholder="e.g. main, v1.2.0 or a commit hash"
              maxLength={200}
              aria-invalid={gitRefError ? true : undefined}
              aria-describedby={gitRefError ? "git-ref-help git-ref-error" : "git-ref-help"}
              className={`${inputBase} ${gitRefError ? "border-sev-critical" : "border-line-strong"} mt-3 h-12 font-mono text-sm sm:max-w-sm`}
            />
            {gitRefError && (
              <p id="git-ref-error" className="mt-2.5 flex items-start gap-1.5 text-[13px] font-medium text-sev-critical">
                <AlertIcon size={15} className="mt-px shrink-0" />
                {gitRefError}
              </p>
            )}
          </div>

          <DemoLink kind={props.kind} loading={props.demoLoading} onDemo={props.onDemo} prefix="No repository at hand?" />
        </div>
      </div>
    </div>
  );
}

function UploadStep(props: {
  kind: Kind;
  source: SourceMode;
  onSource: (m: SourceMode) => void;
  gitUrl: string;
  gitRef: string;
  gitError: string | null;
  gitRefError: string | null;
  onGitUrl: (v: string) => void;
  onGitRef: (v: string) => void;
  onGitUrlBlur: () => void;
  file: File | null;
  fileError: string | null;
  probe: Probe;
  dragging: boolean;
  demoLoading: boolean;
  fileInputRef: RefObject<HTMLInputElement | null>;
  answers: Answers;
  sections: Section[];
  stepStates: StepState[];
  incomplete: Section[];
  confirmed: boolean;
  confirmError: boolean;
  onConfirm: (v: boolean) => void;
  onSelectFile: (f: File | null) => void;
  onDemo: () => void;
  onDragState: (v: boolean) => void;
  onDrop: (e: DragEvent<HTMLDivElement>) => void;
  onEdit: (step: number) => void;
  onFillExample: () => void;
}) {
  const { kind, source, file, fileError, probe, dragging, demoLoading, fileInputRef, answers, sections, stepStates, incomplete } = props;
  const answeredAny = hasOwnAnswers(answers);
  const rowError = fileError ?? (probe.status === "error" ? probe.message : null);
  const completeCount = stepStates.filter((s) => s === "complete").length;
  const limitNote =
    probe.status === "ok"
      ? probe.info.mode === "inline"
        ? `Demo storage: files up to ${formatBytes(probe.info.maxBytes)} are accepted.`
        : `Uploaded directly to private storage, up to ${formatBytes(MAX_UPLOAD_BYTES)}.`
      : kind === "skill"
        ? `A .zip of the skill folder (with its SKILL.md), up to ${formatBytes(MAX_UPLOAD_BYTES)}.`
        : `A .zip archive or a single source file, up to ${formatBytes(MAX_UPLOAD_BYTES)}.`;

  return (
    <div className="mt-8 space-y-6">
      {/* Source */}
      <section aria-labelledby="file-heading" className="space-y-4">
        <h2 id="file-heading" className="sr-only">
          {kind === "skill" ? "Skill source" : "Application source"}
        </h2>
        <SourceToggle value={source} onChange={props.onSource} />

        {source === "git" ? (
          <GitSourceCard
            kind={kind}
            gitUrl={props.gitUrl}
            gitRef={props.gitRef}
            gitError={props.gitError}
            gitRefError={props.gitRefError}
            onGitUrl={props.onGitUrl}
            onGitRef={props.onGitRef}
            onGitUrlBlur={props.onGitUrlBlur}
            demoLoading={demoLoading}
            onDemo={props.onDemo}
          />
        ) : (
          <>
            <div
              onDragOver={(e) => {
                e.preventDefault();
                e.dataTransfer.dropEffect = "copy";
                if (!dragging) props.onDragState(true);
              }}
              onDragLeave={(e) => {
                if (!e.currentTarget.contains(e.relatedTarget as Node | null)) props.onDragState(false);
              }}
              onDrop={props.onDrop}
              className={`flex flex-col items-center gap-5 rounded-[20px] border-2 border-dashed px-6 py-10 text-center transition-colors sm:px-8 sm:py-11 ${
                dragging ? "border-brand bg-brand-soft" : fileError ? "border-[#FDA29B] bg-white" : "border-[#C9D8E4] bg-tint"
              }`}
            >
              <DocumentsIllustration />
              <div className="space-y-1">
                <p className="font-display text-[19px] font-bold text-ink">
                  {dragging ? "Drop the file to add it" : kind === "skill" ? "Drag your skill folder (.zip) here" : "Drag your project here"}
                </p>
                <p className="text-[15px] text-muted">or</p>
              </div>
              <label
                className={`${btn.hero} cursor-pointer has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-brand`}
              >
                <UploadIcon size={18} />
                {file ? "Choose another file" : "Choose a file"}
                <input
                  ref={fileInputRef}
                  id="file-input"
                  type="file"
                  accept={kind === "skill" ? ".zip,.md" : ACCEPT}
                  className="sr-only"
                  aria-describedby={rowError ? "file-error" : "file-hint"}
                  onChange={(e) => {
                    props.onSelectFile(e.target.files?.[0] ?? null);
                    e.target.value = "";
                  }}
                />
              </label>
              <div className="space-y-2.5">
                <ul className="flex flex-wrap items-center justify-center gap-2" aria-label="Accepted formats include">
                  {(kind === "skill" ? [".zip", ".md"] : FORMAT_CHIPS).map((c) => (
                    <li
                      key={c}
                      className="inline-flex h-[26px] items-center rounded-full bg-white px-2.5 text-xs font-semibold text-ink-2 ring-1 ring-inset ring-line"
                    >
                      {c}
                    </li>
                  ))}
                </ul>
                <p id="file-hint" className="text-[13px] text-subtle">
                  {limitNote}
                </p>
              </div>
              <DemoLink kind={kind} loading={demoLoading} onDemo={props.onDemo} prefix={kind === "skill" ? "No skill at hand?" : "No project at hand?"} />
            </div>

            {file && <FileRow file={file} error={rowError} probe={probe} onRemove={() => props.onSelectFile(null)} />}
            {!file && fileError && (
              <p id="file-error" className="flex items-center gap-1.5 text-[13px] font-medium text-sev-critical" role="alert">
                <AlertIcon size={15} />
                {fileError}
              </p>
            )}
          </>
        )}
        {!answeredAny && (
          <p className="text-sm text-muted">
            Using the {DEMO[kind].label}?{" "}
            <button type="button" onClick={props.onFillExample} className="font-semibold text-brand hover:text-brand-strong hover:underline">
              Fill the questionnaire with example answers
            </button>
            .
          </p>
        )}
      </section>

      {/* Summary */}
      <Card labelledBy="summary-heading">
        <div className="flex flex-wrap items-start justify-between gap-3 border-b border-line px-5 py-4 sm:px-6 sm:py-5">
          <div className="min-w-0">
            <h2 id="summary-heading" className="text-[17px] font-semibold text-ink">
              Review your answers
            </h2>
            <p className="mt-1 text-sm text-muted">Open a section to check what you entered.</p>
          </div>
          <StatusPill tone={incomplete.length ? "warn" : "ok"}>
            {completeCount} of {sections.length} complete
          </StatusPill>
        </div>

        {incomplete.length > 0 && (
          <div className="flex gap-3 border-b border-[#FEDF89] bg-warn-soft px-5 py-3.5 sm:px-6">
            <AlertIcon size={18} className="mt-0.5 shrink-0 text-warn" />
            <div className="min-w-0 text-sm text-warn">
              <p className="font-semibold">
                {incomplete.length === 1 ? "1 section is incomplete" : `${incomplete.length} sections are incomplete`}
              </p>
              <ul className="mt-1 flex flex-wrap gap-x-4 gap-y-1">
                {incomplete.map((s) => (
                  <li key={s.id}>
                    <button
                      type="button"
                      onClick={() => props.onEdit(sections.indexOf(s))}
                      className="inline-flex items-center gap-0.5 font-medium underline underline-offset-2 hover:text-[#7A4505]"
                    >
                      {sectionTitle(s, kind)}
                      <ChevronRightIcon size={14} />
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}

        <div className="divide-y divide-line">
          {sections.map((s, i) => {
            const qs = s.questions.filter((q) => isVisible(q, answers));
            const answered = qs.filter((q) => hasValue(answers[q.id])).length;
            const complete = stepStates[i] === "complete";
            return (
              <details key={s.id} className="group">
                <summary className="flex items-center gap-3 px-5 py-3.5 transition-colors hover:bg-surface-2 sm:px-6">
                  <span className="min-w-0 flex-1 truncate text-sm font-medium text-ink">{sectionTitle(s, kind)}</span>
                  <span className="tabular hidden text-[13px] text-subtle sm:inline">
                    {answered}/{qs.length} answered
                  </span>
                  <StatusPill tone={complete ? "ok" : "warn"}>{complete ? "Complete" : "Incomplete"}</StatusPill>
                  <ChevronDownIcon size={16} className="shrink-0 text-faint transition-transform group-open:rotate-180" />
                </summary>
                <div className="border-t border-line bg-surface-2 px-5 py-4 sm:px-6">
                  <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
                    {qs.map((q) => (
                      <div key={q.id} className="contents">
                        <dt className="text-muted">{q.label}</dt>
                        <dd className="break-words text-ink">
                          {hasValue(answers[q.id]) ? answerLabel(q.id, answers[q.id]) : <span className="text-faint">Not answered</span>}
                        </dd>
                      </div>
                    ))}
                  </dl>
                  <button
                    type="button"
                    onClick={() => props.onEdit(i)}
                    className="mt-4 inline-flex items-center gap-1 text-sm font-semibold text-brand hover:text-brand-strong hover:underline"
                  >
                    Edit this section
                    <ArrowRightIcon size={14} />
                  </button>
                </div>
              </details>
            );
          })}
        </div>
      </Card>

      {/* Confirmation */}
      <div className={`rounded-xl border bg-white px-4 py-4 shadow-xs sm:px-5 ${props.confirmError ? "border-[#FDA29B]" : "border-line"}`}>
        <label className="flex cursor-pointer items-start gap-3 text-[15px] leading-6 text-ink-2">
          <input
            id="confirm-check"
            type="checkbox"
            checked={props.confirmed}
            onChange={(e) => props.onConfirm(e.target.checked)}
            aria-invalid={props.confirmError ? true : undefined}
            aria-describedby={props.confirmError ? "confirm-error" : undefined}
            className="mt-[3px] size-[18px] shrink-0 accent-brand"
          />
          <span>I confirm the information is accurate and I am authorised to submit this {kind === "skill" ? "skill" : "asset"}.</span>
        </label>
        {props.confirmError && (
          <p id="confirm-error" role="alert" className="mt-2 flex items-center gap-1.5 pl-[30px] text-[13px] font-medium text-sev-critical">
            Confirm the statement above to continue.
          </p>
        )}
      </div>
    </div>
  );
}

/** "What happens after you submit" explainer shown under the final step. */
function AfterSubmit({ kind }: { kind: Kind }) {
  const items = [AFTER_SUBMIT_FIRST[kind], ...AFTER_SUBMIT_REST];
  return (
    <section aria-labelledby="after-heading" className="mt-14 border-t border-line pt-10 sm:mt-16 sm:pt-12">
      <h2 id="after-heading" className="text-[22px] font-bold tracking-tight text-ink">
        What happens after you submit
      </h2>
      <ol className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {items.map((s, i) => (
          <li key={s.title} className="flex flex-col gap-2.5 rounded-xl border border-line bg-white p-5 shadow-xs">
            <span
              aria-hidden="true"
              className="flex size-8 items-center justify-center rounded-[10px] bg-brand-soft font-display text-sm font-bold text-brand"
            >
              {i + 1}
            </span>
            <span className="font-display text-base font-bold text-ink">{s.title}</span>
            <span className="text-sm leading-[22px] text-muted">{s.text}</span>
            <span className="mt-auto pt-1 text-[13px] font-semibold text-brand">{s.time}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}

/* ------------------------------------------------------------------ progress view */

function ScanProgress({
  assetName,
  run,
  phase,
  simStep,
  elapsedMs,
}: {
  assetName: string;
  run: Run | null;
  phase: Phase;
  simStep: number;
  elapsedMs: number;
}) {
  const mode: SourceMode = run?.mode ?? "file";
  const kind: Kind = run?.kind ?? "app";
  const steps = scanSteps(mode, kind);
  const done = phase === "redirecting";
  const active = phase === "uploading" ? 0 : done ? steps.length : simStep;
  const secs = Math.floor(elapsedMs / 1000);
  const elapsed = `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, "0")}`;
  const firstLabel = steps[0]?.label ?? "Uploading";

  return (
    <div className="mx-auto max-w-[680px] sm:pt-4">
      <div className="text-center">
        <span className="inline-flex h-7 items-center gap-1.5 rounded-full bg-brand-soft px-3 text-xs font-semibold text-brand-strong">
          {done ? <CheckIcon size={14} strokeWidth={2.25} /> : <SpinnerIcon size={14} />}
          {done ? "Scan complete" : active === 0 ? firstLabel : "Scan in progress"}
        </span>
        <h1 id="scan-title" className="mt-4 text-[30px] font-bold leading-[1.2] tracking-[-0.025em] text-ink sm:text-[36px]">
          {done ? "Your report is ready" : kind === "skill" ? "Reviewing your skill" : "Scanning your application"}
        </h1>
        <p className="mx-auto mt-3 max-w-[560px] text-base leading-7 text-muted sm:text-[17px]">
          {done
            ? "Opening the report…"
            : phase === "uploading"
              ? "Uploading your file. This depends on your connection speed; the scan starts as soon as the upload is complete."
              : secs >= 45
                ? "Still working. Large projects and slow dependency look-ups can take up to a minute. Keep this tab open; the report opens automatically."
                : "This usually takes 5 to 40 seconds. Keep this tab open; the report opens automatically."}
        </p>
      </div>

      <Card labelledBy="scan-title" className="mt-8 overflow-hidden">
        <div className="relative h-1 overflow-hidden bg-line" aria-hidden="true">
          {done ? <div className="absolute inset-0 bg-brand" /> : <div className="absolute inset-y-0 left-0 w-2/5 animate-indeterminate bg-brand" />}
        </div>

        <div className="flex items-center gap-4 border-b border-line px-5 py-4 sm:px-6">
          <InitialsTile name={assetName} />
          <div className="min-w-0 flex-1">
            <p className="truncate font-display text-base font-bold text-ink">{assetName}</p>
            {run && (
              <p className="flex min-w-0 items-center gap-1.5 text-[13px] text-subtle">
                {run.mode === "git" && <GitBranchIcon size={13} className="shrink-0" />}
                <span className="truncate font-mono">{run.name}</span>
                <span className="tabular shrink-0">· {run.detail}</span>
              </p>
            )}
          </div>
          <div className="shrink-0 text-right">
            <p className="text-xs font-medium text-subtle">Elapsed</p>
            <p className="tabular font-display text-xl font-bold text-ink">{elapsed}</p>
          </div>
        </div>

        <ol className="divide-y divide-line" aria-label="Scan progress">
          {steps.map((s, i) => {
            const state = i < active ? "done" : i === active ? "active" : "pending";
            return (
              <li key={s.label} className={`flex items-center gap-3 px-5 py-3 sm:px-6 ${state === "active" ? "bg-tint" : ""}`}>
                <span className="flex size-6 shrink-0 items-center justify-center">
                  {state === "done" ? (
                    <span className="flex size-5 items-center justify-center rounded-full bg-brand text-white">
                      <CheckIcon size={13} strokeWidth={2.5} />
                    </span>
                  ) : state === "active" ? (
                    <SpinnerIcon size={20} className="text-brand" />
                  ) : (
                    <span className="size-5 rounded-full border-2 border-line-strong bg-white" />
                  )}
                </span>
                <span
                  className={`min-w-0 flex-1 text-sm ${
                    state === "done" ? "text-ink-2" : state === "active" ? "font-semibold text-ink" : "text-faint"
                  }`}
                >
                  {s.label}
                </span>
                <span
                  className={`shrink-0 text-[13px] ${
                    state === "done" ? "text-subtle" : state === "active" ? "font-medium text-brand" : "text-faint"
                  }`}
                >
                  {state === "done" ? "Done" : state === "active" ? "Running" : "Waiting"}
                </span>
              </li>
            );
          })}
        </ol>

        <div className="border-t border-line bg-surface-2 px-5 py-3 text-[13px] text-subtle sm:px-6">
          Step timing is indicative; all scanners run in one server job. {mode === "git" ? "The repository snapshot" : "Uploaded code"} is never executed.
        </div>
        <p className="sr-only" aria-live="polite">
          {done ? "Scan complete. Opening the report." : (steps[Math.min(active, steps.length - 1)]?.label ?? "")}
        </p>
      </Card>
    </div>
  );
}
