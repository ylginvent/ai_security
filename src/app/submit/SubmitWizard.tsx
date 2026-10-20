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
import { StatusPill } from "@/components/StatusPill";
import { DEMO_ANSWERS } from "@/lib/demo-answers";
import { formatBytes } from "@/lib/format";
import { ALL_QUESTIONS, SECTIONS, answerLabel, isVisible, validateAnswers, type Question, type Section } from "@/lib/questionnaire";
import type { Answers } from "@/lib/types";

/* ------------------------------------------------------------------ constants */

const DRAFT_KEY = "aag.submission-draft.v1";
const UPLOAD_STEP = SECTIONS.length;
const STEP_TITLES = [...SECTIONS.map((s) => s.title), "Upload & scan"];
const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;
const DEMO_FILE_NAME = "contoso-rag-assistant.zip";
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
const STEP_SHORT = [...SECTIONS.map((s) => SHORT_TITLES[s.id] ?? s.title), "Upload & scan"];

/** Friendly display heading per step. */
const STEP_HEADINGS: Record<string, string> = {
  asset: "Tell us about your AI asset",
  data: "What data does it handle?",
  model: "Which models does it rely on?",
  architecture: "How is it built and exposed?",
  controls: "Which safeguards are in place?",
  governance: "How will it be used?",
};
const UPLOAD_HEADING = "Last step: upload your application";
const UPLOAD_INTRO =
  "We check the code, its dependencies and any model files. You get a clear report with what to fix, usually within a minute.";

const FORMAT_CHIPS = [".zip", ".py", ".ipynb", ".ts", ".js", ".tf"];

const AFTER_SUBMIT = [
  {
    title: "Automated scan",
    text: "Six scanners check secrets, dependencies, code, AI risks, model files and infrastructure.",
    time: "Under a minute",
  },
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

const SCAN_STEPS = [
  "Uploading",
  "Extracting archive",
  "Secret detection",
  "Dependency vulnerabilities (OSV.dev)",
  "Static analysis",
  "AI / LLM rules",
  "Model artefacts",
  "Configuration & IaC",
  "Evaluating gate",
];
/** Indicative time spent on each simulated step before moving on; the last step waits for the server. */
const STEP_MS = [0, 1200, 1600, 5200, 3000, 2400, 1800, 1800];

/** Large secondary button that pairs with btn.hero on single-task screens. */
const bigSecondary =
  "inline-flex h-12 items-center justify-center gap-2 rounded-xl border border-line-strong bg-white px-5 text-[15px] font-semibold text-ink-2 shadow-xs transition-colors hover:bg-surface-2";

/* ------------------------------------------------------------------ API helpers */

type UploadInfo =
  | { mode: "storage"; supabaseUrl: string; publishableKey: string; bucket: string; path: string; token: string }
  | { mode: "inline"; maxBytes: number };

class ApiError extends Error {
  fields?: Record<string, string>;
  constructor(message: string, fields?: Record<string, string>) {
    super(message);
    this.name = "ApiError";
    this.fields = fields;
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
  if (status === 504) return "The scan took too long and timed out. Try again, or submit a smaller archive.";
  if (status === 413) return "The file is too large for this environment.";
  return `${fallback} (HTTP ${status}).`;
}

async function requestUploadTarget(file: File): Promise<UploadInfo> {
  const res = await fetch("/api/uploads", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ fileName: file.name, size: file.size }),
  });
  const d = await readBody(res);
  if (!res.ok) throw new ApiError(errorMessage(d, res.status, "The upload could not be prepared"));
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

/* ------------------------------------------------------------------ answer helpers */

const hasValue = (v: string | string[] | undefined) => (Array.isArray(v) ? v.length > 0 : typeof v === "string" && v.trim() !== "");

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

type StepState = "complete" | "attention" | "started" | "todo";

/* ------------------------------------------------------------------ component */

type Phase = "idle" | "uploading" | "scanning" | "redirecting";
type FocusTarget = { kind: "heading" } | { kind: "field"; id: string } | { kind: "element"; id: string };
type Probe = { status: "idle" } | { status: "checking" } | { status: "ok"; info: UploadInfo } | { status: "error"; message: string };

export default function SubmitWizard() {
  const router = useRouter();
  const [answers, setAnswers] = useState<Answers>({});
  const [step, setStep] = useState(0);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [attempted, setAttempted] = useState<Record<string, boolean>>({});
  const [hydrated, setHydrated] = useState(false);
  const [restored, setRestored] = useState(false);

  const [file, setFile] = useState<File | null>(null);
  const [fileError, setFileError] = useState<string | null>(null);
  const [probe, setProbe] = useState<Probe>({ status: "idle" });
  const [demoLoading, setDemoLoading] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [confirmError, setConfirmError] = useState(false);

  const [phase, setPhase] = useState<Phase>("idle");
  const [simStep, setSimStep] = useState(0);
  const [startedAt, setStartedAt] = useState(0);
  const [nowTick, setNowTick] = useState(0);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [focusTarget, setFocusTarget] = useState<FocusTarget | null>(null);

  const headingRef = useRef<HTMLHeadingElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const probeSeq = useRef(0);
  const submittedName = useRef("");

  /* draft persistence --------------------------------------------- */
  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(DRAFT_KEY);
      if (raw) {
        const d: unknown = JSON.parse(raw);
        if (d && typeof d === "object") {
          const draft = d as { answers?: unknown; step?: unknown };
          const restoredAnswers = sanitizeDraft(draft.answers);
          if (Object.keys(restoredAnswers).length) {
            setAnswers(restoredAnswers);
            setRestored(true);
          }
          if (typeof draft.step === "number" && draft.step >= 0 && draft.step <= UPLOAD_STEP) setStep(Math.floor(draft.step));
        }
      }
    } catch {
      /* storage unavailable or corrupt draft: start empty */
    }
    setHydrated(true);
  }, []);

  useEffect(() => {
    if (!hydrated) return;
    try {
      window.localStorage.setItem(DRAFT_KEY, JSON.stringify({ answers, step }));
    } catch {
      /* ignore quota / privacy mode */
    }
  }, [answers, step, hydrated]);

  /* simulated scan progress ---------------------------------------- */
  useEffect(() => {
    if (phase !== "scanning") return;
    let i = 1;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setSimStep(1);
    const next = () => {
      if (i >= SCAN_STEPS.length - 1) return;
      timer = setTimeout(() => {
        i += 1;
        setSimStep(i);
        next();
      }, STEP_MS[i] ?? 2000);
    };
    next();
    return () => {
      if (timer) clearTimeout(timer);
    };
  }, [phase]);

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
    } else {
      const el = document.getElementById(`field-${focusTarget.id}`);
      if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "center" });
        const input = el.querySelector<HTMLElement>("input:checked, input, textarea");
        input?.focus({ preventScroll: true });
      }
    }
    setFocusTarget(null);
  }, [focusTarget]);

  /* derived state ---------------------------------------------------- */
  const sectionErrors = useMemo(() => SECTIONS.map((s) => validateAnswers(answers, s.id)), [answers]);
  const stepStates: StepState[] = useMemo(
    () =>
      SECTIONS.map((s, i): StepState => {
        const valid = Object.keys(sectionErrors[i]).length === 0;
        if (valid) return "complete";
        if (attempted[s.id]) return "attention";
        return s.questions.some((q) => hasValue(answers[q.id])) ? "started" : "todo";
      }),
    [sectionErrors, attempted, answers],
  );
  const incomplete = SECTIONS.filter((_, i) => stepStates[i] !== "complete");
  const allValid = incomplete.length === 0;

  /* navigation ------------------------------------------------------- */
  function goTo(i: number) {
    setStep(i);
    setFocusTarget({ kind: "heading" });
  }

  function focusFirstError(section: Section, errs: Record<string, string>) {
    const first = section.questions.find((q) => errs[q.id]);
    if (first) setFocusTarget({ kind: "field", id: first.id });
  }

  function continueFrom(i: number) {
    const section = SECTIONS[i];
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
    const idx = SECTIONS.findIndex((s) => s.questions.some((q) => errs[q.id]));
    if (idx < 0) return false;
    setErrors((prev) => ({ ...prev, ...errs }));
    setAttempted((prev) => {
      const next = { ...prev };
      for (const s of SECTIONS) if (s.questions.some((q) => errs[q.id])) next[s.id] = true;
      return next;
    });
    setStep(idx);
    focusFirstError(SECTIONS[idx], errs);
    return true;
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
    if (Object.keys(answers).some((k) => hasValue(answers[k])) && !window.confirm("Replace the current answers with the example answers for the demo application?")) return;
    setAnswers(cloneAnswers(DEMO_ANSWERS));
    setErrors({});
    setAttempted({});
  }

  function clearForm() {
    if (!window.confirm("Clear all answers and the selected file? This cannot be undone.")) return;
    setAnswers({});
    setErrors({});
    setAttempted({});
    setFile(null);
    setFileError(null);
    setProbe({ status: "idle" });
    setConfirmed(false);
    setSubmitError(null);
    setRestored(false);
    try {
      window.localStorage.removeItem(DRAFT_KEY);
    } catch {
      /* ignore */
    }
    goTo(0);
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
      // Only server-side rejections block the submit; network hiccups are retried on submit.
      setProbe(e instanceof ApiError ? { status: "error", message: e.message } : { status: "idle" });
    }
  }

  function selectFile(f: File | null) {
    probeSeq.current++;
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
    void probeUpload(f);
  }

  async function loadDemoApp() {
    setDemoLoading(true);
    setFileError(null);
    try {
      const res = await fetch("/api/sample");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const blob = await res.blob();
      selectFile(new File([blob], DEMO_FILE_NAME, { type: "application/zip" }));
    } catch {
      setFileError("The demo application could not be downloaded. Please try again.");
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
    setSubmitError(null);
    const allErrors = validateAnswers(answers);
    if (Object.keys(allErrors).length) {
      showErrors(allErrors);
      return;
    }
    if (!file) {
      setFileError("Select a file to scan.");
      return;
    }
    if (fileError || probe.status === "error") return;
    if (!confirmed) {
      setConfirmError(true);
      return;
    }

    const clean = visibleAnswers(answers);
    submittedName.current = String(clean.asset_name ?? "asset");
    setStartedAt(Date.now());
    setSimStep(0);
    setPhase("uploading");
    window.scrollTo({ top: 0, behavior: "smooth" });

    try {
      const target = await requestUploadTarget(file);
      let res: Response;
      if (target.mode === "storage") {
        const { createClient } = await import("@supabase/supabase-js");
        const supabase = createClient(target.supabaseUrl, target.publishableKey, {
          auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
        });
        const { error } = await supabase.storage
          .from(target.bucket)
          .uploadToSignedUrl(target.path, target.token, file, { contentType: file.type || "application/octet-stream" });
        if (error) throw new ApiError(`The upload failed: ${error.message}`);
        setPhase("scanning");
        res = await fetch("/api/submissions", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ answers: clean, upload: { path: target.path, fileName: file.name, size: file.size } }),
        });
      } else {
        if (file.size > target.maxBytes) {
          throw new ApiError(`This environment accepts files up to ${formatBytes(target.maxBytes)}. Upload a smaller archive.`);
        }
        const form = new FormData();
        form.append("answers", JSON.stringify(clean));
        form.append("file", file, file.name);
        setPhase("scanning");
        res = await fetch("/api/submissions", { method: "POST", body: form });
      }

      const data = await readBody(res);
      if (!res.ok) throw new ApiError(errorMessage(data, res.status, "The submission failed"), parseFields(data.fields));
      const id = typeof data.id === "string" ? data.id : "";
      if (!id) throw new ApiError("The server returned an unexpected response.");

      setPhase("redirecting");
      try {
        window.localStorage.removeItem(DRAFT_KEY);
      } catch {
        /* ignore */
      }
      router.push(`/reports/${encodeURIComponent(id)}`);
    } catch (e) {
      setPhase("idle");
      const message = e instanceof ApiError ? e.message : "The server could not be reached. Check your connection and try again.";
      setSubmitError(message);
      const jumped = e instanceof ApiError && e.fields ? showErrors(e.fields) : false;
      if (!jumped) setFocusTarget({ kind: "element", id: "submit-error" });
    }
  }

  /* render ------------------------------------------------------------ */
  if (phase !== "idle") {
    return (
      <ScanProgress
        assetName={submittedName.current}
        file={file}
        phase={phase}
        simStep={simStep}
        elapsedMs={Math.max(0, nowTick - startedAt)}
      />
    );
  }

  const section = step < UPLOAD_STEP ? SECTIONS[step] : null;
  const heading = section ? STEP_HEADINGS[section.id] ?? section.title : UPLOAD_HEADING;
  const intro = section ? section.intro : UPLOAD_INTRO;
  const submitDisabled = !file || !!fileError || probe.status === "error" || probe.status === "checking";

  return (
    <div className="mx-auto max-w-[1136px]">
      <div className="mx-auto max-w-[860px]">
        {/* Utility row */}
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
          <p className="text-sm font-semibold text-ink-2">New submission</p>
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

        <StepProgress step={step} states={stepStates} onSelect={goTo} />

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

        {restored && step === 0 && (
          <p
            className="mx-auto mt-6 flex w-fit items-center gap-2 rounded-full border border-line bg-white px-3.5 py-1.5 text-[13px] text-muted shadow-xs"
            role="status"
          >
            <span className="size-1.5 rounded-full bg-brand" aria-hidden="true" />
            Your draft was restored from this browser.
          </p>
        )}

        {section ? (
          <>
            <Card labelledBy="step-title" className="mt-8">
              <div className="divide-y divide-line">
                {section.questions
                  .filter((q) => isVisible(q, answers))
                  .map((q) => (
                    <QuestionField key={q.id} q={q} value={answers[q.id]} error={errors[q.id]} onChange={(v) => setAnswer(q.id, v)} />
                  ))}
              </div>
            </Card>

            <FooterBar>
              {step > 0 ? (
                <button type="button" onClick={() => goTo(step - 1)} className={bigSecondary}>
                  <ArrowLeftIcon size={18} />
                  Back
                </button>
              ) : (
                <span />
              )}
              <div className="flex items-center gap-4">
                <span className="hidden text-[13px] text-subtle sm:inline">{hydrated ? "Draft saved in this browser" : ""}</span>
                <button type="button" onClick={() => continueFrom(step)} className={`${btn.hero} min-w-[148px]`}>
                  Continue
                  <ArrowRightIcon size={18} />
                </button>
              </div>
            </FooterBar>
          </>
        ) : (
          <>
            <UploadStep
              file={file}
              fileError={fileError}
              probe={probe}
              dragging={dragging}
              demoLoading={demoLoading}
              fileInputRef={fileInputRef}
              answers={answers}
              stepStates={stepStates}
              incomplete={incomplete}
              confirmed={confirmed}
              confirmError={confirmError}
              onConfirm={(v) => {
                setConfirmed(v);
                if (v) setConfirmError(false);
              }}
              onSelectFile={selectFile}
              onDemo={loadDemoApp}
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
              <button type="button" onClick={() => goTo(step - 1)} className={bigSecondary}>
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

      {!section && <AfterSubmit />}
    </div>
  );
}

/* ------------------------------------------------------------------ progress header */

const STATE_TEXT: Record<StepState, string> = { complete: "Complete", attention: "Needs attention", started: "In progress", todo: "Not started" };

function StepProgress({ step, states, onSelect }: { step: number; states: StepState[]; onSelect: (i: number) => void }) {
  const total = STEP_TITLES.length;
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
          aria-valuetext={`Step ${step + 1} of ${total}: ${STEP_TITLES[step]}`}
          className="h-1.5 min-w-0 flex-1 overflow-hidden rounded-full bg-line"
        >
          <span className="block h-full rounded-full bg-brand transition-[width] duration-500" style={{ width: `${pct}%` }} />
        </span>
        <span className="max-w-[40%] shrink-0 truncate text-[13px] text-muted">{STEP_TITLES[step]}</span>
      </div>

      {/* Segmented step list */}
      <nav aria-label="Submission steps" className="mt-4">
        <ol className="grid gap-1.5 sm:gap-2" style={{ gridTemplateColumns: `repeat(${total}, minmax(0, 1fr))` }}>
          {STEP_TITLES.map((title, i) => {
            const state = i < SECTIONS.length ? states[i] : "upload";
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
                  className="group flex w-full flex-col gap-2 rounded-md py-1.5 text-left"
                >
                  <span className={`h-1 w-full rounded-full transition-colors ${bar}`} />
                  <span className={`hidden text-xs leading-4 transition-colors group-hover:text-ink sm:block ${label}`}>{STEP_SHORT[i]}</span>
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

function UploadStep(props: {
  file: File | null;
  fileError: string | null;
  probe: Probe;
  dragging: boolean;
  demoLoading: boolean;
  fileInputRef: RefObject<HTMLInputElement | null>;
  answers: Answers;
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
  const { file, fileError, probe, dragging, demoLoading, fileInputRef, answers, stepStates, incomplete } = props;
  const answeredAny = Object.keys(answers).some((k) => hasValue(answers[k]));
  const rowError = fileError ?? (probe.status === "error" ? probe.message : null);
  const completeCount = stepStates.filter((s) => s === "complete").length;
  const limitNote =
    probe.status === "ok"
      ? probe.info.mode === "inline"
        ? `Demo storage: files up to ${formatBytes(probe.info.maxBytes)} are accepted.`
        : `Uploaded directly to private storage, up to ${formatBytes(MAX_UPLOAD_BYTES)}.`
      : `A .zip archive or a single source file, up to ${formatBytes(MAX_UPLOAD_BYTES)}.`;

  return (
    <div className="mt-8 space-y-6">
      {/* File */}
      <section aria-labelledby="file-heading" className="space-y-4">
        <h2 id="file-heading" className="sr-only">
          Application source
        </h2>
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
            <p className="font-display text-[19px] font-bold text-ink">{dragging ? "Drop the file to add it" : "Drag your project here"}</p>
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
              accept={ACCEPT}
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
              {FORMAT_CHIPS.map((c) => (
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
          <p className="text-[13px] text-muted">
            No project at hand?{" "}
            <button
              type="button"
              onClick={props.onDemo}
              disabled={demoLoading}
              className="inline-flex items-center gap-1.5 font-semibold text-brand hover:text-brand-strong hover:underline disabled:text-faint disabled:no-underline"
            >
              {demoLoading && <SpinnerIcon size={13} />}
              Use the demo application
            </button>
          </p>
        </div>

        {file && <FileRow file={file} error={rowError} probe={probe} onRemove={() => props.onSelectFile(null)} />}
        {!file && fileError && (
          <p id="file-error" className="flex items-center gap-1.5 text-[13px] font-medium text-sev-critical" role="alert">
            <AlertIcon size={15} />
            {fileError}
          </p>
        )}
        {!answeredAny && (
          <p className="text-sm text-muted">
            Using the demo application?{" "}
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
            {completeCount} of {SECTIONS.length} complete
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
                      onClick={() => props.onEdit(SECTIONS.indexOf(s))}
                      className="inline-flex items-center gap-0.5 font-medium underline underline-offset-2 hover:text-[#7A4505]"
                    >
                      {s.title}
                      <ChevronRightIcon size={14} />
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}

        <div className="divide-y divide-line">
          {SECTIONS.map((s, i) => {
            const qs = s.questions.filter((q) => isVisible(q, answers));
            const answered = qs.filter((q) => hasValue(answers[q.id])).length;
            const complete = stepStates[i] === "complete";
            return (
              <details key={s.id} className="group">
                <summary className="flex items-center gap-3 px-5 py-3.5 transition-colors hover:bg-surface-2 sm:px-6">
                  <span className="min-w-0 flex-1 truncate text-sm font-medium text-ink">{s.title}</span>
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
            type="checkbox"
            checked={props.confirmed}
            onChange={(e) => props.onConfirm(e.target.checked)}
            aria-invalid={props.confirmError ? true : undefined}
            aria-describedby={props.confirmError ? "confirm-error" : undefined}
            className="mt-[3px] size-[18px] shrink-0 accent-brand"
          />
          <span>I confirm the information is accurate and I am authorised to submit this asset.</span>
        </label>
        {props.confirmError && (
          <p id="confirm-error" className="mt-2 flex items-center gap-1.5 pl-[30px] text-[13px] font-medium text-sev-critical">
            Confirm the statement above to continue.
          </p>
        )}
      </div>
    </div>
  );
}

/** "What happens after you submit" explainer shown under the final step. */
function AfterSubmit() {
  return (
    <section aria-labelledby="after-heading" className="mt-14 border-t border-line pt-10 sm:mt-16 sm:pt-12">
      <h2 id="after-heading" className="text-[22px] font-bold tracking-tight text-ink">
        What happens after you submit
      </h2>
      <ol className="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {AFTER_SUBMIT.map((s, i) => (
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
  file,
  phase,
  simStep,
  elapsedMs,
}: {
  assetName: string;
  file: File | null;
  phase: Phase;
  simStep: number;
  elapsedMs: number;
}) {
  const done = phase === "redirecting";
  const active = phase === "uploading" ? 0 : done ? SCAN_STEPS.length : simStep;
  const secs = Math.floor(elapsedMs / 1000);
  const elapsed = `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, "0")}`;

  return (
    <div className="mx-auto max-w-[680px] sm:pt-4">
      <div className="text-center">
        <span className="inline-flex h-7 items-center gap-1.5 rounded-full bg-brand-soft px-3 text-xs font-semibold text-brand-strong">
          {done ? <CheckIcon size={14} strokeWidth={2.25} /> : <SpinnerIcon size={14} />}
          {done ? "Scan complete" : phase === "uploading" ? "Uploading" : "Scan in progress"}
        </span>
        <h1 id="scan-title" className="mt-4 text-[30px] font-bold leading-[1.2] tracking-[-0.025em] text-ink sm:text-[36px]">
          {done ? "Your report is ready" : "Scanning your application"}
        </h1>
        <p className="mx-auto mt-3 max-w-[560px] text-base leading-7 text-muted sm:text-[17px]">
          {done ? "Opening the report…" : "This usually takes 5 to 40 seconds. Keep this tab open; the report opens automatically."}
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
            {file && (
              <p className="flex min-w-0 items-center gap-1.5 text-[13px] text-subtle">
                <span className="truncate font-mono">{file.name}</span>
                <span className="tabular shrink-0">· {formatBytes(file.size)}</span>
              </p>
            )}
          </div>
          <div className="shrink-0 text-right">
            <p className="text-xs font-medium text-subtle">Elapsed</p>
            <p className="tabular font-display text-xl font-bold text-ink">{elapsed}</p>
          </div>
        </div>

        <ol className="divide-y divide-line" aria-label="Scan progress">
          {SCAN_STEPS.map((label, i) => {
            const state = i < active ? "done" : i === active ? "active" : "pending";
            return (
              <li key={label} className={`flex items-center gap-3 px-5 py-3 sm:px-6 ${state === "active" ? "bg-tint" : ""}`}>
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
                  {label}
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
          Step timing is indicative; all scanners run in one server job. Uploaded code is never executed.
        </div>
        <p className="sr-only" aria-live="polite">
          {done ? "Scan complete. Opening the report." : SCAN_STEPS[Math.min(active, SCAN_STEPS.length - 1)]}
        </p>
      </Card>
    </div>
  );
}
