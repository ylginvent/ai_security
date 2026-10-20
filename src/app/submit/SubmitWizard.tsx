"use client";

import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState, type DragEvent, type ReactNode, type RefObject } from "react";
import { Card, PageHeader, btn } from "@/components/Card";
import {
  AlertIcon,
  ArchiveIcon,
  ArrowLeftIcon,
  ArrowRightIcon,
  CheckIcon,
  ChevronRightIcon,
  FileIcon,
  SpinnerIcon,
  UploadIcon,
  XIcon,
} from "@/components/icons";
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
  const stepLabel = `Step ${step + 1} of ${STEP_TITLES.length}`;

  return (
    <div className="space-y-6">
      <PageHeader
        title="New submission"
        description="Describe the AI asset, then upload its source. The questionnaire and the automated scan together determine whether the asset can be published to the Azure AI catalogue."
        actions={
          <>
            <button type="button" onClick={fillExample} className={btn.secondary}>
              Fill with example answers
            </button>
            <button type="button" onClick={clearForm} className={btn.ghost}>
              Clear form
            </button>
          </>
        }
      />

      <div className="grid gap-6 lg:grid-cols-[232px_minmax(0,1fr)] lg:gap-8">
        <StepNav step={step} states={stepStates} onSelect={goTo} />

        <div className="min-w-0 space-y-4">
          {restored && step === 0 && (
            <p className="flex items-center gap-2 rounded-md border border-slate-200 bg-white px-3 py-2 text-[13px] text-slate-600" role="status">
              <span className="size-1.5 rounded-full bg-brand" aria-hidden="true" />
              Your draft was restored from this browser.
            </p>
          )}

          <Card labelledBy="step-title">
            <div className="border-b border-slate-200 px-4 py-4 sm:px-6">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-medium text-slate-500">{stepLabel}</span>
                {section && (
                  <span className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[11px] font-medium text-slate-600" title="Reference framework">
                    {section.framework}
                  </span>
                )}
              </div>
              <h2 id="step-title" ref={headingRef} tabIndex={-1} className="mt-1.5 text-lg font-semibold tracking-tight text-slate-900 focus:outline-none">
                {STEP_TITLES[step]}
              </h2>
              <p className="mt-1 text-sm text-slate-600">
                {section ? section.intro : "Upload the application source, review your answers and start the automated scan."}
              </p>
            </div>

            {section ? (
              <div className="divide-y divide-slate-100">
                {section.questions
                  .filter((q) => isVisible(q, answers))
                  .map((q) => (
                    <QuestionField key={q.id} q={q} value={answers[q.id]} error={errors[q.id]} onChange={(v) => setAnswer(q.id, v)} />
                  ))}
              </div>
            ) : (
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
            )}

            {submitError && step === UPLOAD_STEP && (
              <div id="submit-error" className="mx-4 mb-4 flex scroll-mt-24 gap-3 rounded-md border border-sev-critical/30 bg-sev-critical-soft px-4 py-3 sm:mx-6" role="alert">
                <AlertIcon size={18} className="mt-0.5 shrink-0 text-sev-critical" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-sev-critical">Submission failed</p>
                  <p className="mt-0.5 text-sm text-slate-700">{submitError}</p>
                </div>
                <button type="button" onClick={submit} className={`${btn.secondary} h-8 shrink-0`}>
                  Retry
                </button>
              </div>
            )}

            <div className="flex flex-col-reverse gap-3 border-t border-slate-200 bg-slate-50/60 px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-6">
              <span className="text-xs text-slate-500">{hydrated ? "Draft saved automatically in this browser" : ""}</span>
              <div className="flex gap-2">
                {step > 0 && (
                  <button type="button" onClick={() => goTo(step - 1)} className={btn.secondary}>
                    <ArrowLeftIcon size={16} />
                    Back
                  </button>
                )}
                {step < UPLOAD_STEP ? (
                  <button type="button" onClick={() => continueFrom(step)} className={`${btn.primary} flex-1 sm:flex-none`}>
                    Continue
                    <ArrowRightIcon size={16} />
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={submit}
                    disabled={!file || !!fileError || probe.status === "error" || probe.status === "checking"}
                    className={`${btn.primary} flex-1 sm:flex-none`}
                  >
                    Submit and start scan
                  </button>
                )}
              </div>
            </div>
          </Card>
          {step === UPLOAD_STEP && !allValid && (
            <p className="text-xs text-slate-500">Submitting will take you to the first incomplete section.</p>
          )}
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ step navigation */

function StepIndicator({ index, state, current }: { index: number; state: StepState | "upload"; current: boolean }) {
  if (state === "complete") {
    return (
      <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-brand text-white">
        <CheckIcon size={14} strokeWidth={2} />
      </span>
    );
  }
  if (state === "attention") {
    return (
      <span className="flex size-6 shrink-0 items-center justify-center rounded-full border border-sev-critical bg-sev-critical-soft text-[11px] font-semibold text-sev-critical">
        !
      </span>
    );
  }
  return (
    <span
      className={`tabular flex size-6 shrink-0 items-center justify-center rounded-full border text-[11px] font-semibold ${
        current ? "border-brand bg-white text-brand" : "border-slate-300 bg-white text-slate-500"
      }`}
    >
      {index + 1}
    </span>
  );
}

const STATE_TEXT: Record<StepState, string> = { complete: "Complete", attention: "Needs attention", started: "In progress", todo: "Not started" };

function StepNav({ step, states, onSelect }: { step: number; states: StepState[]; onSelect: (i: number) => void }) {
  const doneCount = states.filter((s) => s === "complete").length;
  return (
    <>
      {/* Mobile: compact segmented progress */}
      <nav aria-label="Submission steps" className="lg:hidden">
        <div className="flex items-baseline justify-between text-xs text-slate-500">
          <span>
            Step {step + 1} of {STEP_TITLES.length}
          </span>
          <span className="tabular">
            {doneCount}/{SECTIONS.length} sections complete
          </span>
        </div>
        <ol className="mt-2 grid gap-1" style={{ gridTemplateColumns: `repeat(${STEP_TITLES.length}, minmax(0, 1fr))` }}>
          {STEP_TITLES.map((title, i) => {
            const state = i < SECTIONS.length ? states[i] : "upload";
            const color =
              state === "complete" ? "bg-brand" : state === "attention" ? "bg-sev-critical" : i === step ? "bg-slate-500" : "bg-slate-200";
            return (
              <li key={title}>
                <button
                  type="button"
                  onClick={() => onSelect(i)}
                  aria-current={i === step ? "step" : undefined}
                  aria-label={`Step ${i + 1}: ${title}${state !== "upload" ? ` (${STATE_TEXT[state]})` : ""}`}
                  className="flex h-6 w-full items-center"
                >
                  <span className={`h-1.5 w-full rounded-full ${color} ${i === step ? "ring-2 ring-brand/30 ring-offset-1" : ""}`} />
                </button>
              </li>
            );
          })}
        </ol>
      </nav>

      {/* Desktop: vertical list */}
      <nav aria-label="Submission steps" className="hidden lg:block">
        <ol className="sticky top-6 space-y-0.5">
          {STEP_TITLES.map((title, i) => {
            const state = i < SECTIONS.length ? states[i] : "upload";
            const current = i === step;
            return (
              <li key={title}>
                <button
                  type="button"
                  onClick={() => onSelect(i)}
                  aria-current={current ? "step" : undefined}
                  className={`flex w-full items-center gap-3 rounded-md px-2.5 py-2 text-left transition-colors ${
                    current ? "bg-white shadow-[0_0_0_1px_rgb(226_232_240)]" : "hover:bg-slate-100"
                  }`}
                >
                  <StepIndicator index={i} state={state} current={current} />
                  <span className="min-w-0">
                    <span className={`block truncate text-[13px] ${current ? "font-semibold text-slate-900" : "font-medium text-slate-700"}`}>{title}</span>
                    <span className="block text-[11px] text-slate-500">{state === "upload" ? "Source & confirmation" : STATE_TEXT[state]}</span>
                  </span>
                </button>
              </li>
            );
          })}
        </ol>
      </nav>
    </>
  );
}

/* ------------------------------------------------------------------ question rendering */

const inputBase =
  "block w-full rounded-md border bg-white px-3 text-sm text-slate-900 shadow-sm placeholder:text-slate-400 focus:border-brand focus:outline-none focus:ring-2 focus:ring-brand/20";

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
  const border = error ? "border-sev-critical" : "border-slate-300";
  const isChoice = q.kind === "select" || q.kind === "multi";

  const label = (
    <div className="mb-2 flex items-baseline justify-between gap-3">
      {isChoice ? (
        <span id={labelId} className="text-sm font-medium text-slate-900">
          {q.label}
        </span>
      ) : (
        <label id={labelId} htmlFor={inputId} className="text-sm font-medium text-slate-900">
          {q.label}
        </label>
      )}
      {!q.required && <span className="shrink-0 text-xs text-slate-500">Optional</span>}
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
        className={`${inputBase} ${border} h-9 sm:max-w-md`}
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
        className={`${inputBase} ${border} resize-y py-2 leading-6`}
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
    const twoCol = options.length > 6;
    control = (
      <div
        role={q.kind === "select" ? "radiogroup" : "group"}
        aria-labelledby={labelId}
        aria-describedby={describedBy}
        aria-required={q.kind === "select" && q.required ? true : undefined}
        aria-invalid={q.kind === "select" && error ? true : undefined}
        className={`grid gap-1.5 ${twoCol ? "md:grid-cols-2" : ""}`}
      >
        {options.map((o, i) => {
          const checked = selected.includes(o.value);
          return (
            <label
              key={o.value}
              className={`flex cursor-pointer items-start gap-3 rounded-md border px-3 py-2.5 text-sm transition-colors has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-1 has-[:focus-visible]:outline-brand ${
                checked
                  ? "border-brand bg-brand-soft text-slate-900"
                  : `${error ? "border-sev-critical/50" : "border-slate-200"} bg-white text-slate-700 hover:border-slate-300 hover:bg-slate-50`
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
                  className={`mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full border bg-white ${checked ? "border-brand" : "border-slate-400"}`}
                >
                  {checked && <span className="size-2 rounded-full bg-brand" />}
                </span>
              ) : (
                <span
                  aria-hidden="true"
                  className={`mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-[3px] border ${
                    checked ? "border-brand bg-brand text-white" : "border-slate-400 bg-white"
                  }`}
                >
                  {checked && <CheckIcon size={12} strokeWidth={2.25} />}
                </span>
              )}
              <span className="leading-5">{o.label}</span>
            </label>
          );
        })}
      </div>
    );
  }

  return (
    <div id={`field-${q.id}`} className="scroll-mt-24 px-4 py-4 sm:px-6">
      {label}
      {q.help && (
        <p id={helpId} className="-mt-1 mb-2 text-[13px] text-slate-500">
          {q.help}
        </p>
      )}
      {control}
      {error && (
        <p id={errorId} className="mt-1.5 flex items-center gap-1.5 text-[13px] font-medium text-sev-critical">
          <AlertIcon size={14} />
          {error === "Required" ? (isChoice ? "Select an option." : "This field is required.") : error}
        </p>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ upload step */

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
  const limitNote =
    probe.status === "ok"
      ? probe.info.mode === "inline"
        ? `Demo storage: files up to ${formatBytes(probe.info.maxBytes)} are accepted.`
        : `Uploaded directly to private storage · up to ${formatBytes(MAX_UPLOAD_BYTES)}.`
      : `.zip archive or a single source file · up to ${formatBytes(MAX_UPLOAD_BYTES)}.`;

  return (
    <div className="space-y-6 px-4 py-5 sm:px-6">
      {/* File */}
      <section aria-labelledby="file-heading">
        <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
          <h3 id="file-heading" className="text-sm font-medium text-slate-900">
            Application source
          </h3>
          <button
            type="button"
            onClick={props.onDemo}
            disabled={demoLoading}
            className="inline-flex items-center gap-1.5 text-[13px] font-medium text-brand hover:text-brand-strong hover:underline disabled:text-slate-400 disabled:no-underline"
          >
            {demoLoading && <SpinnerIcon size={13} />}
            Use demo application
          </button>
        </div>

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
          className={`rounded-md border border-dashed px-4 py-6 text-center transition-colors ${
            dragging ? "border-brand bg-brand-soft" : fileError ? "border-sev-critical/60 bg-white" : "border-slate-300 bg-slate-50/60"
          }`}
        >
          <UploadIcon size={22} className="mx-auto text-slate-500" />
          <p className="mt-2 text-sm text-slate-700">
            Drag and drop a file here, or{" "}
            <label className="cursor-pointer rounded-sm font-medium text-brand underline-offset-2 hover:underline has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-brand">
              browse
              <input
                ref={fileInputRef}
                id="file-input"
                type="file"
                accept={ACCEPT}
                className="sr-only"
                aria-describedby={fileError ? "file-error" : undefined}
                onChange={(e) => {
                  props.onSelectFile(e.target.files?.[0] ?? null);
                  e.target.value = "";
                }}
              />
            </label>
          </p>
          <p className="mt-1 text-xs text-slate-500">{limitNote}</p>
        </div>

        {file && (
          <div className="mt-3 flex items-center gap-3 rounded-md border border-slate-200 bg-white px-3 py-2.5">
            <span className="flex size-8 shrink-0 items-center justify-center rounded border border-slate-200 bg-slate-50 text-slate-500">
              {/\.zip$/i.test(file.name) ? <ArchiveIcon size={16} /> : <FileIcon size={16} />}
            </span>
            <div className="min-w-0 flex-1">
              <div className="truncate font-mono text-[13px] text-slate-900">{file.name}</div>
              <div className="tabular flex items-center gap-1.5 text-xs text-slate-500">
                {formatBytes(file.size)}
                {probe.status === "checking" && (
                  <>
                    <span aria-hidden="true">·</span>
                    <SpinnerIcon size={11} /> Checking upload target
                  </>
                )}
                {probe.status === "ok" && !fileError && (
                  <>
                    <span aria-hidden="true">·</span>
                    <span className="text-ok">Ready</span>
                  </>
                )}
              </div>
            </div>
            <button type="button" onClick={() => props.onSelectFile(null)} className={`${btn.ghost} h-8 w-8 px-0`} aria-label={`Remove ${file.name}`}>
              <XIcon size={16} />
            </button>
          </div>
        )}
        {(fileError || probe.status === "error") && (
          <p id="file-error" className="mt-2 flex items-center gap-1.5 text-[13px] font-medium text-sev-critical" role="alert">
            <AlertIcon size={14} />
            {fileError ?? (probe.status === "error" ? probe.message : "")}
          </p>
        )}
        {!answeredAny && (
          <p className="mt-3 text-[13px] text-slate-600">
            Using the demo application?{" "}
            <button type="button" onClick={props.onFillExample} className="font-medium text-brand hover:underline">
              Fill the questionnaire with example answers
            </button>
            .
          </p>
        )}
      </section>

      {/* Summary */}
      <section aria-labelledby="summary-heading">
        <h3 id="summary-heading" className="mb-2 text-sm font-medium text-slate-900">
          Review your answers
        </h3>
        {incomplete.length > 0 && (
          <div className="mb-3 rounded-md border border-amber-200 bg-amber-50 px-3 py-2.5 text-[13px] text-amber-900">
            <p className="font-medium">
              {incomplete.length === 1 ? "1 section is incomplete" : `${incomplete.length} sections are incomplete`}
            </p>
            <ul className="mt-1 flex flex-wrap gap-x-4 gap-y-1">
              {incomplete.map((s) => (
                <li key={s.id}>
                  <button
                    type="button"
                    onClick={() => props.onEdit(SECTIONS.indexOf(s))}
                    className="inline-flex items-center gap-0.5 font-medium underline underline-offset-2 hover:text-amber-950"
                  >
                    {s.title}
                    <ChevronRightIcon size={13} />
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}
        <div className="divide-y divide-slate-200 rounded-md border border-slate-200">
          {SECTIONS.map((s, i) => {
            const qs = s.questions.filter((q) => isVisible(q, answers));
            const answered = qs.filter((q) => hasValue(answers[q.id])).length;
            const complete = stepStates[i] === "complete";
            return (
              <details key={s.id} className="group">
                <summary className="flex items-center gap-3 px-3 py-2.5 hover:bg-slate-50">
                  <ChevronRightIcon size={14} className="shrink-0 text-slate-400 transition-transform group-open:rotate-90" />
                  <span className="min-w-0 flex-1 truncate text-[13px] font-medium text-slate-800">{s.title}</span>
                  <span className="tabular text-xs text-slate-500">
                    {answered}/{qs.length}
                  </span>
                  {complete ? (
                    <span className="inline-flex items-center gap-1 text-xs font-medium text-ok">
                      <CheckIcon size={13} strokeWidth={2} /> Complete
                    </span>
                  ) : (
                    <span className="text-xs font-medium text-warn">Incomplete</span>
                  )}
                </summary>
                <div className="border-t border-slate-100 bg-slate-50/50 px-3 py-3 sm:pl-9">
                  <dl className="grid gap-x-6 gap-y-2.5 text-[13px] sm:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
                    {qs.map((q) => (
                      <div key={q.id} className="contents">
                        <dt className="text-slate-500">{q.label}</dt>
                        <dd className="break-words text-slate-900">
                          {hasValue(answers[q.id]) ? answerLabel(q.id, answers[q.id]) : <span className="text-slate-400">Not answered</span>}
                        </dd>
                      </div>
                    ))}
                  </dl>
                  <button type="button" onClick={() => props.onEdit(i)} className="mt-3 text-[13px] font-medium text-brand hover:underline">
                    Edit section
                  </button>
                </div>
              </details>
            );
          })}
        </div>
      </section>

      {/* Confirmation */}
      <div>
        <label className="flex cursor-pointer items-start gap-3 text-sm text-slate-800">
          <input
            type="checkbox"
            checked={props.confirmed}
            onChange={(e) => props.onConfirm(e.target.checked)}
            aria-invalid={props.confirmError ? true : undefined}
            aria-describedby={props.confirmError ? "confirm-error" : undefined}
            className="mt-0.5 size-4 shrink-0 accent-brand"
          />
          <span>I confirm the information is accurate and I am authorised to submit this asset.</span>
        </label>
        {props.confirmError && (
          <p id="confirm-error" className="mt-1.5 pl-7 text-[13px] font-medium text-sev-critical">
            Confirm the statement above to continue.
          </p>
        )}
      </div>
    </div>
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
    <div className="mx-auto max-w-2xl">
      <Card labelledBy="scan-title" className="overflow-hidden">
        <div className="relative h-1 overflow-hidden bg-slate-100" aria-hidden="true">
          {done ? <div className="absolute inset-0 bg-brand" /> : <div className="absolute inset-y-0 left-0 w-2/5 animate-indeterminate bg-brand" />}
        </div>
        <div className="border-b border-slate-200 px-5 py-4 sm:px-6">
          <h1 id="scan-title" className="text-lg font-semibold tracking-tight text-slate-900">
            {done ? "Scan complete" : `Scanning ${assetName}`}
          </h1>
          <p className="mt-1 text-sm text-slate-600">
            {done ? "Opening the report…" : "The asset is being analysed. This usually takes 5–40 seconds — keep this tab open."}
          </p>
          {file && (
            <p className="mt-2 flex items-center gap-2 text-xs text-slate-500">
              <FileIcon size={13} />
              <span className="truncate font-mono">{file.name}</span>
              <span className="tabular">· {formatBytes(file.size)}</span>
            </p>
          )}
        </div>
        <ol className="px-5 py-3 sm:px-6" aria-label="Scan progress">
          {SCAN_STEPS.map((label, i) => {
            const state = i < active ? "done" : i === active ? "active" : "pending";
            return (
              <li key={label} className="flex items-center gap-3 py-1.5">
                <span className="flex size-5 shrink-0 items-center justify-center">
                  {state === "done" ? (
                    <span className="flex size-4 items-center justify-center rounded-full bg-brand text-white">
                      <CheckIcon size={11} strokeWidth={2.5} />
                    </span>
                  ) : state === "active" ? (
                    <SpinnerIcon size={16} className="text-brand" />
                  ) : (
                    <span className="size-2 rounded-full bg-slate-300" />
                  )}
                </span>
                <span
                  className={`text-sm ${state === "done" ? "text-slate-600" : state === "active" ? "font-medium text-slate-900" : "text-slate-400"}`}
                >
                  {label}
                </span>
                <span className="sr-only">{state === "done" ? "(done)" : state === "active" ? "(in progress)" : "(pending)"}</span>
              </li>
            );
          })}
        </ol>
        <div className="flex items-center justify-between border-t border-slate-200 bg-slate-50/60 px-5 py-2.5 text-xs text-slate-500 sm:px-6">
          <span>Step timing is indicative; all scanners run in one server job.</span>
          <span className="tabular font-mono" aria-label={`Elapsed time ${elapsed}`}>
            {elapsed}
          </span>
        </div>
        <p className="sr-only" aria-live="polite">
          {done ? "Scan complete. Opening the report." : SCAN_STEPS[Math.min(active, SCAN_STEPS.length - 1)]}
        </p>
      </Card>
    </div>
  );
}
