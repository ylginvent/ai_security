import { COMMENT_LINE, snippetOf, splitLines, type Archive, type RawFinding, type ScannerResult, type SourceFile } from "./archive";
import { AI_RULES, GUARDRAIL, JS, LLM_CALL, LLM_CONTEXT, LLM_SDK_IMPORT, PY, SAST_RULES, TOKEN_LIMIT, type Rule } from "./rules";

const MAX_HITS_PER_RULE = 25;
const MAX_LINE = 4000;
const SNIPPET = 160;

interface CompiledRule {
  rule: Rule;
  exts: Set<string>;
  line: RegExp;
  pre: RegExp;
  hits: RawFinding[];
  extra: number;
}

function compile(rule: Rule): CompiledRule {
  const flags = rule.pattern.flags.replace("g", "");
  return {
    rule,
    exts: new Set(rule.extensions),
    line: new RegExp(rule.pattern.source, flags),
    // Snelle check op het hele bestand; m-flag zodat ^ ook per regel werkt
    pre: new RegExp(rule.pattern.source, flags.replace("m", "") + "m"),
    hits: [],
    extra: 0,
  };
}

function fill(template: string, m: RegExpExecArray): string {
  if (!template.includes("{match}")) return template;
  let v: string = m[0];
  for (let i = 1; i < m.length; i++) {
    if (m[i] !== undefined) {
      v = m[i];
      break;
    }
  }
  v = v.trim().replace(/\s+/g, " ");
  return template.replace("{match}", v.length > 60 ? `${v.slice(0, 59)}…` : v);
}

const SECRET_VALUE = /((?:password|passwd|api[ _-]?key|secret|token|credentials?)\b\s*(?:is|=|:)\s*["']?)([^\s"']{2})[^\s"']*/gi;

/** Bekende sleutelformaten die in een snippet van een code-regel kunnen staan (bijv. OpenAI(api_key="sk-…")). */
const KNOWN_TOKEN =
  /\b(sk-(?:ant-|proj-|or-)?|AKIA|ASIA|gh[pousr]_|github_pat_|glpat-|hf_|xox[baprs]-|AIza|sb_secret_|gsk_|eyJ)[A-Za-z0-9_\-+/=.]{12,}/g;

function maskLine(line: string, maskSecrets: boolean): string {
  const t = line.replace(KNOWN_TOKEN, "$1****");
  return maskSecrets ? t.replace(SECRET_VALUE, "$1$2****") : t;
}

/** Snippet rond de treffer, zodat die ook in lange regels zichtbaar is. */
function snippetAround(line: string, at: number): string {
  if (line.length <= SNIPPET) return snippetOf(line);
  const start = Math.max(0, Math.min(at - 40, line.length - (SNIPPET - 2)));
  const body = line.slice(start, start + SNIPPET - 2);
  return snippetOf(`${start > 0 ? "…" : ""}${body}${start + SNIPPET - 2 < line.length ? "…" : ""}`, SNIPPET);
}

/** Aantal nog niet gesloten haakjes vanaf `from` (voor meerregelige aanroepen). */
function openParens(line: string, from: number): number {
  let n = 0;
  for (let i = from; i < line.length; i++) {
    if (line[i] === "(") n++;
    else if (line[i] === ")") n--;
  }
  return n;
}

/** Regex-regels per regel toepassen, met een cap van 25 treffers per regel. */
export function runRules(files: SourceFile[], rules: Rule[]): RawFinding[] {
  const compiled = rules.map(compile);
  for (const file of files) {
    const text = file.text;
    if (text === undefined || text === "") continue;
    const active = compiled.filter((c) => c.exts.has(file.ext) && (!c.rule.appliesTo || c.rule.appliesTo(file)) && c.pre.test(text));
    if (!active.length) continue;
    const lines = splitLines(text);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > MAX_LINE || COMMENT_LINE.test(line)) continue;
      for (const c of active) {
        const r = c.rule;
        const m = c.line.exec(line);
        if (!m) continue;
        if (r.requires && !r.requires.test(line)) continue;
        if (r.unless) {
          if (r.unless.test(line)) continue;
          // meerregelige aanroep: de uitzondering (bijv. weights_only=True) kan op de volgende regels staan
          if (r.unlessLines && openParens(line, m.index) > 0) {
            const window = lines.slice(i + 1, i + 1 + r.unlessLines).join("\n");
            if (r.unless.test(window)) continue;
          }
        }
        if (c.hits.length >= MAX_HITS_PER_RULE) {
          c.extra++;
          continue;
        }
        const shown = maskLine(line, r.maskSnippet === true);
        const lead = line.length - line.trimStart().length;
        c.hits.push({
          scanner: r.scanner,
          ruleId: r.id,
          severity: r.severity,
          title: fill(r.title, m),
          description: fill(r.description, m),
          remediation: r.remediation,
          refs: r.refs,
          file: file.path,
          line: i + 1,
          snippet: snippetAround(shown.trim(), Math.max(0, Math.min(m.index, shown.length) - lead)),
        });
      }
    }
  }

  const out: RawFinding[] = [];
  for (const c of compiled) {
    if (c.extra > 0 && c.hits.length) {
      const last = c.hits[c.hits.length - 1];
      last.description += ` (+${c.extra} more occurrence${c.extra === 1 ? "" : "s"} of this pattern not listed individually.)`;
    }
    out.push(...c.hits);
  }
  return out;
}

const CODE_EXTS = new Set([...PY, ...JS]);

/**
 * Meegeleverde bibliotheken, bundels en type-declaraties: geen eigen code van de indiener, en
 * minified/gebundelde code geeft veel valse treffers (eval, innerHTML in jQuery …).
 */
const VENDORED =
  /(?:^|\/)(?:vendors?|third[_-]?party|bower_components|jspm_packages|wwwroot\/lib)\/|\.min\.[cm]?js$|[.-](?:bundle|chunk)\.[cm]?js$|\.d\.[cm]?ts$/i;

function ownCode(archive: Archive): SourceFile[] {
  return archive.files.filter((f) => !VENDORED.test(f.path));
}

function codeFiles(archive: Archive): SourceFile[] {
  return ownCode(archive).filter((f) => f.text !== undefined && CODE_EXTS.has(f.ext));
}

/* ------------------------------------------------------------------------ SAST */

export function scanSast(archive: Archive): ScannerResult {
  const files = codeFiles(archive);
  if (!files.length) return { findings: [], status: "skipped", note: "No Python or JavaScript/TypeScript source files found." };
  return { findings: runRules(ownCode(archive), SAST_RULES) };
}

/* -------------------------------------------------------------------- AI / LLM */

/** Bestanden die een LLM aanroepen zonder ergens een output-token limiet te zetten (LLM10). */
function missingTokenLimits(files: SourceFile[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (const f of files) {
    const text = f.text ?? "";
    if (!LLM_CALL.test(text) || TOKEN_LIMIT.test(text) || !LLM_CONTEXT.test(text)) continue;
    const lines = splitLines(text);
    const idx = lines.findIndex((l) => !COMMENT_LINE.test(l) && LLM_CALL.test(l));
    if (idx < 0) continue;
    out.push({
      scanner: "ai",
      ruleId: "ai-no-output-token-limit",
      severity: "low",
      title: "LLM call without an output token limit",
      description: "This file calls a language model but never sets max_tokens (or an equivalent). Without a cap, a single prompt — or a prompt-injected loop — can produce very long answers, driving up cost and latency and making \"denial-of-wallet\" attacks easy.",
      remediation: "Set a limit on every call or on the client, e.g. client.chat.completions.create(..., max_tokens=800) / max_completion_tokens (OpenAI, Azure OpenAI), ChatOpenAI(max_tokens=800) (LangChain) or generateText({ ..., maxTokens: 800 }) (Vercel AI SDK). Also enforce per-user rate limits and token quotas, for example with Azure API Management's azure-openai-token-limit policy.",
      refs: ["OWASP LLM10:2025", "CWE-770"],
      file: f.path,
      line: idx + 1,
      snippet: snippetOf(maskLine(lines[idx], false)),
    });
  }
  return out;
}

const MANIFEST = /(?:^|\/)(?:requirements[^/]*\.txt|pyproject\.toml|Pipfile|setup\.py|setup\.cfg|package\.json|[^/]+\.csproj|pom\.xml|go\.mod)$/i;
const MANIFEST_SDK =
  /^\s*["']?(openai|anthropic|langchain[\w-]*|llama[-_]index[\w-]*|semantic[-_]kernel|azure-ai-inference|azure-ai-openai|litellm|ollama|groq|groq-sdk|mistralai|cohere|crewai|pyautogen|autogen[\w-]*|smolagents|pydantic-ai|google-generativeai|google-genai|@anthropic-ai\/sdk|@azure\/openai|@langchain\/[\w-]+|@ai-sdk\/[\w-]+|@google\/generative-ai|@google\/genai|@mistralai\/mistralai|Microsoft\.SemanticKernel|Azure\.AI\.OpenAI)["']?\s*(?:[=<>~!:;\[]|$)/gim;

/** Guardrail-verwijzing in code die geen commentaar is ("# TODO: add guardrails" telt niet). */
function hasGuardrail(text: string, isManifest: boolean): boolean {
  if (!GUARDRAIL.test(text)) return false;
  if (isManifest) return true;
  return splitLines(text).some((l) => !COMMENT_LINE.test(l) && GUARDRAIL.test(l));
}

/** Repo-niveau: gebruikt de app een LLM-SDK maar nergens een guardrail / content-safety laag? */
function missingGuardrails(archive: Archive): RawFinding[] {
  const sdks = new Set<string>();
  let guarded = false;
  for (const f of ownCode(archive)) {
    const text = f.text;
    if (text === undefined) continue;
    const isCode = CODE_EXTS.has(f.ext) || f.ext === ".cs";
    const isManifest = MANIFEST.test(f.path);
    if (!isCode && !isManifest) continue;
    if (!guarded && hasGuardrail(text, isManifest)) guarded = true;
    const re = isManifest ? MANIFEST_SDK : LLM_SDK_IMPORT;
    for (const m of text.matchAll(re)) {
      const name = m.slice(1).find((x) => x !== undefined);
      if (!name) continue;
      // Python-modules ("langchain.chat_models") op topniveau; npm-scopes en .NET-namespaces heel laten
      const short = name.includes("/") || /^[A-Z]/.test(name) ? name : name.split(".")[0];
      sdks.add(short.toLowerCase().replace(/_/g, "-"));
    }
  }
  if (!sdks.size || guarded) return [];
  const list = Array.from(sdks).sort().slice(0, 8).join(", ");
  return [
    {
      scanner: "ai",
      ruleId: "ai-no-guardrails",
      severity: "medium",
      title: "No prompt-injection or content-safety guardrail detected",
      description: `The application uses LLM SDKs (${list}) but no guardrail or content-safety layer was found in the code or dependencies (Azure AI Content Safety / Prompt Shields, NeMo Guardrails, Guardrails AI, LLM Guard, Llama Guard, Presidio, moderation endpoints). Prompt injection, jailbreaks and harmful output are then only held back by the model's own training.`,
      remediation: "Screen user prompts and retrieved documents before they reach the model, e.g. with Azure AI Content Safety Prompt Shields (azure-ai-contentsafety: ContentSafetyClient → shieldPrompt), keep the Azure OpenAI content filters enabled, and validate model output before it is shown or acted upon. If the guardrail is applied outside this code (e.g. Azure API Management or the Azure OpenAI deployment's content filter), say so in the questionnaire.",
      refs: ["OWASP LLM01:2025", "OWASP LLM05:2025", "MITRE ATLAS AML.T0051"],
    },
  ];
}

export function scanAi(archive: Archive): ScannerResult {
  const files = codeFiles(archive);
  const findings = [...runRules(ownCode(archive), AI_RULES), ...missingTokenLimits(files), ...missingGuardrails(archive)];
  return { findings };
}
