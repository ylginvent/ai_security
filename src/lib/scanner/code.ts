import { COMMENT_LINE, snippetOf, splitLines, type Archive, type RawFinding, type ScannerResult, type SourceFile } from "./archive";
import { AI_RULES, GUARDRAIL, JS, LLM_CALL, LLM_SDK_IMPORT, PY, SAST_RULES, TOKEN_LIMIT, type Rule } from "./rules";

const MAX_HITS_PER_RULE = 25;
const MAX_LINE = 4000;

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

const SECRET_VALUE = /((?:password|passwd|api[ _-]?key|secret|token|credentials?)\b\s*(?:is|=|:)\s*["']?)([^\s"']{4})[^\s"']*/gi;

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
        const m = c.line.exec(line);
        if (!m || (c.rule.unless && c.rule.unless.test(line))) continue;
        if (c.hits.length >= MAX_HITS_PER_RULE) {
          c.extra++;
          continue;
        }
        const r = c.rule;
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
          snippet: snippetOf(r.maskSnippet ? line.replace(SECRET_VALUE, "$1$2****") : line),
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

function codeFiles(archive: Archive): SourceFile[] {
  return archive.files.filter((f) => f.text !== undefined && CODE_EXTS.has(f.ext));
}

/* ------------------------------------------------------------------------ SAST */

export function scanSast(archive: Archive): ScannerResult {
  const files = codeFiles(archive);
  if (!files.length) return { findings: [], status: "skipped", note: "No Python or JavaScript/TypeScript source files found." };
  return { findings: runRules(archive.files, SAST_RULES) };
}

/* -------------------------------------------------------------------- AI / LLM */

/** Bestanden die een LLM aanroepen zonder ergens een output-token limiet te zetten (LLM10). */
function missingTokenLimits(files: SourceFile[]): RawFinding[] {
  const out: RawFinding[] = [];
  for (const f of files) {
    const text = f.text ?? "";
    if (!LLM_CALL.test(text) || TOKEN_LIMIT.test(text)) continue;
    const lines = splitLines(text);
    const idx = lines.findIndex((l) => !COMMENT_LINE.test(l) && LLM_CALL.test(l));
    if (idx < 0) continue;
    out.push({
      scanner: "ai",
      ruleId: "ai-no-output-token-limit",
      severity: "low",
      title: "LLM call without an output token limit",
      description: "This file calls a language model but never sets max_tokens (or an equivalent). Without a cap, a single prompt — or a prompt-injected loop — can produce very long completions, driving up cost and latency and making denial-of-wallet attacks easy.",
      remediation: "Set max_tokens / max_completion_tokens on every call (or on the client), and enforce per-user rate limits and token quotas, for example with Azure API Management's azure-openai-token-limit policy.",
      refs: ["OWASP LLM10:2025", "CWE-770"],
      file: f.path,
      line: idx + 1,
      snippet: snippetOf(lines[idx]),
    });
  }
  return out;
}

const MANIFEST = /(?:^|\/)(?:requirements[^/]*\.txt|pyproject\.toml|Pipfile|setup\.py|setup\.cfg|package\.json|[^/]+\.csproj|pom\.xml|go\.mod)$/i;
const MANIFEST_SDK = /^\s*["']?(openai|anthropic|langchain[\w-]*|llama[-_]index[\w-]*|semantic[-_]kernel|azure-ai-inference|azure-ai-openai|@anthropic-ai\/sdk|@azure\/openai|@langchain\/[\w-]+|@ai-sdk\/[\w-]+|Microsoft\.SemanticKernel|Azure\.AI\.OpenAI)["']?\s*(?:[=<>~!:;\[]|$)/gim;

/** Repo-niveau: gebruikt de app een LLM-SDK maar nergens een guardrail / content-safety laag? */
function missingGuardrails(archive: Archive): RawFinding[] {
  const sdks = new Set<string>();
  let guarded = false;
  for (const f of archive.files) {
    const text = f.text;
    if (text === undefined) continue;
    const isCode = CODE_EXTS.has(f.ext) || f.ext === ".cs";
    const isManifest = MANIFEST.test(f.path);
    if (!isCode && !isManifest) continue;
    if (GUARDRAIL.test(text)) guarded = true;
    const re = isManifest ? MANIFEST_SDK : LLM_SDK_IMPORT;
    for (const m of text.matchAll(re)) {
      const name = m.slice(1).find((x) => x !== undefined);
      if (name) sdks.add(name.split(".")[0].toLowerCase().replace(/_/g, "-"));
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
      description: `The application uses LLM SDKs (${list}) but no reference to a guardrail or content-safety layer was found (Azure AI Content Safety / Prompt Shields, NeMo Guardrails, Guardrails AI, LLM Guard, Presidio, moderation endpoints). Direct and indirect prompt injection, jailbreaks and harmful output are therefore only mitigated by the model's own alignment.`,
      remediation: "Screen user prompts and retrieved documents with Azure AI Content Safety Prompt Shields, keep the Azure OpenAI content filters enabled, and validate model output before it is shown or acted upon. Document the guardrail design in the questionnaire.",
      refs: ["OWASP LLM01:2025", "OWASP LLM05:2025", "MITRE ATLAS AML.T0051"],
    },
  ];
}

export function scanAi(archive: Archive): ScannerResult {
  const files = codeFiles(archive);
  const findings = [...runRules(archive.files, AI_RULES), ...missingTokenLimits(files), ...missingGuardrails(archive)];
  return { findings };
}
