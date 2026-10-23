import { answerLabel, isSkill } from "./questionnaire";
import type { Answers, Finding, Severity } from "./types";

/**
 * Vergelijkt de antwoorden uit de intake met wat de scan in de code vond.
 * Een tegenstrijdigheid is zelf een risico: de reviewer kan de rest van de antwoorden dan minder vertrouwen.
 */

interface Rule {
  id: string;
  severity: Severity;
  /** Antwoord dat de bewering bevat. */
  question: string;
  claims: (a: Answers) => boolean;
  evidence: (f: Finding) => boolean;
  title: string;
  why: string;
  remediation: string;
  refs: string[];
}

const has = (a: Answers, id: string, v: string) => (Array.isArray(a[id]) ? (a[id] as string[]).includes(v) : a[id] === v);
const rule = (...ids: string[]) => (f: Finding) => ids.some((id) => f.ruleId === id || f.ruleId.startsWith(`${id}-`));

const RULES: Rule[] = [
  {
    id: "external-ai",
    severity: "high",
    question: "data_flows",
    claims: (a) => Array.isArray(a.data_flows) && !has(a, "data_flows", "external_ai"),
    evidence: rule("ai-public-llm-endpoint"),
    title: "Answers say no external AI provider is used, but the code calls one",
    why: "The intake does not list data flowing to an external AI API, yet the code sends prompts to a public AI endpoint. Data may leave the Capgemini tenant without the controls the answers imply.",
    remediation: "Either switch the code to the tenant-hosted model (Azure OpenAI / AI Foundry) or update the data-flow answer and complete the related checks.",
    refs: ["OWASP LLM02:2025", "GDPR Chapter V"],
  },
  {
    id: "secrets",
    severity: "medium",
    question: "secrets_mgmt",
    claims: (a) => a.secrets_mgmt === "managed_identity" || a.secrets_mgmt === "key_vault",
    evidence: (f) => f.scanner === "secrets" && (f.severity === "critical" || f.severity === "high"),
    title: "Answers say secrets are kept in Key Vault or a managed identity, but credentials were found in the code",
    why: "The intake says no keys are stored in the code, but the secret scanner found hard-coded credentials in the upload.",
    remediation: "Revoke and replace (rotate) the exposed credentials, remove them from the code and the Git history, and load them from Key Vault or use a managed identity, as your answer states.",
    refs: ["CWE-798"],
  },
  {
    id: "agency",
    severity: "high",
    question: "agency",
    // Alles behalve "code_exec" (ook write_tools) sluit uitvoeren van door het model gegenereerde code uit
    claims: (a) => !has(a, "agency", "code_exec"),
    // allow_dangerous_deserialization (FAISS.load_local e.d.) is een laadrisico, geen agency: niet als bewijs tellen
    evidence: (f) =>
      rule("ai-code-execution-tool", "ai-llm-output-execution")(f) || (f.ruleId === "ai-dangerous-langchain-flag" && !/deserializ/i.test(f.title)),
    title: "Answers say the AI cannot execute code, but the code lets it run code or commands",
    why: "The intake does not declare code execution, but the code lets the model run generated code, shell commands or free-form queries. A prompt injection can then run commands with the application's permissions.",
    remediation: "Remove the execution capability or run it in an isolated sandbox without credentials or network access. If the capability is intended, change the agency answer to code execution so the right controls are assessed.",
    refs: ["OWASP LLM06:2025", "OWASP LLM05:2025"],
  },
  {
    id: "model-format",
    severity: "medium",
    question: "model_format",
    claims: (a) => a.model_format === "safe" || a.model_format === "na",
    evidence: (f) => f.scanner === "model" && f.ruleId.startsWith("pickle"),
    title: "Answers say no pickle-based model files are shipped, but they were found",
    why: "The intake declares safe formats only, but the upload contains pickle-based model files that can execute code when loaded.",
    remediation: "Convert the weights to safetensors or ONNX, or correct the model-format answer.",
    refs: ["CWE-502", "OWASP LLM03:2025"],
  },
  {
    id: "guardrails",
    severity: "low",
    question: "guardrails",
    claims: (a) => a.guardrails === "prompt_shields" || a.guardrails === "other",
    evidence: rule("ai-no-guardrails"),
    title: "A guardrail is declared, but none was found in the code",
    why: "The intake mentions prompt-injection protection, but no guardrail or content-safety integration was detected. It may run outside this repository; please confirm.",
    remediation: "Point the reviewer to where the guardrail is configured, or add it to the application.",
    refs: ["OWASP LLM01:2025"],
  },
  {
    id: "exposure",
    severity: "medium",
    question: "exposure",
    claims: (a) => a.exposure === "internal",
    evidence: rule("ai-gradio-public-share"),
    title: "Answers say the asset is internal only, but the code opens a public share link",
    why: "The intake declares internal exposure, but the code creates a public gradio.live tunnel.",
    remediation: "Remove share=True and serve the app behind the corporate network or Entra ID.",
    refs: ["OWASP LLM10:2025"],
  },
  {
    id: "licences",
    severity: "low",
    question: "licences",
    claims: (a) => a.licences === "yes",
    evidence: rule("license-copyleft"),
    title: "Licences are marked as reviewed, but copyleft dependencies were found",
    why: "Copyleft licences can restrict how the asset is distributed to clients.",
    remediation: "Confirm the copyleft dependencies are acceptable for the intended distribution, or replace them.",
    refs: ["NIST AI RMF GOVERN 6.1"],
  },
];

export function consistencyFindings(answers: Answers, findings: Finding[]): Finding[] {
  if (isSkill(answers)) return [];
  const out: Finding[] = [];
  for (const r of RULES) {
    if (answers[r.question] === undefined || !r.claims(answers)) continue;
    // onderdrukte bevindingen (info) tellen niet als bewijs
    const hits = findings.filter((f) => f.severity !== "info" && r.evidence(f));
    if (!hits.length) continue;
    const first = hits[0];
    const where = hits
      .slice(0, 3)
      .map((f) => (f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : f.title))
      .join(", ");
    out.push({
      id: `c-${r.id}`,
      scanner: "consistency",
      ruleId: `C.${r.id}`,
      severity: r.severity,
      title: r.title,
      description: `${r.why} Your answer: “${answerLabel(r.question, answers[r.question])}”. Evidence: ${where}${hits.length > 3 ? ` and ${hits.length - 3} more` : ""}.`,
      remediation: r.remediation,
      refs: r.refs,
      file: first.file,
      line: first.line,
    });
  }
  return out;
}
