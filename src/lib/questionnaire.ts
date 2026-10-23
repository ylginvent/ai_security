import type { AiActTier, Answers, Finding, Severity } from "./types";

/**
 * Intake-vragenlijst voor AI-assets. Opgebouwd uit:
 * - NIST AI RMF 1.0 (Govern / Map / Measure / Manage)
 * - ISO/IEC 42001 (AI management system) en ISO/IEC 23894 (AI risk)
 * - EU AI Act (Art. 5 verboden praktijken, Annex III hoog risico, Art. 50 transparantie)
 * - OWASP Top 10 for LLM Applications 2025 en OWASP AI Exchange
 * - GDPR (Art. 9 bijzondere persoonsgegevens, Art. 22 geautomatiseerde besluiten, Art. 35 DPIA)
 * - MITRE ATLAS
 * Iedere optie kan een bevinding opleveren die in het rapport en de gate meetelt.
 */

export interface QFinding {
  severity: Severity;
  title: string;
  detail: string;
  remediation: string;
  refs: string[];
}

export interface QOption {
  value: string;
  label: string;
  finding?: QFinding;
}

export interface Question {
  id: string;
  label: string;
  help?: string;
  kind: "text" | "email" | "textarea" | "select" | "multi";
  options?: QOption[];
  required?: boolean;
  placeholder?: string;
  showIf?: (a: Answers) => boolean;
}

export interface Section {
  id: string;
  title: string;
  intro: string;
  framework: string;
  questions: Question[];
}

const has = (a: Answers, id: string, value: string) => {
  const v = a[id];
  return Array.isArray(v) ? v.includes(value) : v === value;
};
const usesLlm = (a: Answers) =>
  ["llm_app", "rag", "agent"].includes(String(a.asset_type ?? "")) ||
  (Array.isArray(a.model_provider) && a.model_provider.some((p) => p !== "none" && p !== "inhouse_ml"));

export const SECTIONS: Section[] = [
  {
    id: "asset",
    title: "Asset & ownership",
    intro: "Who owns this asset and what is it? Every catalogue item needs an accountable owner.",
    framework: "NIST AI RMF · GOVERN 2 / MAP 1",
    questions: [
      { id: "asset_name", label: "Asset name", kind: "text", required: true, placeholder: "e.g. Contract Clause Assistant" },
      { id: "asset_version", label: "Version", kind: "text", placeholder: "e.g. 1.2.0" },
      {
        id: "owner_name",
        label: "Accountable owner",
        help: "The person who answers for this asset and fixes the findings. Usually the product owner or tech lead, not the submitter's manager.",
        kind: "text",
        required: true,
        placeholder: "Full name",
      },
      { id: "owner_email", label: "Owner e-mail", kind: "email", required: true, placeholder: "firstname.lastname@capgemini.com" },
      {
        id: "business_unit",
        label: "Business unit",
        kind: "select",
        required: true,
        options: [
          { value: "invent", label: "Capgemini Invent" },
          { value: "ind", label: "Insights & Data" },
          { value: "cis", label: "Cloud Infrastructure Services" },
          { value: "apps", label: "Applications & Technology" },
          { value: "er&d", label: "Engineering & R&D" },
          { value: "fs", label: "Financial Services" },
          { value: "other", label: "Other" },
        ],
      },
      { id: "description", label: "What does the asset do?", kind: "textarea", required: true, placeholder: "Purpose, users, inputs and outputs in 2–4 sentences." },
      {
        id: "asset_type",
        label: "Asset type",
        help: "Pick the closest match. An assistant that searches your documents is RAG; one that can call tools or APIs is agentic.",
        kind: "select",
        required: true,
        options: [
          { value: "llm_app", label: "LLM application / chatbot" },
          { value: "rag", label: "RAG / knowledge assistant" },
          { value: "agent", label: "Agentic / multi-agent system (uses tools)" },
          { value: "ml_model", label: "Classical ML model (prediction, classification)" },
          { value: "cv_speech", label: "Computer vision / speech model" },
          { value: "library", label: "AI accelerator, SDK or code library" },
          { value: "prompts", label: "Prompt library / templates" },
          { value: "skill", label: "Agent skill (SKILL.md)" },
        ],
      },
      {
        id: "lifecycle",
        label: "Maturity",
        kind: "select",
        required: true,
        options: [
          {
            value: "poc",
            label: "Proof of concept",
            finding: {
              severity: "low",
              title: "Asset is a proof of concept",
              detail: "PoC assets typically lack hardening, monitoring and support. Catalogue consumers may assume production readiness.",
              remediation: "Label the catalogue item clearly as PoC/accelerator, or harden it before publishing as a reusable product.",
              refs: ["NIST AI RMF MAP 1.1"],
            },
          },
          { value: "pilot", label: "Pilot with real users" },
          { value: "production", label: "Production-ready" },
        ],
      },
      {
        id: "intended_users",
        label: "Who will use it?",
        kind: "select",
        required: true,
        options: [
          { value: "internal", label: "Capgemini employees only" },
          { value: "client", label: "Specific client(s)" },
          { value: "multi_client", label: "Multiple clients (productised)" },
          {
            value: "public",
            label: "General public / consumers",
            finding: {
              severity: "medium",
              title: "Asset is exposed to the general public",
              detail: "Public-facing AI is a higher-value target for prompt injection, abuse and reputational incidents.",
              remediation: "Require red-teaming, abuse monitoring, rate limiting and a public AI disclosure before go-live.",
              refs: ["OWASP LLM01:2025", "OWASP LLM10:2025", "EU AI Act Art. 50"],
            },
          },
        ],
      },
    ],
  },
  {
    id: "data",
    title: "Data & privacy",
    intro: "What data goes in, where does it go and who may see it?",
    framework: "GDPR · ISO/IEC 27001 · OWASP LLM02",
    questions: [
      {
        id: "data_classification",
        label: "Highest data classification processed",
        help: "Including prompts, retrieved documents, training data and logs.",
        kind: "select",
        required: true,
        options: [
          { value: "public", label: "Public" },
          { value: "internal", label: "Internal" },
          { value: "confidential", label: "Confidential (client or commercially sensitive)" },
          {
            value: "restricted",
            label: "Restricted / secret",
            finding: {
              severity: "high",
              title: "Restricted data processed by AI asset",
              detail: "Restricted data requires explicit approval from the data owner and CISO before it may be processed by an AI system.",
              remediation: "Obtain CISO/data owner sign-off, keep processing inside the Capgemini tenant and enable full audit logging.",
              refs: ["ISO/IEC 27001 A.5.12", "OWASP LLM02:2025"],
            },
          },
        ],
      },
      {
        id: "personal_data",
        label: "Personal data",
        help: "Any information about an identifiable person, including names, e-mail addresses, employee IDs and free text that mentions people. Pseudonymised data is still personal data under GDPR; only truly anonymised data is not.",
        kind: "select",
        required: true,
        options: [
          { value: "none", label: "No personal data" },
          { value: "anonymised", label: "Anonymised only (nobody can be re-identified)" },
          { value: "pseudonymised", label: "Pseudonymised (names replaced by codes or IDs)" },
          { value: "personal", label: "Personal data (names, e-mails, HR data …)" },
          {
            value: "special",
            label: "Special categories (health, biometrics, religion, …)",
            finding: {
              severity: "high",
              title: "Special category personal data (GDPR Art. 9)",
              detail: "Processing special category data is prohibited unless an Art. 9(2) exception applies and a DPIA is completed.",
              remediation: "Complete a DPIA, document the legal basis and involve the Data Protection Officer before publication.",
              refs: ["GDPR Art. 9", "GDPR Art. 35"],
            },
          },
        ],
      },
      {
        id: "client_data",
        label: "Does it process client data?",
        help: "Documents, records or other data that belong to a client, even when it is only used in prompts or a search index.",
        kind: "select",
        required: true,
        options: [
          { value: "no", label: "No" },
          { value: "yes_contract", label: "Yes, covered by contract / client approval" },
          {
            value: "yes_unclear",
            label: "Yes, contractual position unclear",
            finding: {
              severity: "high",
              title: "Client data without a clear contractual basis",
              detail: "Client contracts often restrict use of their data with (third-party) AI services and for model training.",
              remediation: "Check the MSA/DPA with the engagement lead and Legal; obtain written client approval for AI processing.",
              refs: ["GDPR Art. 28", "NIST AI RMF GOVERN 6"],
            },
          },
        ],
      },
      {
        id: "data_flows",
        label: "Where does data flow? (select all that apply)",
        help: "Think of every place prompts, documents, outputs and logs are sent or stored. Calling the public OpenAI, Anthropic or Google API counts as external, even with a paid account.",
        kind: "multi",
        required: true,
        options: [
          { value: "tenant", label: "Stays within the Capgemini Azure tenant" },
          {
            value: "external_ai",
            label: "Sent to an external AI API (public OpenAI, Anthropic, Google, …)",
            finding: {
              severity: "medium",
              title: "Data is sent to an external AI provider",
              detail: "Prompts and context leave the Capgemini tenant. Retention, training use and jurisdiction depend on the provider's terms.",
              remediation: "Prefer Azure OpenAI / Azure AI Foundry in the Capgemini tenant, or confirm zero data retention and no-training terms.",
              refs: ["OWASP LLM02:2025", "OWASP LLM03:2025"],
            },
          },
          {
            value: "saas",
            label: "Sent to other third-party SaaS",
            finding: {
              severity: "low",
              title: "Data shared with third-party SaaS",
              detail: "Third-party processors must be assessed by procurement and security.",
              remediation: "Verify the vendor is on the approved supplier list and a DPA is in place.",
              refs: ["ISO/IEC 27001 A.5.19"],
            },
          },
          {
            value: "non_eu",
            label: "Leaves the EU/EEA",
            finding: {
              severity: "medium",
              title: "Data transfer outside the EU/EEA",
              detail: "International transfers need an adequacy decision or SCCs plus a transfer impact assessment.",
              remediation: "Deploy in EU regions (e.g. West Europe / Sweden Central) or document SCCs and a TIA.",
              refs: ["GDPR Chapter V"],
            },
          },
        ],
      },
      {
        id: "training_use",
        label: "Training / fine-tuning",
        help: "Only answer yes if you trained or fine-tuned a model yourself. Indexing documents for search (RAG) is not training.",
        kind: "select",
        required: true,
        options: [
          { value: "none", label: "No training or fine-tuning" },
          { value: "internal", label: "Fine-tuned on Capgemini internal data" },
          {
            value: "client",
            label: "Fine-tuned on client data",
            finding: {
              severity: "medium",
              title: "Model fine-tuned on client data",
              detail: "Client data can be memorised and extracted from fine-tuned models (training data extraction).",
              remediation: "Restrict reuse of the model to that client, document approval and test for memorisation/leakage.",
              refs: ["OWASP LLM02:2025", "MITRE ATLAS AML.T0024"],
            },
          },
          {
            value: "scraped",
            label: "Trained on public / scraped data",
            finding: {
              severity: "medium",
              title: "Training data from public / scraped sources",
              detail: "Risk of copyright infringement, licence violations and data poisoning.",
              remediation: "Document data provenance and licences, and validate datasets for poisoning.",
              refs: ["OWASP LLM04:2025", "EU AI Act Art. 53"],
            },
          },
        ],
      },
      {
        id: "retention",
        label: "Retention of prompts, outputs and logs",
        help: "How long is stored data kept before it is deleted? Enforced means it is deleted automatically, for example by a storage lifecycle rule.",
        kind: "select",
        required: true,
        options: [
          { value: "enforced", label: "Defined and deleted automatically" },
          { value: "defined", label: "Defined, but not deleted automatically" },
          {
            value: "undefined",
            label: "Not defined",
            finding: {
              severity: "low",
              title: "No retention policy for AI data",
              detail: "Prompts, outputs and logs may be kept indefinitely, conflicting with storage limitation.",
              remediation: "Define retention per data type and enforce it with lifecycle policies.",
              refs: ["GDPR Art. 5(1)(e)"],
            },
          },
        ],
      },
      {
        id: "dpia",
        label: "Data Protection Impact Assessment (DPIA)",
        help: "A privacy risk assessment done with the privacy office or Data Protection Officer before personal data is processed.",
        kind: "select",
        required: true,
        showIf: (a) => a.personal_data === "pseudonymised" || a.personal_data === "personal" || a.personal_data === "special",
        options: [
          { value: "done", label: "Completed" },
          { value: "in_progress", label: "In progress" },
          {
            value: "not_done",
            label: "Not done",
            finding: {
              severity: "medium",
              title: "Personal data processed without a DPIA",
              detail: "AI systems processing personal data are usually 'likely high risk' under GDPR and require a DPIA.",
              remediation: "Run a DPIA with the privacy office before publishing the asset.",
              refs: ["GDPR Art. 35"],
            },
          },
        ],
      },
    ],
  },
  {
    id: "model",
    title: "Model & supply chain",
    intro: "Which models and third-party components does the asset rely on?",
    framework: "OWASP LLM03 · LLM04 · MITRE ATLAS",
    questions: [
      {
        id: "model_provider",
        label: "Models used (select all that apply)",
        help: "Include every model the asset calls or ships, such as chat, embedding, reranking and classification models.",
        kind: "multi",
        required: true,
        options: [
          { value: "azure_openai", label: "Azure OpenAI (Capgemini tenant)" },
          { value: "foundry", label: "Azure AI Foundry model catalogue" },
          { value: "public_api", label: "Public API (OpenAI, Anthropic, Google, Mistral …)" },
          { value: "open_weights", label: "Open-weight model, self-hosted (Llama, Mistral, Phi …)" },
          { value: "huggingface", label: "Model downloaded from Hugging Face" },
          { value: "inhouse_ml", label: "In-house trained model" },
          { value: "none", label: "No ML model" },
        ],
      },
      {
        id: "model_provenance",
        label: "Are models and versions pinned and from a trusted source?",
        help: "Pinned means the code asks for one exact model version (for example a deployment version or a Hugging Face commit), so it cannot change without review.",
        kind: "select",
        required: true,
        showIf: (a) => Array.isArray(a.model_provider) && a.model_provider.some((p) => p !== "none"),
        options: [
          { value: "verified", label: "Yes, approved registry with pinned version / hash" },
          { value: "partial", label: "Partially" },
          {
            value: "no",
            label: "No",
            finding: {
              severity: "medium",
              title: "Model provenance not verified",
              detail: "Unpinned or unverified models can be swapped for poisoned or backdoored versions.",
              remediation: "Pin model versions/revisions, verify hashes and host models in an approved registry (e.g. Azure ML registry).",
              refs: ["OWASP LLM03:2025", "MITRE ATLAS AML.T0010"],
            },
          },
        ],
      },
      {
        id: "model_format",
        label: "Format of shipped model weights",
        help: "Model files included in your code or downloaded at runtime. Choose 'No model weights shipped' if you only call a hosted model through an API.",
        kind: "select",
        required: true,
        options: [
          { value: "na", label: "No model weights shipped" },
          { value: "safe", label: "Safe formats only (safetensors, ONNX, GGUF)" },
          {
            value: "pickle",
            label: "Pickle-based (.pkl, .pt, .bin, .joblib)",
            finding: {
              severity: "medium",
              title: "Pickle-based model format",
              detail: "Pickle files can execute arbitrary code when loaded.",
              remediation: "Convert weights to safetensors or ONNX; never load untrusted pickles.",
              refs: ["CWE-502", "OWASP LLM03:2025"],
            },
          },
          { value: "unknown", label: "Don't know" },
        ],
      },
      {
        id: "licences",
        label: "Have model, dataset and package licences been reviewed for commercial use?",
        help: "Some open models, datasets and libraries forbid commercial use or require you to share your source code (e.g. CC-BY-NC, GPL, AGPL).",
        kind: "select",
        required: true,
        options: [
          { value: "yes", label: "Yes" },
          {
            value: "no",
            label: "No / not sure",
            finding: {
              severity: "medium",
              title: "Licences not reviewed",
              detail: "Many open models and datasets carry non-commercial or use-restricted licences (e.g. CC-BY-NC, Llama acceptable use).",
              remediation: "Review licences of all models, datasets and dependencies before productising.",
              refs: ["NIST AI RMF GOVERN 6.1"],
            },
          },
        ],
      },
    ],
  },
  {
    id: "architecture",
    title: "Architecture & agency",
    intro: "How is the asset exposed and what is it allowed to do?",
    framework: "OWASP LLM01 · LLM06 · Zero Trust",
    questions: [
      {
        id: "exposure",
        label: "Network exposure",
        help: "Can it be reached from the internet, or only from the Capgemini network / VPN? Public demo links (e.g. Gradio or ngrok share links) count as internet-facing.",
        kind: "select",
        required: true,
        options: [
          { value: "internal", label: "Internal network / private endpoint only" },
          { value: "internet_auth", label: "Internet-facing with authentication" },
          {
            value: "internet_open",
            label: "Internet-facing without authentication",
            finding: {
              severity: "high",
              title: "Unauthenticated internet-facing AI endpoint",
              detail: "Anyone can consume the model (cost abuse, data extraction, jailbreaking).",
              remediation: "Put the endpoint behind Entra ID authentication / API Management with rate limits.",
              refs: ["OWASP LLM10:2025", "CWE-306"],
            },
          },
        ],
      },
      {
        id: "authentication",
        label: "Authentication",
        help: "How do users or calling systems prove who they are before they can use the asset?",
        kind: "select",
        required: true,
        options: [
          { value: "entra", label: "Microsoft Entra ID (SSO)" },
          { value: "api_key", label: "API keys" },
          { value: "custom", label: "Custom / other" },
          {
            value: "none",
            label: "None",
            finding: {
              severity: "high",
              title: "No authentication",
              detail: "Without authentication there is no accountability and no way to enforce access to data.",
              remediation: "Use Entra ID with managed identities for service-to-service calls.",
              refs: ["CWE-306"],
            },
          },
        ],
      },
      {
        id: "agency",
        label: "What can the AI do on its own?",
        help: "Choose the most powerful capability, without a human clicking to approve each step. Running generated Python, SQL or shell commands counts as executing code.",
        kind: "select",
        required: true,
        options: [
          { value: "text", label: "Only produce text / predictions" },
          { value: "read_tools", label: "Call read-only tools (search, retrieval)" },
          {
            value: "write_tools",
            label: "Take actions in systems (e-mail, tickets, DB writes)",
            finding: {
              severity: "medium",
              title: "AI can take actions in other systems",
              detail: "Prompt injection can turn tool access into unauthorised actions (excessive agency).",
              remediation: "Apply least privilege per tool, require human approval for impactful actions and log every tool call.",
              refs: ["OWASP LLM06:2025", "OWASP LLM01:2025"],
            },
          },
          {
            value: "code_exec",
            label: "Execute code or shell commands",
            finding: {
              severity: "high",
              title: "AI can execute code",
              detail: "LLM-generated code execution is equivalent to remote code execution if the model can be manipulated.",
              remediation: "Run code in an isolated sandbox (e.g. Azure Container Apps dynamic sessions) without network or secrets.",
              refs: ["OWASP LLM05:2025", "OWASP LLM06:2025", "CWE-94"],
            },
          },
        ],
      },
      {
        id: "rag_permissions",
        label: "Are user permissions enforced on retrieved documents?",
        help: "Can a user only get answers from documents they are allowed to open themselves? Without this, the assistant can leak documents to the wrong people.",
        kind: "select",
        required: true,
        showIf: (a) => a.asset_type === "rag" || a.asset_type === "agent",
        options: [
          { value: "enforced", label: "Yes, security trimming per user" },
          {
            value: "not_enforced",
            label: "No, all users can retrieve all indexed content",
            finding: {
              severity: "high",
              title: "No permission enforcement in retrieval",
              detail: "Users can extract documents they are not authorised to read via the assistant.",
              remediation: "Implement document-level security trimming (e.g. Azure AI Search security filters with Entra groups).",
              refs: ["OWASP LLM02:2025", "OWASP LLM08:2025"],
            },
          },
        ],
      },
      {
        id: "untrusted_content",
        label: "Does it process untrusted external content (web pages, e-mails, uploaded files)?",
        help: "Content written by someone outside your team can contain hidden instructions for the model (indirect prompt injection).",
        kind: "select",
        required: true,
        showIf: usesLlm,
        options: [
          { value: "no", label: "No" },
          {
            value: "yes",
            label: "Yes",
            finding: {
              severity: "medium",
              title: "Exposure to indirect prompt injection",
              detail: "Instructions hidden in documents, e-mails or web pages can hijack the model.",
              remediation: "Use Prompt Shields / spotlighting, separate trusted and untrusted context and restrict tool access.",
              refs: ["OWASP LLM01:2025", "MITRE ATLAS AML.T0051"],
            },
          },
        ],
      },
    ],
  },
  {
    id: "controls",
    title: "Security controls",
    intro: "Which safeguards are in place today?",
    framework: "OWASP AI Exchange · NIST AI RMF MEASURE / MANAGE",
    questions: [
      {
        id: "guardrails",
        label: "Prompt-injection / jailbreak protection",
        help: "A filter that checks prompts and retrieved content for attempts to override the model's instructions. The default Azure OpenAI content filter alone does not count.",
        kind: "select",
        required: true,
        showIf: usesLlm,
        options: [
          { value: "prompt_shields", label: "Azure AI Content Safety – Prompt Shields" },
          { value: "other", label: "Other guardrail (NeMo Guardrails, LLM Guard, …)" },
          {
            value: "none",
            label: "None",
            finding: {
              severity: "medium",
              title: "No prompt-injection protection",
              detail: "Without input screening the model is easily manipulated.",
              remediation: "Enable Azure AI Content Safety Prompt Shields or an equivalent guardrail.",
              refs: ["OWASP LLM01:2025"],
            },
          },
        ],
      },
      {
        id: "output_filtering",
        label: "Output filtering (content safety, PII redaction)",
        kind: "select",
        required: true,
        showIf: usesLlm,
        options: [
          { value: "yes", label: "Yes" },
          { value: "partial", label: "Partially" },
          {
            value: "no",
            label: "No",
            finding: {
              severity: "low",
              title: "No output filtering",
              detail: "Harmful content or personal data may be returned to users.",
              remediation: "Enable content filters and PII detection (e.g. Azure AI Language PII / Presidio) on outputs.",
              refs: ["OWASP LLM05:2025", "OWASP LLM02:2025"],
            },
          },
        ],
      },
      {
        id: "secrets_mgmt",
        label: "How are secrets and keys managed?",
        help: "API keys, passwords and connection strings. The scan checks the code for hard-coded secrets, so answer for how it really works today.",
        kind: "select",
        required: true,
        options: [
          { value: "managed_identity", label: "Managed identities (no keys)" },
          { value: "key_vault", label: "Azure Key Vault" },
          {
            value: "env",
            label: "Environment variables / pipeline secrets",
            finding: {
              severity: "low",
              title: "Secrets in environment variables",
              detail: "Acceptable for pipelines, but keys are long-lived and hard to rotate.",
              remediation: "Move to managed identities or Key Vault references.",
              refs: ["CWE-522"],
            },
          },
          {
            value: "code",
            label: "In code / config files",
            finding: {
              severity: "high",
              title: "Secrets stored in code or config",
              detail: "Secrets in source code end up in repositories, packages and the catalogue.",
              remediation: "Rotate the secrets now and move them to Key Vault / managed identities.",
              refs: ["CWE-798"],
            },
          },
        ],
      },
      {
        id: "logging",
        label: "Logging & monitoring",
        kind: "select",
        required: true,
        options: [
          { value: "full", label: "Audit logging of prompts, tool calls and admin actions, sent to SIEM" },
          { value: "basic", label: "Basic application logging" },
          {
            value: "none",
            label: "None",
            finding: {
              severity: "medium",
              title: "No logging or monitoring",
              detail: "Abuse, data leakage and incidents cannot be detected or investigated.",
              remediation: "Log to Log Analytics / Sentinel with PII-aware retention.",
              refs: ["NIST AI RMF MANAGE 4.1", "ISO/IEC 27001 A.8.15"],
            },
          },
        ],
      },
      {
        id: "rate_limiting",
        label: "Rate limiting / cost controls",
        kind: "select",
        required: true,
        showIf: usesLlm,
        options: [
          { value: "yes", label: "Yes (e.g. API Management, token quotas)" },
          {
            value: "no",
            label: "No",
            finding: {
              severity: "low",
              title: "No rate limiting or token quotas",
              detail: "Unbounded usage can lead to denial of wallet and service degradation.",
              remediation: "Add per-user rate limits and token quotas (APIM GenAI gateway policies).",
              refs: ["OWASP LLM10:2025"],
            },
          },
        ],
      },
      {
        id: "red_teaming",
        label: "Security testing / AI red-teaming",
        help: "Has someone deliberately tried to break it, for example with jailbreak prompts or an automated tool such as PyRIT, garak or promptfoo?",
        kind: "select",
        required: true,
        options: [
          { value: "done", label: "Performed (PyRIT, garak, manual red team, pentest)" },
          { value: "planned", label: "Planned" },
          {
            value: "no",
            label: "Not performed",
            finding: {
              severity: "low",
              title: "No adversarial testing performed",
              detail: "Jailbreaks, prompt injection and data leakage have not been tested.",
              remediation: "Run an automated red-team (PyRIT / garak / promptfoo) and fix the findings.",
              refs: ["NIST AI RMF MEASURE 2.7", "MITRE ATLAS"],
            },
          },
        ],
      },
      {
        id: "threat_model",
        label: "Threat model available?",
        help: "A written overview of what could go wrong (who could attack it, how, and what protects against it). A one-page document is enough.",
        kind: "select",
        required: true,
        options: [
          { value: "yes", label: "Yes" },
          {
            value: "no",
            label: "No",
            finding: {
              severity: "low",
              title: "No threat model",
              detail: "Without a threat model it is unclear which AI-specific threats were considered.",
              remediation: "Create a lightweight threat model (STRIDE + OWASP LLM Top 10 / MITRE ATLAS).",
              refs: ["NIST AI RMF MAP 5"],
            },
          },
        ],
      },
      {
        id: "incident_response",
        label: "AI incident response owner and process",
        kind: "select",
        required: true,
        options: [
          { value: "yes", label: "Defined" },
          {
            value: "no",
            label: "Not defined",
            finding: {
              severity: "low",
              title: "No AI incident response process",
              detail: "Nobody is accountable when the model misbehaves or leaks data.",
              remediation: "Name an incident owner and document how to disable the asset quickly.",
              refs: ["NIST AI RMF MANAGE 4.3", "EU AI Act Art. 73"],
            },
          },
        ],
      },
    ],
  },
  {
    id: "governance",
    title: "Governance & EU AI Act",
    intro: "Classify the use case. This determines the EU AI Act risk tier.",
    framework: "EU AI Act · Capgemini Code of Ethics for AI",
    questions: [
      {
        id: "ai_act_domains",
        label: "Is the asset intended for any of these uses? (select all that apply)",
        help: "These uses are regulated by the EU AI Act. Some are banned outright (Art. 5); the others are high risk (Annex III) and need extra approval. Most assets fall under 'None of these'.",
        kind: "multi",
        required: true,
        options: [
          { value: "none", label: "None of these" },
          // Art. 5: verboden praktijken
          { value: "social_scoring", label: "Social scoring: rating people on their behaviour or personality, leading to unfair treatment" },
          { value: "manipulation", label: "Manipulative or deceptive techniques, or exploiting age, disability or social situation, that can cause significant harm" },
          { value: "emotion_work", label: "Recognising emotions of employees or students (except for medical or safety reasons)" },
          { value: "biometric_sensitive", label: "Inferring race, political views, religion, sexual orientation or union membership from biometric data" },
          { value: "facial_scraping", label: "Building face-recognition databases by scraping images from the internet or CCTV" },
          { value: "predictive_policing", label: "Predicting whether someone will commit a crime based only on profiling or personality" },
          { value: "realtime_rbi", label: "Real-time remote biometric identification in public spaces for law enforcement" },
          // Annex III: hoog risico
          { value: "biometric", label: "Other biometric identification, categorisation or emotion recognition" },
          { value: "employment", label: "Recruitment, promotion, termination, task allocation or performance monitoring of workers" },
          { value: "education", label: "Education: admission, grading, assessing level or proctoring exams" },
          { value: "essential_services", label: "Access to essential services: credit scoring, life or health insurance pricing, public benefits, emergency triage" },
          { value: "critical_infra", label: "Safety component of critical infrastructure (energy, water, gas, heating, road traffic, digital infrastructure)" },
          { value: "law_enforcement", label: "Law enforcement, migration, asylum, border control, justice or elections" },
        ],
      },
      {
        id: "decisions_about_people",
        label: "Does the output influence decisions about individuals?",
        help: "For example who is hired, promoted, approved for a loan or flagged for an investigation.",
        kind: "select",
        required: true,
        options: [
          { value: "no", label: "No" },
          { value: "human_review", label: "Yes, always reviewed by a human" },
          {
            value: "automated",
            label: "Yes, fully automated",
            finding: {
              severity: "high",
              title: "Fully automated decisions about individuals",
              detail: "Individuals have the right not to be subject to solely automated decisions with legal or similar effects.",
              remediation: "Add meaningful human review, explanation and a contest procedure.",
              refs: ["GDPR Art. 22", "EU AI Act Art. 14"],
            },
          },
        ],
      },
      {
        // Toont zich bij acties in systemen, code-uitvoering of volledig geautomatiseerde besluiten (agency staat in "Architecture & agency").
        id: "human_oversight",
        label: "Does a human approve impactful actions or decisions?",
        help: "You see this question because the AI can take actions in other systems, run code or decide about people on its own. Human-in-the-loop means a person can check and stop the action before it takes effect.",
        kind: "select",
        required: true,
        showIf: (a) => a.agency === "write_tools" || a.agency === "code_exec" || a.decisions_about_people === "automated",
        options: [
          { value: "always", label: "Always required" },
          { value: "some", label: "For some actions" },
          {
            value: "none",
            label: "No human oversight",
            finding: {
              severity: "high",
              title: "Autonomous actions without human oversight",
              detail: "The system can act without a human able to intervene.",
              remediation: "Add approval steps for irreversible or high-impact actions and a kill switch.",
              refs: ["OWASP LLM06:2025", "EU AI Act Art. 14"],
            },
          },
        ],
      },
      {
        id: "transparency",
        label: "Are users told they interact with AI / is AI content labelled?",
        help: "For example a line in the chat window ('You are chatting with an AI assistant') or a label on generated text, images or audio.",
        kind: "select",
        required: true,
        options: [
          { value: "yes", label: "Yes" },
          { value: "na", label: "Not applicable (no end users)" },
          {
            value: "no",
            label: "No",
            finding: {
              severity: "medium",
              title: "Missing AI transparency notice",
              detail: "People interacting with AI systems must be informed, and synthetic content must be marked.",
              remediation: "Add an AI disclosure in the UI and label generated content.",
              refs: ["EU AI Act Art. 50"],
            },
          },
        ],
      },
      {
        id: "documentation",
        label: "Model / system card documenting purpose, limitations and evaluation",
        help: "A short document (or README section) that tells others what the asset is for, what it should not be used for, and how well it performs.",
        kind: "select",
        required: true,
        options: [
          { value: "yes", label: "Yes" },
          {
            value: "no",
            label: "No",
            finding: {
              severity: "low",
              title: "No model / system card",
              detail: "Catalogue consumers cannot judge fitness for purpose and known limitations.",
              remediation: "Publish a system card with intended use, limitations, evaluation results and owners.",
              refs: ["ISO/IEC 42001 A.6.2.7", "NIST AI RMF MAP 2"],
            },
          },
        ],
      },
      {
        id: "ethics_review",
        label: "Reviewed against the Capgemini Code of Ethics for AI?",
        kind: "select",
        required: true,
        options: [
          { value: "yes", label: "Yes" },
          {
            value: "no",
            label: "No",
            finding: {
              severity: "low",
              title: "No responsible AI review",
              detail: "Fairness, explainability and societal impact have not been assessed.",
              remediation: "Complete the responsible AI checklist with the local ethics champion.",
              refs: ["Capgemini Code of Ethics for AI", "ISO/IEC 42001"],
            },
          },
        ],
      },
    ],
  },
];

export const ALL_QUESTIONS: Question[] = SECTIONS.flatMap((s) => s.questions);

/** EU AI Act Art. 5. */
const PROHIBITED = ["social_scoring", "manipulation", "emotion_work", "biometric_sensitive", "facial_scraping", "predictive_policing", "realtime_rbi"];
/** EU AI Act Annex III. */
const HIGH_RISK = ["biometric", "employment", "education", "essential_services", "critical_infra", "law_enforcement"];

export function aiActTier(a: Answers): AiActTier {
  const d = Array.isArray(a.ai_act_domains) ? a.ai_act_domains : [];
  if (d.some((x) => PROHIBITED.includes(x))) return "prohibited";
  if (d.some((x) => HIGH_RISK.includes(x))) return "high";
  if (usesLlm(a) || a.asset_type === "cv_speech" || a.intended_users === "public") return "limited";
  return "minimal";
}

export const AI_ACT_LABEL: Record<AiActTier, string> = {
  prohibited: "Prohibited practice (Art. 5)",
  high: "High risk (Annex III)",
  limited: "Limited risk – transparency obligations (Art. 50)",
  minimal: "Minimal risk",
};

/** Skills krijgen een lichte intake: alleen de sectie "Asset & ownership"; de rest volgt uit de scan. */
export const isSkill = (a: Answers) => a.asset_type === "skill";

const ASSET_QUESTION_IDS = new Set(SECTIONS[0].questions.map((q) => q.id));

/** De secties die voor dit type asset ingevuld moeten worden. */
export function sectionsFor(a: Answers): Section[] {
  return isSkill(a) ? SECTIONS.slice(0, 1) : SECTIONS;
}

export function isVisible(q: Question, a: Answers) {
  if (isSkill(a) && !ASSET_QUESTION_IDS.has(q.id)) return false;
  return !q.showIf || q.showIf(a);
}

/** Geeft een foutmelding per ontbrekend verplicht veld. */
export function validateAnswers(a: Answers, sectionId?: string): Record<string, string> {
  const errors: Record<string, string> = {};
  const sections = sectionId ? SECTIONS.filter((s) => s.id === sectionId) : sectionsFor(a);
  for (const q of sections.flatMap((s) => s.questions)) {
    if (!isVisible(q, a)) continue;
    const v = a[q.id];
    const empty = v === undefined || (Array.isArray(v) ? v.length === 0 : String(v).trim() === "");
    if (q.required && empty) errors[q.id] = "Required";
    else if (q.kind === "email" && v && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v))) errors[q.id] = "Invalid e-mail address";
    else if (typeof v === "string" && v.length > 4000) errors[q.id] = "Too long";
  }
  return errors;
}

/** Zet antwoorden om in bevindingen voor het rapport. */
export function questionnaireFindings(a: Answers): Finding[] {
  const out: Finding[] = [];
  for (const q of ALL_QUESTIONS) {
    if (!isVisible(q, a) || !q.options) continue;
    const v = a[q.id];
    const values = Array.isArray(v) ? v : v ? [v] : [];
    for (const opt of q.options) {
      if (!opt.finding || !values.includes(opt.value)) continue;
      out.push({
        id: `q-${q.id}-${opt.value}`,
        scanner: "questionnaire",
        ruleId: `Q.${q.id}`,
        severity: opt.finding.severity,
        title: opt.finding.title,
        description: `${opt.finding.detail} (Answer to “${q.label}”: ${opt.label})`,
        remediation: opt.finding.remediation,
        refs: opt.finding.refs,
      });
    }
  }

  const tier = aiActTier(a);
  if (tier === "prohibited") {
    out.push({
      id: "q-ai-act-prohibited",
      scanner: "questionnaire",
      ruleId: "Q.ai_act",
      severity: "critical",
      title: "Use case is a prohibited AI practice under the EU AI Act",
      description: `The declared use (${answerLabel("ai_act_domains", (Array.isArray(a.ai_act_domains) ? a.ai_act_domains : []).filter((x) => PROHIBITED.includes(x)))}) is a prohibited practice under Art. 5 of the EU AI Act, banned since 2 February 2025. Narrow exceptions exist (e.g. medical or safety reasons for emotion recognition, authorised law-enforcement use), but they need a legal assessment.`,
      remediation: "This asset cannot be published. Involve Legal & Compliance. If the answer was a mistake, correct it and submit again.",
      refs: ["EU AI Act Art. 5"],
    });
  } else if (tier === "high") {
    out.push({
      id: "q-ai-act-high",
      scanner: "questionnaire",
      ruleId: "Q.ai_act",
      severity: "high",
      title: "High-risk AI system under the EU AI Act",
      description: "Annex III use cases require risk management, data governance, technical documentation, logging, human oversight and conformity assessment.",
      remediation: "Route to the AI governance board; prepare technical documentation (Annex IV) and a conformity assessment.",
      refs: ["EU AI Act Art. 6", "EU AI Act Annex III", "EU AI Act Art. 9–15"],
    });
  }

  if (has(a, "data_flows", "external_ai") && (a.data_classification === "restricted" || a.personal_data === "special")) {
    out.push({
      id: "q-restricted-external",
      scanner: "questionnaire",
      ruleId: "Q.data_combo",
      severity: "critical",
      title: "Restricted or special-category data sent to an external AI provider",
      description: "The combination of highly sensitive data and an external AI API is not allowed under the data handling policy.",
      remediation: "Process this data only with models hosted inside the Capgemini Azure tenant.",
      refs: ["OWASP LLM02:2025", "GDPR Art. 9", "GDPR Chapter V"],
    });
  }
  return out;
}

export function answerLabel(qId: string, value: string | string[] | undefined): string {
  const q = ALL_QUESTIONS.find((x) => x.id === qId);
  if (value === undefined) return "—";
  const values = Array.isArray(value) ? value : [value];
  if (!q?.options) return values.join(", ");
  return values.map((v) => q.options!.find((o) => o.value === v)?.label ?? v).join(", ");
}
