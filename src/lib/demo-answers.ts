import type { Answers } from "./types";

/**
 * Example intake answers for the bundled demo application (contoso-rag-assistant.zip, built in sample.ts).
 * Deliberately moderately risky so the report shows a realistic mix of questionnaire findings.
 * Three answers are optimistic on purpose, so the "Answers vs. code" check has something to show:
 * - agency "read_tools", while app/agent.py gives the model a Python REPL and exec()s its output;
 * - secrets_mgmt "key_vault", while app/config.py and .env contain (fake) credentials;
 * - exposure "internal", while app/ui.py opens a public Gradio share link.
 * Only option values that exist in questionnaire.ts are used.
 */
export const DEMO_ANSWERS: Answers = {
  // Asset & ownership
  asset_name: "Contoso RAG Assistant",
  asset_version: "0.9.2",
  owner_name: "Marta Kowalski",
  owner_email: "marta.kowalski@capgemini.com",
  business_unit: "ind",
  description:
    "HR policy assistant for Contoso employees. Answers questions about leave, expenses and payroll from the HR policy library (retrieval-augmented generation), and lets HR analysts ask for ad-hoc headcount reports in natural language.",
  asset_type: "rag",
  lifecycle: "pilot",
  intended_users: "client",

  // Data & privacy
  data_classification: "confidential",
  personal_data: "personal",
  client_data: "yes_contract",
  data_flows: ["tenant", "external_ai"],
  training_use: "none",
  retention: "defined",
  dpia: "in_progress",

  // Model & supply chain
  model_provider: ["azure_openai", "public_api", "huggingface"],
  model_provenance: "partial",
  model_format: "pickle",
  licences: "yes",

  // Architecture & agency
  exposure: "internal",
  authentication: "api_key",
  agency: "read_tools",
  rag_permissions: "not_enforced",
  untrusted_content: "yes",

  // Security controls
  guardrails: "none",
  output_filtering: "partial",
  secrets_mgmt: "key_vault",
  logging: "basic",
  rate_limiting: "no",
  red_teaming: "planned",
  threat_model: "no",
  incident_response: "yes",

  // Governance & EU AI Act
  ai_act_domains: ["none"],
  decisions_about_people: "no",
  transparency: "yes",
  documentation: "no",
  ethics_review: "yes",
};

/**
 * Example intake answers for the bundled demo Agent Skill (invoice-summariser-skill.zip).
 * Skills only fill in the "Asset & ownership" section; every value exists in questionnaire.ts.
 */
export const DEMO_SKILL_ANSWERS: Answers = {
  asset_name: "Invoice Summariser Skill",
  asset_version: "0.3.0",
  owner_name: "Jonas Verhoeven",
  owner_email: "jonas.verhoeven@capgemini.com",
  business_unit: "apps",
  description:
    "Agent skill that reads supplier invoices (PDF or text), extracts the totals, VAT and due dates, and writes a short summary for the finance team. Includes a helper script that parses the files.",
  asset_type: "skill",
  lifecycle: "pilot",
  intended_users: "internal",
};
