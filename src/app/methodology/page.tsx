import type { Metadata } from "next";
import type { ReactNode } from "react";
import { Card, CardHeader, PageHeader, TableScroll, td, th } from "@/components/Card";
import { CheckIcon, InfoIcon } from "@/components/icons";
import { PASS_SCORE } from "@/lib/scoring";

export const metadata: Metadata = { title: "Methodology" };

const TOC = [
  { id: "scanners", label: "Automated scanners" },
  { id: "skills", label: "Agent skill review" },
  { id: "licences", label: "Licences & deprecation" },
  { id: "consistency", label: "Answers vs. code" },
  { id: "git", label: "Git repository import" },
  { id: "owasp", label: "OWASP Top 10 for LLMs" },
  { id: "frameworks", label: "Questionnaire frameworks" },
  { id: "gate", label: "Gate policy" },
  { id: "scoring", label: "Trust score" },
  { id: "limitations", label: "Limitations" },
];

const SCANNERS: { name: string; checks: string; basis: string; impact: string }[] = [
  {
    name: "Secret detection",
    checks: "Cloud and AI provider keys, tokens, private keys, connection strings and passwords in source and configuration files.",
    basis: "Gitleaks-derived rules with entropy and placeholder filtering",
    impact: "Blocking (critical / high)",
  },
  {
    name: "Dependencies & licences",
    checks:
      "Packages from npm, PyPI, Maven, NuGet, Go and crates.io manifests and lockfiles, matched against known advisories (CVE, GHSA); declared licences and deprecation status per version.",
    basis: "OSV.dev vulnerability database · deps.dev (Open Source Insights) · CycloneDX SBOM export",
    impact: "Blocking when critical",
  },
  {
    name: "Static analysis",
    checks:
      "Code and command injection, insecure deserialisation, SQL built from strings, cross-site scripting via innerHTML, disabled TLS verification, weak hashing, permissive CORS, debug mode, insecure temporary files.",
    basis: "Semgrep- and Bandit-derived patterns for Python, JavaScript and TypeScript",
    impact: "By severity",
  },
  {
    name: "AI / LLM rules",
    checks:
      "LLM output passed to exec, shell or SQL; agents with code-execution tools; disabled LangChain safety flags; user input concatenated into prompts; credentials in system prompts; public AI APIs instead of tenant-hosted models; unpinned or remote-code models; public Gradio share links; prompts written to logs; missing token limits and guardrails.",
    basis: "OWASP Top 10 for LLM Applications 2025 · MITRE ATLAS",
    impact: "By severity",
  },
  {
    name: "Model artefacts",
    checks:
      "Pickle-based weights (.pkl, .pt, .bin, .joblib) inspected for opcodes that import or call code on load; Keras models with Lambda layers; NumPy files with object arrays. Model files that cannot be inspected are listed.",
    basis: "ModelScan-style analysis of pickle, Keras and NumPy files",
    impact: "Blocking when executable code is found",
  },
  {
    name: "Configuration & IaC",
    checks:
      "Dockerfiles, Kubernetes manifests, Terraform / Bicep and GitHub Actions workflows: root or privileged containers, unpinned images, secrets baked into images, public network access, weak TLS, risky workflow triggers. Also committed .env files and a missing README, LICENSE or SECURITY.md.",
    basis: "Hadolint- and Checkov-derived rules",
    impact: "By severity",
  },
  {
    name: "Agent skill review",
    checks: "Every SKILL.md folder: format and metadata, how clearly it tells an agent what to do and when, and risky instructions or scripts (see below).",
    basis: "Agent Skills specification (agentskills.io) · skill authoring best practices",
    impact: "Feedback; security issues by severity",
  },
  {
    name: "Answers vs. code",
    checks: "Contradictions between the questionnaire answers and what the other scanners found in the code.",
    basis: "Cross-check of questionnaire answers and scan results",
    impact: "By severity",
  },
];

const SKILL_CHECKS: { title: string; intro: string; items: string[] }[] = [
  {
    title: "Structure",
    intro: "Does the skill follow the Agent Skills format?",
    items: [
      "SKILL.md starts with YAML front matter",
      "A valid name (max. 64 characters) that matches the folder name",
      "A valid description (max. 1,024 characters)",
      "Referenced files exist, are at most one level deep and use forward slashes",
    ],
  },
  {
    title: "Quality",
    intro: "Will an agent understand when and how to use it?",
    items: [
      "The description is specific, in the third person, and says what the skill does and when to use it",
      "The SKILL.md body stays under 500 lines; long reference files have a table of contents",
      "Concrete examples or a step-by-step workflow, and no time-sensitive information",
      "Scripts handle errors explicitly and declare their dependencies",
    ],
  },
  {
    title: "Security",
    intro: "Could the skill or its scripts cause harm?",
    items: [
      "Prompt-injection or instruction-override text, and hidden or invisible Unicode characters",
      "Data exfiltration, access to credential stores and embedded credentials",
      "Remote code fetched at runtime, obfuscated payloads and destructive commands",
      "Broad tool permissions (allowed-tools), disabled safety prompts and unexpected network hosts",
    ],
  },
];

const CONSISTENCY_EXAMPLES: { answer: string; code: string }[] = [
  { answer: "No data is sent to an external AI provider", code: "The code calls a public AI endpoint" },
  { answer: "Secrets live in Key Vault or managed identities", code: "Credentials were found in the code" },
  { answer: "The AI only produces text or predictions", code: "The code can execute code or shell commands" },
  { answer: "No pickle-based model files are shipped", code: "Pickle-based model files were found" },
  { answer: "A prompt-injection guardrail is in place", code: "No guardrail was found in the code" },
  { answer: "The asset is for internal use only", code: "The code opens a public share link" },
  { answer: "Model and dataset licences were reviewed", code: "Copyleft dependencies were found" },
];

type Cov = "code" | "questionnaire" | "both" | "manual";
const OWASP: { id: string; name: string; desc: string; cov: Cov }[] = [
  { id: "LLM01", name: "Prompt Injection", desc: "Inputs that alter the model's behaviour or bypass its instructions, directly or via retrieved content.", cov: "both" },
  { id: "LLM02", name: "Sensitive Information Disclosure", desc: "Leakage of personal data, credentials or confidential content through prompts, outputs or logs.", cov: "both" },
  { id: "LLM03", name: "Supply Chain", desc: "Vulnerable or tampered models, datasets, packages and plugins.", cov: "both" },
  { id: "LLM04", name: "Data and Model Poisoning", desc: "Manipulated training, fine-tuning or embedding data that introduces backdoors or bias.", cov: "questionnaire" },
  { id: "LLM05", name: "Improper Output Handling", desc: "Model output passed to interpreters, browsers or databases without validation.", cov: "both" },
  { id: "LLM06", name: "Excessive Agency", desc: "Tools and permissions that let the model act beyond what the use case requires.", cov: "both" },
  { id: "LLM07", name: "System Prompt Leakage", desc: "Secrets or security controls embedded in system prompts that can be extracted.", cov: "code" },
  { id: "LLM08", name: "Vector and Embedding Weaknesses", desc: "Missing access control or poisoning in retrieval pipelines and vector stores.", cov: "questionnaire" },
  { id: "LLM09", name: "Misinformation", desc: "Confident but incorrect output relied on without verification.", cov: "manual" },
  { id: "LLM10", name: "Unbounded Consumption", desc: "Missing limits on tokens, requests or cost, enabling denial of service or denial of wallet.", cov: "both" },
];

const FRAMEWORKS: { name: string; use: string }[] = [
  { name: "NIST AI RMF 1.0", use: "Ownership, intended use, monitoring and incident response (GOVERN, MAP, MEASURE, MANAGE)." },
  { name: "ISO/IEC 42001", use: "AI management system controls: documentation, system cards, responsible AI review." },
  {
    name: "EU AI Act",
    use: "Risk tier: prohibited practices (Art. 5, e.g. social scoring, emotion recognition at work, biometric categorisation by sensitive traits, untargeted face scraping, predictive policing), high-risk use cases (Annex III, e.g. HR, education, credit, critical infrastructure, law enforcement), transparency (Art. 50), human oversight (Art. 14).",
  },
  { name: "GDPR", use: "Personal and special-category data, DPIA (Art. 35), automated decisions (Art. 22), international transfers (Chapter V)." },
  { name: "MITRE ATLAS", use: "Adversarial techniques against AI systems: prompt injection, model supply-chain compromise, data extraction." },
  { name: "OWASP LLM Top 10 / AI Exchange", use: "Architecture, agency and guardrail questions for LLM-based assets." },
];

const BLOCKING = [
  { label: "No exposed secrets", detail: "No critical or high-severity credential findings." },
  { label: "No unsafe model artefacts", detail: "No model file that executes code when loaded." },
  { label: "No critical findings", detail: "Across code, dependencies, configuration and questionnaire." },
  { label: "No prohibited AI practice", detail: "Use case does not fall under EU AI Act Art. 5." },
  { label: "Something could be scanned", detail: "An upload without any scannable source, manifest or model file cannot be assessed." },
];

const NON_BLOCKING = [
  { label: "No high-severity findings", detail: "High findings need remediation or a documented risk acceptance." },
  { label: `Trust score ≥ ${PASS_SCORE}`, detail: "Below the threshold the asset is routed to manual review." },
  { label: "Not a high-risk AI system", detail: "Annex III use cases require AI governance board approval." },
  { label: "Scan completed fully", detail: "A scanner that failed or timed out, a truncated archive or mostly unread files mean a reviewer must assess the gap." },
  { label: "No self-declared exceptions for serious findings", detail: "Critical or high findings waived via .aigateignore or an inline comment must be confirmed by a reviewer." },
];

const WEIGHTS = [
  { sev: "Critical", w: "× 0.70", cls: "bg-sev-critical" },
  { sev: "High", w: "× 0.88", cls: "bg-sev-high" },
  { sev: "Medium", w: "× 0.96", cls: "bg-sev-medium" },
  { sev: "Low", w: "× 0.99", cls: "bg-sev-low" },
  { sev: "Info / suppressed", w: "× 1", cls: "bg-sev-info" },
];

function Coverage({ on, label }: { on: boolean; label: string }) {
  return on ? (
    <span className="inline-flex items-center gap-1 text-ok">
      <CheckIcon size={14} strokeWidth={2} />
      <span className="sr-only">{label}: covered</span>
    </span>
  ) : (
    <span className="text-slate-300">
      <span aria-hidden="true">—</span>
      <span className="sr-only">{label}: not covered</span>
    </span>
  );
}

function Section({ id, title, description, children }: { id: string; title: string; description?: string; children: ReactNode }) {
  return (
    <Card labelledBy={`${id}-title`} id={id} className="scroll-mt-6">
      <CardHeader id={`${id}-title`} title={title} description={description} />
      {children}
    </Card>
  );
}

export default function MethodologyPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Methodology"
        description="How AI Asset Gate assesses an asset before it can be published to the Azure AI catalogue: what is checked, which open-source rulesets and data are used, and how the gate decides."
      />

      <div className="grid gap-6 lg:grid-cols-[200px_minmax(0,1fr)] lg:gap-8">
        <nav aria-label="On this page" className="hidden lg:block">
          <div className="sticky top-6">
            <div className="mb-2 text-[11px] font-medium uppercase tracking-[0.06em] text-subtle">On this page</div>
            <ul className="space-y-0.5 border-l border-line">
              {TOC.map((t) => (
                <li key={t.id}>
                  <a href={`#${t.id}`} className="-ml-px block border-l border-transparent py-1 pl-3 text-[13px] text-muted hover:border-slate-400 hover:text-ink">
                    {t.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </nav>

        <div className="min-w-0 space-y-6">
          <Section
            id="scanners"
            title="Automated scanners"
            description="Every upload or repository snapshot is extracted in memory and analysed by the scanners below. Nothing is executed. Upload a .zip archive or a single source file; other archive formats (.tar.gz, .7z, .rar) cannot be unpacked. Folders such as node_modules, .venv, dist and build are skipped. Findings carry a severity, location, remediation and references."
          >
            <TableScroll label="Scanners">
              <table className="w-full min-w-[760px] text-[13px]">
                <thead className="border-b border-line bg-surface-2/70">
                  <tr>
                    <th scope="col" className={th}>Scanner</th>
                    <th scope="col" className={th}>What is checked</th>
                    <th scope="col" className={th}>Open-source basis</th>
                    <th scope="col" className={th}>Gate impact</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line align-top">
                  {SCANNERS.map((s) => (
                    <tr key={s.name}>
                      <td className={`${td} whitespace-nowrap align-top font-medium text-ink`}>{s.name}</td>
                      <td className={`${td} align-top leading-5 text-muted`}>{s.checks}</td>
                      <td className={`${td} align-top leading-5 text-ink-2`}>{s.basis}</td>
                      <td className={`${td} whitespace-nowrap align-top text-ink-2`}>{s.impact}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableScroll>
          </Section>

          <Section
            id="skills"
            title="Agent skill review"
            description="Agent skills are folders with a SKILL.md that teach an AI agent a task. They get a quick intake (one section) and a dedicated review with a score from 0 to 100 and concrete suggestions."
          >
            <div className="grid gap-px bg-line md:grid-cols-3">
              {SKILL_CHECKS.map((g) => (
                <div key={g.title} className="bg-white px-4 py-4 sm:px-5">
                  <h3 className="text-[13px] font-semibold text-ink">{g.title}</h3>
                  <p className="mt-0.5 text-xs text-subtle">{g.intro}</p>
                  <ul className="mt-3 space-y-2">
                    {g.items.map((it) => (
                      <li key={it} className="flex gap-2 text-[13px] leading-5 text-muted">
                        <CheckIcon size={14} strokeWidth={2} className="mt-[3px] shrink-0 text-brand" />
                        {it}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
            <p className="border-t border-line px-4 py-3 text-[13px] leading-5 text-muted sm:px-5">
              Based on the open{" "}
              <a href="https://agentskills.io/specification" target="_blank" rel="noopener noreferrer" className="font-medium text-brand hover:text-brand-strong">
                Agent Skills specification
                <span className="sr-only"> (opens in a new tab)</span>
              </a>{" "}
              and published skill-authoring best practices. The skill&apos;s files also go through the regular scanners (secrets, dependencies, code), so a
              leaked key in a skill script blocks it like any other asset. Structure and quality checks mainly give feedback; security problems are also
              reported as findings and count towards the gate.
            </p>
          </Section>

          <Section
            id="licences"
            title="Licences & deprecation"
            description="Besides known vulnerabilities, every resolved package version is looked up in deps.dev (Open Source Insights, by Google)."
          >
            <ul className="space-y-2.5 px-4 py-4 text-[13px] leading-5 text-muted sm:px-5">
              <li className="flex gap-2">
                <CheckIcon size={14} strokeWidth={2} className="mt-[3px] shrink-0 text-brand" />
                <span>
                  <span className="font-medium text-ink-2">Declared licences</span> (SPDX identifiers) appear in the Dependencies table of the report.
                  Copyleft licences such as GPL or AGPL are reported as a medium finding, because they can restrict commercial reuse; packages without a
                  recognised licence are reported as a low finding (&ldquo;None found&rdquo; in the table).
                </span>
              </li>
              <li className="flex gap-2">
                <CheckIcon size={14} strokeWidth={2} className="mt-[3px] shrink-0 text-brand" />
                <span>
                  <span className="font-medium text-ink-2">Deprecated versions</span> that the maintainer has marked as deprecated are reported as a low
                  finding, because they no longer receive fixes.
                </span>
              </li>
              <li className="flex gap-2">
                <CheckIcon size={14} strokeWidth={2} className="mt-[3px] shrink-0 text-brand" />
                <span>
                  If deps.dev cannot be reached, the scan still completes; licences are then shown as unknown (&ldquo;—&rdquo;).
                </span>
              </li>
            </ul>
          </Section>

          <Section
            id="consistency"
            title="Answers vs. code"
            description="The questionnaire is self-declared. This check compares the answers with what the scanners actually found, so contradictions surface before a reviewer has to spot them."
          >
            <TableScroll label="Examples of answers that contradict the code">
              <table className="w-full min-w-[560px] text-[13px]">
                <thead className="border-b border-line bg-surface-2/70">
                  <tr>
                    <th scope="col" className={th}>The questionnaire says</th>
                    <th scope="col" className={th}>The code shows</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {CONSISTENCY_EXAMPLES.map((x) => (
                    <tr key={x.answer}>
                      <td className={`${td} align-top leading-5 text-ink-2`}>{x.answer}</td>
                      <td className={`${td} align-top leading-5 text-muted`}>{x.code}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableScroll>
            <p className="border-t border-line px-4 py-3 text-[13px] leading-5 text-muted sm:px-5">
              These are examples. Mismatches appear in the report as findings from &ldquo;Answers vs. code&rdquo;. They have no file location: fix them by
              correcting the answer or by changing the code, then submit again.
            </p>
          </Section>

          <Section
            id="git"
            title="Git repository import"
            description="Instead of uploading a zip you can paste a link to a public repository."
          >
            <dl className="divide-y divide-line">
              {[
                { k: "Supported", v: "Public repositories on github.com (https://github.com/owner/repo) and gitlab.com (https://gitlab.com/group/project). A .git suffix is fine." },
                { k: "Version", v: "Optionally a branch, tag or commit. Without it, the repository's default branch is used." },
                {
                  k: "How",
                  v: "The server downloads a snapshot archive of that version from the host over https. Nothing is cloned, no Git hooks run, submodules are not included and no code is executed.",
                },
                {
                  k: "Limits",
                  v: "Snapshots larger than 50 MB are rejected and the download must finish within about 25 seconds. The snapshot is scanned exactly like an uploaded archive and kept with the submission.",
                },
              ].map((row) => (
                <div key={row.k} className="grid gap-1 px-4 py-3 sm:grid-cols-[160px_minmax(0,1fr)] sm:gap-6 sm:px-5">
                  <dt className="text-[13px] font-medium text-ink">{row.k}</dt>
                  <dd className="text-[13px] leading-5 text-muted">{row.v}</dd>
                </div>
              ))}
            </dl>
          </Section>

          <Section
            id="owasp"
            title="OWASP Top 10 for LLM Applications 2025"
            description="Coverage of each risk by automated code rules and by the intake questionnaire."
          >
            <TableScroll label="OWASP LLM Top 10 coverage">
              <table className="w-full min-w-[680px] text-[13px]">
                <thead className="border-b border-line bg-surface-2/70">
                  <tr>
                    <th scope="col" className={th}>ID</th>
                    <th scope="col" className={th}>Risk</th>
                    <th scope="col" className={`${th} text-center`}>Code rules</th>
                    <th scope="col" className={`${th} text-center`}>Questionnaire</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {OWASP.map((o) => (
                    <tr key={o.id}>
                      <td className={`${td} whitespace-nowrap align-top font-mono text-xs text-ink-2`}>{o.id}:2025</td>
                      <td className={`${td} align-top`}>
                        <div className="font-medium text-ink">{o.name}</div>
                        <div className="mt-0.5 leading-5 text-subtle">{o.desc}</div>
                        {o.cov === "manual" && <div className="mt-1 text-xs font-medium text-warn">Not automated — assessed during reviewer sign-off.</div>}
                      </td>
                      <td className={`${td} text-center align-top`}>
                        <Coverage on={o.cov === "code" || o.cov === "both"} label="Code rules" />
                      </td>
                      <td className={`${td} text-center align-top`}>
                        <Coverage on={o.cov === "questionnaire" || o.cov === "both"} label="Questionnaire" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableScroll>
          </Section>

          <Section
            id="frameworks"
            title="Questionnaire frameworks"
            description="The intake questionnaire has six sections; agent skills only fill in the first one. Answers that indicate risk produce findings that count towards the gate like scanner findings."
          >
            <dl className="divide-y divide-line">
              {FRAMEWORKS.map((f) => (
                <div key={f.name} className="grid gap-1 px-4 py-3 sm:grid-cols-[220px_minmax(0,1fr)] sm:gap-6 sm:px-5">
                  <dt className="text-[13px] font-medium text-ink">{f.name}</dt>
                  <dd className="text-[13px] leading-5 text-muted">{f.use}</dd>
                </div>
              ))}
            </dl>
          </Section>

          <Section id="gate" title="Gate policy" description="The decision is deterministic and recorded with the report and audit trail.">
            <div className="grid gap-px bg-slate-200 md:grid-cols-2">
              <div className="bg-white px-4 py-4 sm:px-5">
                <h3 className="flex items-center gap-2 text-[13px] font-semibold text-ink">
                  <span className="size-2 rounded-full bg-sev-critical" aria-hidden="true" />
                  Blocking gates
                </h3>
                <p className="mt-1 text-xs text-subtle">Any failure results in Blocked. The asset cannot be approved.</p>
                <ul className="mt-3 space-y-2.5">
                  {BLOCKING.map((g) => (
                    <li key={g.label} className="text-[13px]">
                      <div className="font-medium text-ink-2">{g.label}</div>
                      <div className="text-subtle">{g.detail}</div>
                    </li>
                  ))}
                </ul>
              </div>
              <div className="bg-white px-4 py-4 sm:px-5">
                <h3 className="flex items-center gap-2 text-[13px] font-semibold text-ink">
                  <span className="size-2 rounded-full bg-sev-medium" aria-hidden="true" />
                  Non-blocking gates
                </h3>
                <p className="mt-1 text-xs text-subtle">Any failure results in Manual review required.</p>
                <ul className="mt-3 space-y-2.5">
                  {NON_BLOCKING.map((g) => (
                    <li key={g.label} className="text-[13px]">
                      <div className="font-medium text-ink-2">{g.label}</div>
                      <div className="text-subtle">{g.detail}</div>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
            <ol className="grid border-t border-line text-[13px] sm:grid-cols-3">
              <li className="px-4 py-3 sm:px-5">
                <div className="font-semibold text-sev-critical">Blocked</div>
                <div className="mt-0.5 text-muted">A blocking gate failed. Fix and resubmit.</div>
              </li>
              <li className="border-t border-line px-4 py-3 sm:border-l sm:border-t-0 sm:px-5">
                <div className="font-semibold text-warn">Manual review required</div>
                <div className="mt-0.5 text-muted">No blocking failure, but at least one non-blocking gate failed.</div>
              </li>
              <li className="border-t border-line px-4 py-3 sm:border-l sm:border-t-0 sm:px-5">
                <div className="font-semibold text-ok">Approved for catalogue</div>
                <div className="mt-0.5 text-muted">All gates passed. A reviewer still signs off before publication.</div>
              </li>
            </ol>
          </Section>

          <Section
            id="scoring"
            title="Trust score"
            description="Starts at 100. Each distinct rule that fires multiplies the score by a factor for its severity; repeats of the same rule count for a quarter each (up to four). Ten different problems weigh more than one problem repeated ten times, and the score never collapses to zero after a couple of findings."
          >
            <div className="grid gap-6 px-4 py-4 sm:px-5 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <TableScroll>
                <table className="w-full text-[13px]">
                  <thead className="border-b border-line">
                    <tr>
                      <th scope="col" className="py-2 pr-3 text-left text-[11px] font-medium uppercase tracking-[0.06em] text-subtle">Severity</th>
                      <th scope="col" className="py-2 text-right text-[11px] font-medium uppercase tracking-[0.06em] text-subtle">Factor per rule</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {WEIGHTS.map((w) => (
                      <tr key={w.sev}>
                        <td className="py-2 pr-3">
                          <span className="inline-flex items-center gap-2 text-ink-2">
                            <span className={`size-2 rounded-full ${w.cls}`} aria-hidden="true" />
                            {w.sev}
                          </span>
                        </td>
                        <td className="tabular py-2 text-right font-mono text-ink">{w.w}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableScroll>
              <div className="space-y-3 text-[13px] leading-5 text-muted">
                <p className="rounded-md border border-line bg-surface-2 px-3 py-2 font-mono text-xs text-ink-2">
                  score = 100 × Π factor<sup>1 + 0.25 × min(repeats, 4)</sup> per rule
                </p>
                <p>
                  The pass threshold is <span className="tabular font-semibold text-ink">{PASS_SCORE}</span>. One critical finding already fails the
                  blocking gate regardless of the score; the score separates assets with a few minor findings from assets with many.
                </p>
                <p>
                  <span className="font-semibold text-ink">Exceptions.</span> Like Semgrep, Bandit and Gitleaks, the gate honours a{" "}
                  <code className="font-mono text-xs">.aigateignore</code> file (gitignore-style patterns) and inline markers (
                  <code className="font-mono text-xs">nosec</code>, <code className="font-mono text-xs">nosemgrep</code>,{" "}
                  <code className="font-mono text-xs">gitleaks:allow</code>, <code className="font-mono text-xs">aigate:ignore</code>). Findings in test,
                  example and demo code are treated the same way, except secrets. Suppressed findings stay visible as info, with the reason, so the reviewer
                  can challenge them. Blocking findings (critical findings and exposed credentials) cannot be waived this way, and catch-all patterns such
                  as <code className="font-mono text-xs">*</code> are ignored.
                </p>
              </div>
            </div>
          </Section>

          <section id="limitations" aria-labelledby="limitations-title" className="scroll-mt-6 rounded-xl border border-amber-200 bg-amber-50 px-4 py-4 sm:px-5">
            <h2 id="limitations-title" className="flex items-center gap-2 text-[15px] font-semibold text-amber-950">
              <InfoIcon size={18} className="text-amber-700" />
              Limitations of this demo
            </h2>
            <ul className="mt-2 list-disc space-y-1.5 pl-5 text-[13px] leading-5 text-amber-950/90 marker:text-amber-700">
              <li>Scanners are pattern-based re-implementations of open-source rulesets. They do not perform data-flow or taint analysis and will produce false positives and false negatives.</li>
              <li>The gate is not a replacement for full Semgrep, Trivy, Gitleaks or ModelScan runs, nor for a penetration test or an AI red-team exercise.</li>
              <li>
                Questionnaire answers are self-declared by the asset owner and are only as reliable as the reviewer&apos;s verification. The answers-vs-code
                check catches some contradictions, not all.
              </li>
              <li>
                The agent skill review and the answers-vs-code check are heuristic: they look for patterns and can miss problems or flag something that is
                fine. A skill score says how well a skill follows the format and best practices, not that it is safe.
              </li>
              <li>Git import supports public GitHub and GitLab repositories only. Private repositories, other hosts and submodules are not supported yet.</li>
              <li>Licence data is the licence declared in deps.dev for each package version. It is not a legal review of the licence terms.</li>
              <li>Catalogue publication is simulated; no entry is created in Azure.</li>
              <li>Roadmap: run the real tools in an isolated, network-restricted worker (e.g. Azure Container Apps jobs) and attach their native SARIF output to the report.</li>
            </ul>
          </section>
        </div>
      </div>
    </div>
  );
}
