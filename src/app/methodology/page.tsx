import type { Metadata } from "next";
import type { ReactNode } from "react";
import { Card, CardHeader, PageHeader, TableScroll, td, th } from "@/components/Card";
import { CheckIcon, InfoIcon } from "@/components/icons";
import { PASS_SCORE } from "@/lib/scoring";

export const metadata: Metadata = { title: "Methodology" };

const TOC = [
  { id: "scanners", label: "Automated scanners" },
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
    name: "Dependency vulnerabilities",
    checks: "Packages from npm, PyPI, Maven, NuGet, Go and crates.io manifests and lockfiles, matched against known advisories (CVE, GHSA).",
    basis: "OSV.dev vulnerability database · CycloneDX SBOM export",
    impact: "Blocking when critical",
  },
  {
    name: "Static analysis",
    checks: "Code and command injection, insecure deserialisation, SQL built from strings, disabled TLS verification, weak hashing, permissive CORS, debug mode.",
    basis: "Semgrep- and Bandit-derived patterns for Python, JavaScript and TypeScript",
    impact: "By severity",
  },
  {
    name: "AI / LLM rules",
    checks: "LLM output passed to exec, shell or SQL; user input concatenated into prompts; credentials in system prompts; unpinned or remote-code models; prompts written to logs; missing token limits.",
    basis: "OWASP Top 10 for LLM Applications 2025 · MITRE ATLAS",
    impact: "By severity",
  },
  {
    name: "Model artefacts",
    checks: "Pickle-based weights (.pkl, .pt, .bin, .joblib) inspected for opcodes that import or call code on load.",
    basis: "ModelScan-style pickle opcode analysis",
    impact: "Blocking when executable code is found",
  },
  {
    name: "Configuration & IaC",
    checks: "Dockerfiles, Kubernetes manifests and Terraform / Bicep for root containers, unpinned images, public exposure and missing encryption.",
    basis: "Hadolint- and Checkov-derived rules",
    impact: "By severity",
  },
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
  { name: "EU AI Act", use: "Risk tier: prohibited practices (Art. 5), high-risk use cases (Annex III), transparency (Art. 50), human oversight (Art. 14)." },
  { name: "GDPR", use: "Personal and special-category data, DPIA (Art. 35), automated decisions (Art. 22), international transfers (Chapter V)." },
  { name: "MITRE ATLAS", use: "Adversarial techniques against AI systems: prompt injection, model supply-chain compromise, data extraction." },
  { name: "OWASP LLM Top 10 / AI Exchange", use: "Architecture, agency and guardrail questions for LLM-based assets." },
];

const BLOCKING = [
  { label: "No exposed secrets", detail: "No critical or high-severity credential findings." },
  { label: "No unsafe model artefacts", detail: "No model file that executes code when loaded." },
  { label: "No critical findings", detail: "Across code, dependencies, configuration and questionnaire." },
  { label: "No prohibited AI practice", detail: "Use case does not fall under EU AI Act Art. 5." },
];

const NON_BLOCKING = [
  { label: "No high-severity findings", detail: "High findings need remediation or a documented risk acceptance." },
  { label: `Trust score ≥ ${PASS_SCORE}`, detail: "Below the threshold the asset is routed to manual review." },
  { label: "Not a high-risk AI system", detail: "Annex III use cases require AI governance board approval." },
];

const WEIGHTS = [
  { sev: "Critical", w: "30", cls: "bg-sev-critical" },
  { sev: "High", w: "12", cls: "bg-sev-high" },
  { sev: "Medium", w: "5", cls: "bg-sev-medium" },
  { sev: "Low", w: "1.5", cls: "bg-sev-low" },
  { sev: "Info", w: "0", cls: "bg-sev-info" },
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
            description="Every upload is extracted in memory and analysed by six scanners. Findings carry a severity, location, remediation and references."
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
            description="The intake questionnaire has six sections. Answers that indicate risk produce findings that count towards the gate like scanner findings."
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
            description="Starts at 100 and subtracts a weight per finding. At most three hits per rule are counted, so one pattern repeated across many files cannot dominate the score."
          >
            <div className="grid gap-6 px-4 py-4 sm:px-5 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
              <TableScroll>
                <table className="w-full text-[13px]">
                  <thead className="border-b border-line">
                    <tr>
                      <th scope="col" className="py-2 pr-3 text-left text-[11px] font-medium uppercase tracking-[0.06em] text-subtle">Severity</th>
                      <th scope="col" className="py-2 text-right text-[11px] font-medium uppercase tracking-[0.06em] text-subtle">Points per finding</th>
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
                        <td className="tabular py-2 text-right font-mono text-ink">−{w.w}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableScroll>
              <div className="space-y-3 text-[13px] leading-5 text-muted">
                <p className="rounded-md border border-line bg-surface-2 px-3 py-2 font-mono text-xs text-ink-2">
                  score = max(0, 100 − Σ weight × min(hits per rule, 3))
                </p>
                <p>
                  The pass threshold is <span className="tabular font-semibold text-ink">{PASS_SCORE}</span>. One critical finding already fails the
                  blocking gate regardless of the score; the score separates assets with a few minor findings from assets with many.
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
              <li>Questionnaire answers are self-declared by the asset owner and are only as reliable as the reviewer&apos;s verification.</li>
              <li>Catalogue publication is simulated; no entry is created in Azure.</li>
              <li>Roadmap: run the real tools in an isolated, network-restricted worker (e.g. Azure Container Apps jobs) and attach their native SARIF output to the report.</li>
            </ul>
          </section>
        </div>
      </div>
    </div>
  );
}
