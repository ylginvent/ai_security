import { aiActTier } from "./questionnaire";
import type { AiActTier, Answers, Decision, Finding, GateResult, Severity } from "./types";
import { SEVERITIES } from "./types";

/**
 * Elke unieke regel vermenigvuldigt de score met een factor per severity; herhalingen van dezelfde regel
 * tellen voor een kwart mee (max. 4 extra). Zo blijft de score onderscheidend: hij zakt niet bij twee
 * kritieke bevindingen al naar 0, en tien keer hetzelfde probleem weegt minder dan tien verschillende.
 */
export const RULE_FACTOR: Record<Severity, number> = { critical: 0.7, high: 0.88, medium: 0.96, low: 0.99, info: 1 };
const REPEAT_WEIGHT = 0.25;
const MAX_REPEATS = 4;

/** Minimale score om zonder handmatige review door te mogen. */
export const PASS_SCORE = 75;

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const c = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) c[f.severity]++;
  return c;
}

export function trustScore(findings: Finding[]): number {
  // per regel: zwaarste severity en aantal treffers
  const perRule = new Map<string, { factor: number; hits: number }>();
  for (const f of findings) {
    if (f.severity === "info") continue;
    const key = `${f.scanner}:${f.ruleId}`;
    const cur = perRule.get(key);
    const factor = RULE_FACTOR[f.severity];
    perRule.set(key, { factor: Math.min(cur?.factor ?? 1, factor), hits: (cur?.hits ?? 0) + 1 });
  }
  let score = 1;
  for (const { factor, hits } of perRule.values()) score *= Math.pow(factor, 1 + REPEAT_WEIGHT * Math.min(hits - 1, MAX_REPEATS));
  return Math.max(0, Math.min(100, Math.round(score * 100)));
}

export interface Evaluation {
  score: number;
  decision: Decision;
  tier: AiActTier;
  counts: Record<Severity, number>;
  gates: GateResult[];
}

/**
 * De gate-policy voor publicatie in de Azure AI-productcatalogus.
 * - blocked: een blokkerende gate faalt (kritieke bevinding, gelekte secrets, verboden AI-praktijk)
 * - conditional: geen blokkade, maar high-bevindingen, hoog-risico onder de AI Act of score onder de drempel -> handmatige review
 * - approved: alle gates groen
 */
export function evaluate(findings: Finding[], answers: Answers): Evaluation {
  const counts = countBySeverity(findings);
  const score = trustScore(findings);
  const tier = aiActTier(answers);
  const by = (pred: (f: Finding) => boolean) => findings.filter(pred).length;

  const secrets = by((f) => f.scanner === "secrets" && (f.severity === "critical" || f.severity === "high"));
  const malicious = by((f) => f.scanner === "model" && f.severity === "critical");
  const criticalVulns = by((f) => f.scanner === "dependencies" && f.severity === "critical");
  const critical = counts.critical;
  const high = counts.high;

  const gates: GateResult[] = [
    {
      id: "no-secrets",
      label: "No exposed secrets",
      blocking: true,
      passed: secrets === 0,
      detail: secrets ? `${secrets} credential(s) found in the source. Rotate them before resubmitting.` : "No credentials or private keys detected.",
    },
    {
      id: "no-malicious-models",
      label: "No unsafe model artefacts",
      blocking: true,
      passed: malicious === 0,
      detail: malicious ? `${malicious} model file(s) contain code that executes on load.` : "No executable payloads found in model files.",
    },
    {
      id: "no-critical",
      label: "No critical findings",
      blocking: true,
      passed: critical === 0,
      detail: critical
        ? `${critical} critical finding(s)${criticalVulns ? `, of which ${criticalVulns} in dependencies` : ""}.`
        : "No critical issues in code, dependencies or questionnaire.",
    },
    {
      id: "ai-act",
      label: "EU AI Act classification allowed",
      blocking: tier === "prohibited",
      passed: tier !== "prohibited" && tier !== "high",
      detail:
        tier === "prohibited"
          ? "Use case falls under a prohibited practice (Art. 5)."
          : tier === "high"
            ? "High-risk system (Annex III): requires AI governance board approval."
            : "No prohibited or high-risk use case declared.",
    },
    {
      id: "no-high",
      label: "No high-severity findings",
      blocking: false,
      passed: high === 0,
      detail: high ? `${high} high-severity finding(s) need remediation or a documented risk acceptance.` : "No high-severity findings.",
    },
    {
      id: "score",
      label: `Trust score ≥ ${PASS_SCORE}`,
      blocking: false,
      passed: score >= PASS_SCORE,
      detail: `Score ${score}/100.`,
    },
  ];

  const blocked = gates.some((g) => g.blocking && !g.passed);
  const allPassed = gates.every((g) => g.passed);
  const decision: Decision = blocked ? "blocked" : allPassed ? "approved" : "conditional";
  return { score, decision, tier, counts, gates };
}

export const DECISION_LABEL: Record<Decision, string> = {
  approved: "Approved for catalogue",
  conditional: "Manual review required",
  blocked: "Blocked",
};
