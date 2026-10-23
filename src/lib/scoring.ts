import { aiActTier } from "./questionnaire";
import type { AiActTier, Answers, Decision, Finding, GateResult, Severity, Suppression } from "./types";
import { SCAN_EMPTY_RULE, SCAN_INCOMPLETE_RULE, SEVERITIES } from "./types";

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

const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const c = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) c[f.severity]++;
  return c;
}

interface RuleGroup {
  scanner: Finding["scanner"];
  ruleId: string;
  /** Titel van de zwaarste bevinding van deze regel. */
  title: string;
  severity: Severity;
  hits: number;
}

/** Bevindingen per regel: zwaarste severity en aantal treffers (info telt niet mee). */
function groupByRule(findings: Finding[]): RuleGroup[] {
  const perRule = new Map<string, RuleGroup>();
  for (const f of findings) {
    if (f.severity === "info") continue;
    const key = `${f.scanner}:${f.ruleId}`;
    const cur = perRule.get(key);
    if (!cur) {
      perRule.set(key, { scanner: f.scanner, ruleId: f.ruleId, title: f.title, severity: f.severity, hits: 1 });
      continue;
    }
    cur.hits++;
    if (RANK[f.severity] > RANK[cur.severity]) {
      cur.severity = f.severity;
      cur.title = f.title;
    }
  }
  return Array.from(perRule.values());
}

function scoreOf(groups: RuleGroup[]): number {
  let score = 1;
  for (const g of groups) score *= Math.pow(RULE_FACTOR[g.severity], 1 + REPEAT_WEIGHT * Math.min(g.hits - 1, MAX_REPEATS));
  return Math.max(0, Math.min(100, Math.round(score * 100)));
}

export function trustScore(findings: Finding[]): number {
  return scoreOf(groupByRule(findings));
}

export interface ScoreDeduction {
  scanner: Finding["scanner"];
  ruleId: string;
  title: string;
  severity: Severity;
  /** Aantal bevindingen van deze regel. */
  hits: number;
  /** Zoveel punten stijgt de score als alle bevindingen van deze regel zijn opgelost. */
  points: number;
}

/**
 * Wat kost elke regel aan score? Gesorteerd op grootste winst, zodat de gebruiker ziet wat de score verklaart
 * en wat hem het meest verhoogt.
 */
export function scoreDeductions(findings: Finding[]): ScoreDeduction[] {
  const groups = groupByRule(findings);
  const total = scoreOf(groups);
  return groups
    .map((g) => ({ ...g, points: scoreOf(groups.filter((x) => x !== g)) - total }))
    .sort((a, b) => b.points - a.points || RANK[b.severity] - RANK[a.severity] || b.hits - a.hits);
}

function quote(title: string, max = 80): string {
  const t = title.length > max ? `${title.slice(0, max - 1)}…` : title;
  return `“${t}”`;
}

/** Eerste paar titels als voorbeeld: “A”, “B” and 3 more. */
function examples(list: Finding[], max = 3): string {
  const titles = Array.from(new Set(list.map((f) => f.title)));
  const shown = titles.slice(0, max).map((t) => quote(t)).join(", ");
  return titles.length > max ? `${shown} and ${titles.length - max} more` : shown;
}

function files(list: Finding[], max = 3): string {
  const paths = Array.from(new Set(list.map((f) => f.file).filter((p): p is string => p !== undefined)));
  if (!paths.length) return "the source";
  const shown = paths.slice(0, max).join(", ");
  return paths.length > max ? `${shown} and ${paths.length - max} more file(s)` : shown;
}

/** Uitleg bij de score: waar komt hij vandaan en wat levert de meeste winst op. */
function explainScore(score: number, findings: Finding[]): string {
  const deductions = scoreDeductions(findings);
  if (!deductions.length) return `Score ${score}/100: no open findings lower the score.`;
  const item = (d: ScoreDeduction) => `${quote(d.title, 60)} (${d.hits > 1 ? `${d.hits}×, ` : ""}+${d.points})`;
  if (score >= PASS_SCORE) {
    return `Score ${score}/100, at or above the pass mark of ${PASS_SCORE}. Biggest deductions (points regained when fixed): ${deductions.slice(0, 3).map(item).join(", ")}.`;
  }
  // Kleinste set regels (max. 5) die de score boven de drempel brengt
  const groups = groupByRule(findings);
  const byKey = (d: ScoreDeduction) => groups.find((g) => g.scanner === d.scanner && g.ruleId === d.ruleId);
  for (let n = 1; n <= Math.min(5, deductions.length); n++) {
    const fixed = new Set(deductions.slice(0, n).map(byKey));
    const after = scoreOf(groups.filter((g) => !fixed.has(g)));
    if (after >= PASS_SCORE) {
      return `Score ${score}/100, below the pass mark of ${PASS_SCORE}. Fixing ${n === 1 ? "this issue" : `these ${n} issues`} raises it to ${after}: ${deductions
        .slice(0, n)
        .map(item)
        .join(", ")}.`;
    }
  }
  return `Score ${score}/100, below the pass mark of ${PASS_SCORE}. Biggest gains (points regained when fixed): ${deductions.slice(0, 5).map(item).join(", ")}.`;
}

/** Afwaardering van een bevinding; valt terug op de tekst die de suppressie-stap in de beschrijving zet. */
export function suppressionOf(f: Finding): Suppression | null {
  if (f.suppressed) return f.suppressed;
  if (f.severity !== "info" || !f.refs.includes("suppressed")) return null;
  const m = /Original severity: (critical|high|medium|low)\b/.exec(f.description);
  if (!m) return null;
  const by: Suppression["by"] = /test, example or demo code/.test(f.description) ? "test-code" : /inline exception comment/.test(f.description) ? "inline" : "ignore-file";
  return { by, originalSeverity: m[1] as Severity };
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
 * - blocked: een blokkerende gate faalt (kritieke bevinding, gelekte secrets, onveilig model, verboden AI-praktijk)
 * - conditional: geen blokkade, maar high-bevindingen, hoog-risico onder de AI Act, score onder de drempel,
 *   een onvolledige scan of zelf weggezette kritieke/high-bevindingen -> handmatige review
 * - approved: alle gates groen
 */
export function evaluate(findings: Finding[], answers: Answers): Evaluation {
  const counts = countBySeverity(findings);
  const score = trustScore(findings);
  const tier = aiActTier(answers);

  const secrets = findings.filter((f) => f.scanner === "secrets" && (f.severity === "critical" || f.severity === "high"));
  const malicious = findings.filter((f) => f.scanner === "model" && f.severity === "critical");
  const critical = findings.filter((f) => f.severity === "critical");
  const criticalVulns = critical.filter((f) => f.scanner === "dependencies").length;
  const high = findings.filter((f) => f.severity === "high");
  const incomplete = findings.filter((f) => f.ruleId === SCAN_INCOMPLETE_RULE || f.ruleId === SCAN_EMPTY_RULE);
  // Niets scanbaars in de upload: er valt niets te beoordelen, dus blokkeren in plaats van handmatige review
  const empty = incomplete.some((f) => f.ruleId === SCAN_EMPTY_RULE);
  // Door de indiener zelf weggezet (.aigateignore of inline); testcode wordt automatisch afgewaardeerd en telt niet
  const waived = findings.filter((f) => {
    const s = suppressionOf(f);
    return s !== null && s.by !== "test-code" && RANK[s.originalSeverity] >= RANK.high;
  });

  const gates: GateResult[] = [
    {
      id: "no-secrets",
      label: "No exposed secrets",
      blocking: true,
      passed: secrets.length === 0,
      detail: secrets.length
        ? `${secrets.length} credential(s) found in ${files(secrets)}. Revoke (rotate) them at the provider, remove them from the code and the Git history, and load them from Key Vault or a managed identity instead.`
        : "No credentials or private keys detected.",
    },
    {
      id: "no-malicious-models",
      label: "No unsafe model artefacts",
      blocking: true,
      passed: malicious.length === 0,
      detail: malicious.length
        ? `${malicious.length} model file finding(s) show code that executes when the model is loaded (${files(malicious)}). Convert the weights to safetensors or ONNX.`
        : "No executable payloads found in model files.",
    },
    {
      id: "no-critical",
      label: "No critical findings",
      blocking: true,
      passed: critical.length === 0,
      detail: critical.length
        ? `${critical.length} critical finding(s)${criticalVulns ? `, of which ${criticalVulns} in dependencies` : ""}: ${examples(critical)}. Each must be fixed before the asset can be published.`
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
      passed: high.length === 0,
      detail: high.length
        ? `${high.length} high-severity finding(s) need remediation or a documented risk acceptance: ${examples(high)}.`
        : "No high-severity findings.",
    },
    {
      id: "score",
      label: `Trust score ≥ ${PASS_SCORE}`,
      blocking: false,
      passed: score >= PASS_SCORE,
      detail: explainScore(score, findings),
    },
    {
      id: "scan-complete",
      label: "Scan completed fully",
      blocking: empty,
      passed: incomplete.length === 0,
      detail: empty
        ? "Nothing in the upload could be scanned, so no check has run. Upload the source code (zip without node_modules, venv or build output, or a public Git URL) and submit again."
        : incomplete.length
          ? `Part of the upload could not be checked automatically: ${examples(incomplete)}. A reviewer has to assess what was not covered.`
          : "All scanners ran and the upload contained scannable content.",
    },
    {
      id: "exceptions",
      label: "No self-declared exceptions for serious findings",
      blocking: false,
      passed: waived.length === 0,
      detail: waived.length
        ? `${waived.length} critical or high finding(s) were marked as exceptions in .aigateignore or with an inline comment: ${examples(waived)}. A reviewer must confirm each exception.`
        : "No critical or high findings were waived with .aigateignore or inline comments.",
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
