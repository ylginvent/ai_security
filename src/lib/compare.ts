import { suppressionOf } from "./scoring";
import type { ComparedFinding, Comparison, Finding, Severity, Submission } from "./types";

/** Bovengrens voor de opgeloste bevindingen die in het rapport worden bewaard (het totaal blijft exact). */
const MAX_FIXED = 500;

const norm = (s: string | undefined) => (s ?? "").replace(/\s+/g, " ").trim().toLowerCase().slice(0, 300);

/** Telt mee voor de beslissing: alles behalve info (uitzonderingen en test-/democode zijn al naar info afgewaardeerd). */
export const counts = (f: Finding) => f.severity !== "info";

/** Eén regel = scanner + ruleId; daarop groeperen we herhalingen van hetzelfde probleem. */
export const ruleKey = (f: { scanner: string; ruleId: string }) => `${f.scanner}:${f.ruleId}`;

/**
 * Sleutels van streng naar los. Regelnummers verschuiven bij elke wijziging, dus na de exacte match volgen een match op
 * de code zelf (verplaatst) en op de titel binnen hetzelfde bestand. Over bestanden heen matchen we niet: een probleem
 * dat in bestand A is opgelost en in B opduikt, is één opgelost en één nieuw.
 */
const KEYS: ((f: Finding) => string | null)[] = [
  (f) => `${ruleKey(f)}|${f.file ?? ""}|${f.line ?? ""}|${norm(f.title)}`,
  (f) => (f.snippet ? `${ruleKey(f)}|${f.file ?? ""}|s:${norm(f.snippet)}` : null),
  (f) => `${ruleKey(f)}|${f.file ?? ""}|${norm(f.title)}`,
];

/** Koppelt bevindingen van de nieuwe versie aan die van de vorige. Resultaat: index nieuw -> index vorig. */
export function matchFindings(prev: Finding[], curr: Finding[]): Map<number, number> {
  const pairs = new Map<number, number>();
  const usedPrev = new Set<number>();
  for (const key of KEYS) {
    const pool = new Map<string, number[]>();
    prev.forEach((f, i) => {
      if (usedPrev.has(i)) return;
      const k = key(f);
      if (k === null) return;
      const list = pool.get(k);
      if (list) list.push(i);
      else pool.set(k, [i]);
    });
    curr.forEach((f, i) => {
      if (pairs.has(i)) return;
      const k = key(f);
      const list = k === null ? undefined : pool.get(k);
      const p = list?.shift();
      if (p === undefined) return;
      pairs.set(i, p);
      usedPrev.add(p);
    });
  }
  return pairs;
}

function compact(f: Finding, waived: boolean): ComparedFinding {
  return {
    scanner: f.scanner,
    ruleId: f.ruleId,
    severity: suppressionOf(f)?.originalSeverity ?? f.severity,
    title: f.title,
    ...(f.file ? { file: f.file } : {}),
    ...(f.line ? { line: f.line } : {}),
    ...(waived ? { waived: true } : {}),
  };
}

/** Vergelijkt de bevindingen van deze versie met het rapport van de vorige versie. */
export function compareWithPrevious(previous: Submission, findings: Finding[]): Comparison | undefined {
  const prev = previous.report?.findings;
  if (previous.status !== "completed" || !prev) return undefined;
  const pairs = matchFindings(prev, findings);
  const matchedPrev = new Map<number, number>();
  for (const [c, p] of pairs) matchedPrev.set(p, c);

  const fixed: ComparedFinding[] = [];
  let fixedTotal = 0;
  prev.forEach((f, p) => {
    if (!counts(f)) return;
    const c = matchedPrev.get(p);
    if (c !== undefined && counts(findings[c])) return;
    fixedTotal++;
    if (fixed.length < MAX_FIXED) fixed.push(compact(f, c !== undefined));
  });

  const added: number[] = [];
  const open: Comparison["open"] = [];
  findings.forEach((f, c) => {
    if (!counts(f)) return;
    const p = pairs.get(c);
    if (p === undefined || !counts(prev[p])) {
      added.push(c);
      return;
    }
    const was: Severity = prev[p].severity;
    open.push(was !== f.severity ? { index: c, was } : { index: c });
  });

  return {
    previousId: previous.id,
    previousVersion: previous.asset_version,
    previousSubmittedAt: previous.created_at,
    previousScore: previous.score,
    previousDecision: previous.decision,
    previousCounts: previous.counts,
    ...(previous.report?.engineVersion ? { previousEngineVersion: previous.report.engineVersion } : {}),
    fixed,
    fixedTotal,
    added,
    open,
  };
}

/** "1.2.0" -> "1.2.1", "v3" -> "v4"; null als er geen versienummer te herkennen is. */
export function nextVersion(v: string | null | undefined): string | null {
  const m = /^(.*?)(\d+)(\D*)$/.exec((v ?? "").trim());
  if (!m) return null;
  return `${m[1]}${Number(m[2]) + 1}${m[3]}`;
}
