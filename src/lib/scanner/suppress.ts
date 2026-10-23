import type { SuppressionSource } from "../types";
import { COMMENT_LINE, splitLines, type Archive, type RawFinding } from "./archive";

/**
 * Uitzonderingen zoals bij Semgrep (.semgrepignore, nosemgrep), Bandit (# nosec) en Gitleaks (gitleaks:allow).
 * Onderdrukte bevindingen verdwijnen niet: ze worden "info" (tellen niet mee in score en gates) en houden
 * de reden in de beschrijving, zodat de reviewer kan zien wat er is weggezet.
 *
 * Blokkerende bevindingen (critical, of een gelekte credential met severity high/critical) kan de indiener
 * NIET zelf wegzetten: anders zou één regel "*" in .aigateignore elke blokkade opheffen. Zulke bevindingen
 * houden hun severity; de beschrijving vermeldt dat er een uitzondering is aangevraagd, zodat de reviewer
 * het risico bewust kan accepteren.
 *
 * Let op: het formaat " — Suppressed: <reden> Original severity: <sev>. The reviewer should confirm this exception."
 * wordt in src/lib/format.ts (suppressionInfo) geparsed; niet wijzigen zonder die parser aan te passen.
 */

export const IGNORE_FILE = ".aigateignore";

/** Inline-markers; alleen op dezelfde regel of op een commentaarregel direct erboven. */
const INLINE_MARKER = /(?:^|[^\w-])(?:nosec|nosemgrep|gitleaks:allow|aigate[:-]ignore)\b/i;

/** Map- of bestandsnamen die op test-, voorbeeld- of demo-code wijzen. */
const TEST_DIR = /^(?:tests?|__tests__|spec|specs|fixtures?|samples?|examples?|demos?|testdata|mocks?|__mocks__)$/i;
const TEST_FILE = /(?:^|[._-])(?:tests?|spec|samples?|examples?|fixtures?|mocks?|demo)(?:[._-]|$)/i;

/** Max. aantal patronen uit .aigateignore. */
const MAX_PATTERNS = 200;

function isTestOrSample(path: string): boolean {
  const parts = path.split("/");
  const name = parts.pop() ?? "";
  return parts.some((p) => TEST_DIR.test(p)) || TEST_FILE.test(name.replace(/\.[^.]+$/, ""));
}

/** Bevindingen die de beslissing blokkeren en dus niet door de indiener weggezet mogen worden. */
function isBlocking(f: RawFinding): boolean {
  return f.severity === "critical" || (f.scanner === "secrets" && f.severity === "high");
}

/** Zet een gitignore-achtig patroon om naar een RegExp (ondersteunt *, **, ?, map/ en patronen zonder slash). */
function globToRegExp(pattern: string): RegExp {
  let p = pattern;
  if (p.endsWith("/")) p = p.slice(0, -1);
  // gitignore: een slash aan het begin of in het midden verankert het patroon aan de root
  const anchored = p.includes("/");
  p = p.replace(/^\//, "");
  let re = "";
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === "*") {
      if (p[i + 1] === "*") {
        // "**/" = nul of meer mappen, "**" elders = alles
        if (p[i + 2] === "/") {
          re += "(?:.*/)?";
          i += 2;
        } else {
          re += ".*";
          i += 1;
        }
      } else {
        re += "[^/]*";
      }
    } else if (c === "?") {
      re += "[^/]";
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  const prefix = anchored ? "^" : "^(?:.*/)?";
  // een map-patroon (of patroon zonder wildcard aan het eind) matcht ook alles eronder
  return new RegExp(`${prefix}${re}(?:/.*)?$`);
}

interface IgnoreRule {
  pattern: string;
  negate: boolean;
  re: RegExp;
}

interface IgnoreConfig {
  rules: IgnoreRule[];
  /** Patronen die alles zouden matchen en daarom genegeerd zijn. */
  rejected: string[];
}

/** Patronen als "*", "**", "**\/*", "/" of "*.*" zetten het hele archief weg; die honoreren we niet. */
const CATCH_ALL = /^[*./]*$/;

function readIgnore(archive: Archive): IgnoreConfig {
  const file = archive.files.find((f) => f.path === IGNORE_FILE);
  const config: IgnoreConfig = { rules: [], rejected: [] };
  if (!file?.text) return config;
  for (const raw of splitLines(file.text)) {
    let line = raw.trim().replace(/\\/g, "/");
    if (!line || line.startsWith("#")) continue;
    const negate = line.startsWith("!");
    if (negate) line = line.slice(1).trim();
    if (!line) continue;
    if (!negate && CATCH_ALL.test(line)) {
      config.rejected.push(line);
      continue;
    }
    config.rules.push({ pattern: (negate ? "!" : "") + line, negate, re: globToRegExp(line) });
    if (config.rules.length >= MAX_PATTERNS) break;
  }
  return config;
}

/** gitignore-semantiek: het laatste patroon dat matcht wint ("!pad" maakt een eerdere uitsluiting ongedaan). */
function ignoredBy(rules: IgnoreRule[], path: string): IgnoreRule | null {
  let hit: IgnoreRule | null = null;
  for (const r of rules) {
    if (r.re.test(path)) hit = r.negate ? null : r;
  }
  return hit;
}

function downgrade(f: RawFinding, by: SuppressionSource, reason: string): RawFinding {
  return {
    ...f,
    severity: "info",
    // Tekst + ref blijven als fallback voor oudere rapporten (format.ts suppressionInfo, scoring)
    description: `${f.description} — Suppressed: ${reason} Original severity: ${f.severity}. The reviewer should confirm this exception.`,
    refs: [...f.refs, "suppressed"],
    suppressed: { by, originalSeverity: f.severity, reason },
  };
}

/** Uitzondering aangevraagd voor een blokkerende bevinding: severity blijft, reden wordt vermeld. */
function refuse(f: RawFinding, how: string): RawFinding {
  const what = f.scanner === "secrets" ? "Exposed credentials" : "Critical findings";
  return {
    ...f,
    description: `${f.description}\n\nException not applied: ${how}, but ${what.toLowerCase()} block publication and cannot be waived by the submitter. Fix the issue (for a credential: rotate it and remove it from the code). If you are sure it is a false positive — for example a revoked or fake test key — explain why in the submission so the reviewer can accept it.`,
  };
}

export interface SuppressionResult {
  findings: RawFinding[];
  note?: string;
}

export function applySuppressions(archive: Archive, findings: RawFinding[]): SuppressionResult {
  const ignore = readIgnore(archive);
  const byPath = new Map(archive.files.map((f) => [f.path, f]));
  const linesCache = new Map<string, string[]>();
  const linesOf = (path: string): string[] | null => {
    const cached = linesCache.get(path);
    if (cached) return cached;
    const text = byPath.get(path)?.text;
    if (!text) return null;
    const lines = splitLines(text);
    linesCache.set(path, lines);
    return lines;
  };
  const lineHasMarker = (path: string, line: number | undefined): boolean => {
    if (!line) return false;
    const lines = linesOf(path);
    if (!lines) return false;
    const here = lines[line - 1] ?? "";
    const above = lines[line - 2] ?? "";
    // Regel erboven telt alleen als het een losse commentaarregel is (zoals "# nosec" boven een lange regel)
    return INLINE_MARKER.test(here) || (COMMENT_LINE.test(above) && INLINE_MARKER.test(above));
  };

  let byFile = 0;
  let byInline = 0;
  let byTest = 0;
  let refused = 0;
  const patternHits = new Map<string, number>();

  const out = findings.map((f) => {
    if (f.severity === "info" || !f.file) return f;
    const file = f.file;
    const hit = ignoredBy(ignore.rules, file);
    const inline = !hit && lineHasMarker(file, f.line);
    if (isBlocking(f)) {
      if (hit || inline) {
        refused++;
        return refuse(f, hit ? `the path matches "${hit.pattern}" in ${IGNORE_FILE}` : "the line is marked with an inline exception comment");
      }
      // ook in test-/voorbeeldcode: een gelekte sleutel of kritieke bevinding is altijd echt
      return f;
    }
    if (hit) {
      byFile++;
      patternHits.set(hit.pattern, (patternHits.get(hit.pattern) ?? 0) + 1);
      return downgrade(f, "ignore-file", `path matches "${hit.pattern}" in ${IGNORE_FILE}.`);
    }
    if (inline) {
      byInline++;
      return downgrade(f, "inline", "marked with an inline exception comment (nosec / nosemgrep / gitleaks:allow / aigate:ignore).");
    }
    // secrets blijven tellen, ook in testcode: een gelekte sleutel is altijd echt
    if (f.scanner !== "secrets" && isTestOrSample(file)) {
      byTest++;
      return downgrade(f, "test-code", "located in test, example or demo code that is not part of the shipped asset.");
    }
    return f;
  });

  const parts: string[] = [];
  if (byFile) {
    const top = Array.from(patternHits.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([p, n]) => `"${p}" (${n})`)
      .join(", ");
    parts.push(`${byFile} by ${IGNORE_FILE} [${top}]`);
  }
  if (byInline) parts.push(`${byInline} by inline comments`);
  if (byTest) parts.push(`${byTest} in test/example/demo code`);
  const notes: string[] = [];
  if (parts.length) notes.push(`${parts.join(", ")} downgraded to info.`);
  if (refused) notes.push(`${refused} exception(s) not applied because the finding is blocking (critical or an exposed credential).`);
  if (ignore.rejected.length) {
    notes.push(`Ignored catch-all pattern(s) in ${IGNORE_FILE}: ${ignore.rejected.slice(0, 5).map((p) => `"${p}"`).join(", ")}.`);
  }
  return { findings: out, note: notes.length ? notes.join(" ") : undefined };
}
