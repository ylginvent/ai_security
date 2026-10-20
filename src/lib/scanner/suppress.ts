import type { Archive, RawFinding, SourceFile } from "./archive";

/**
 * Uitzonderingen zoals bij Semgrep (.semgrepignore, nosemgrep), Bandit (# nosec) en Gitleaks (gitleaks:allow).
 * Onderdrukte bevindingen verdwijnen niet: ze worden "info" (tellen niet mee in score en gates) en houden
 * de reden in de beschrijving, zodat de reviewer kan zien wat er is weggezet.
 */

export const IGNORE_FILE = ".aigateignore";

const INLINE_MARKER = /\b(?:nosec|nosemgrep|gitleaks:allow|aigate[:-]ignore)\b/i;

/** Map- of bestandsnamen die op test-, voorbeeld- of demo-code wijzen. */
const TEST_DIR = /^(?:tests?|__tests__|spec|specs|fixtures?|samples?|examples?|demos?|testdata|mocks?|__mocks__)$/i;
const TEST_FILE = /(?:^|[._-])(?:tests?|spec|samples?|examples?|fixtures?|mocks?|demo)(?:[._-]|$)/i;

function isTestOrSample(path: string): boolean {
  const parts = path.split("/");
  const name = parts.pop() ?? "";
  return parts.some((p) => TEST_DIR.test(p)) || TEST_FILE.test(name.replace(/\.[^.]+$/, ""));
}

/** Zet een gitignore-achtig patroon om naar een RegExp (ondersteunt *, **, ?, map/ en patronen zonder slash). */
function globToRegExp(pattern: string): RegExp {
  let p = pattern.trim();
  const dirOnly = p.endsWith("/");
  if (dirOnly) p = p.slice(0, -1);
  const anchored = p.startsWith("/") || p.includes("/");
  p = p.replace(/^\//, "");
  let re = "";
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === "*") {
      if (p[i + 1] === "*") {
        // "**/" = nul of meer mappen, "**" aan het eind = alles
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

function readIgnore(archive: Archive): { pattern: string; re: RegExp }[] {
  const file = archive.files.find((f) => f.path === IGNORE_FILE);
  if (!file?.text) return [];
  return file.text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#") && !l.startsWith("!"))
    .slice(0, 200)
    .map((pattern) => ({ pattern, re: globToRegExp(pattern) }));
}

function lineHasMarker(file: SourceFile | undefined, line: number | undefined): boolean {
  if (!file?.text || !line) return false;
  const lines = file.text.split(/\r?\n/);
  const here = lines[line - 1] ?? "";
  const above = lines[line - 2] ?? "";
  return INLINE_MARKER.test(here) || INLINE_MARKER.test(above);
}

function downgrade(f: RawFinding, reason: string): RawFinding {
  return {
    ...f,
    severity: "info",
    description: `${f.description} — Suppressed: ${reason} Original severity: ${f.severity}. The reviewer should confirm this exception.`,
    refs: [...f.refs, "suppressed"],
  };
}

export interface SuppressionResult {
  findings: RawFinding[];
  note?: string;
}

export function applySuppressions(archive: Archive, findings: RawFinding[]): SuppressionResult {
  const ignore = readIgnore(archive);
  const byPath = new Map(archive.files.map((f) => [f.path, f]));
  let byFile = 0;
  let byInline = 0;
  let byTest = 0;

  const out = findings.map((f) => {
    if (f.severity === "info" || !f.file) return f;
    const hit = ignore.find((i) => i.re.test(f.file!));
    if (hit) {
      byFile++;
      return downgrade(f, `path matches "${hit.pattern}" in ${IGNORE_FILE}.`);
    }
    if (lineHasMarker(byPath.get(f.file), f.line)) {
      byInline++;
      return downgrade(f, "marked with an inline exception comment (nosec / nosemgrep / gitleaks:allow / aigate:ignore).");
    }
    // secrets blijven tellen, ook in testcode: een gelekte sleutel is altijd echt
    if (f.scanner !== "secrets" && isTestOrSample(f.file)) {
      byTest++;
      return downgrade(f, "located in test, example or demo code that is not part of the shipped asset.");
    }
    return f;
  });

  const parts: string[] = [];
  if (byFile) parts.push(`${byFile} by ${IGNORE_FILE}`);
  if (byInline) parts.push(`${byInline} by inline comments`);
  if (byTest) parts.push(`${byTest} in test/example/demo code`);
  return { findings: out, note: parts.length ? `${parts.join(", ")} downgraded to info.` : undefined };
}
