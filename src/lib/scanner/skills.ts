import type { Severity, SkillCheck, SkillReview } from "../types";
import { snippetOf, splitLines, type Archive, type RawFinding, type ScannerResult, type SourceFile } from "./archive";

/**
 * Review van Agent Skills (SKILL.md + reference-bestanden + scripts). Structuur- en kwaliteitschecks
 * volgen de gepubliceerde Agent Skills best practices; de securitychecks zoeken naar prompt injection,
 * exfiltratie, verborgen Unicode, remote code en te ruime tool-rechten. Alleen securityproblemen en een
 * ontbrekende/ongeldige name of description worden ook als Finding gerapporteerd.
 */

export interface SkillScanResult extends ScannerResult {
  skills: SkillReview[];
}

/* ------------------------------------------------------------------ algemeen */

const SCRIPT_EXTS = new Set([".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".ps1"]);
const MAX_LINE = 10000;
const MAX_FINDINGS_PER_CHECK = 10;
const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const isSkillMd = (f: SourceFile) => f.name.toLowerCase() === "skill.md";
const within = (dir: string, path: string) => dir === "" || path.startsWith(`${dir}/`);
const relPath = (dir: string, path: string) => (dir && path.startsWith(`${dir}/`) ? path.slice(dir.length + 1) : path);
const plural = (n: number, word: string, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;

function lineCount(text: string): number {
  if (text === "") return 0;
  return splitLines(text.replace(/\r?\n$/, "")).length;
}

function listShort(items: string[], max = 5): string {
  const shown = items.slice(0, max).join(", ");
  return items.length > max ? `${shown} and ${items.length - max} more` : shown;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Pad relatief aan `base` oplossen; null als het boven de archiefroot uitkomt. */
function resolveRel(base: string, target: string): string | null {
  const parts = base ? base.split("/") : [];
  for (const seg of target.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      if (!parts.length) return null;
      parts.pop();
      continue;
    }
    parts.push(seg);
  }
  return parts.join("/");
}

/* ------------------------------------------------------- redactie & weergave */

const KEY_VALUE = /((?:password|passwd|pwd|api[_-]?key|secret|token|credential|auth)[\w-]*["']?\s*[:=]\s*["']?)([^\s"']{4})[^\s"',;)]*/gi;
const LONG_TOKEN = /[A-Za-z0-9_\-+\/]{24,}/g;

/** Secret-achtige waarden in een snippet maskeren. */
function redact(line: string): string {
  return line
    .replace(KEY_VALUE, "$1$2****")
    .replace(LONG_TOKEN, (tok) => (/\d/.test(tok) && /[A-Za-z]/.test(tok) ? `${tok.slice(0, 4)}****` : tok));
}

/** Zero-width, bidi-controls, BOM midden in tekst en Unicode tag characters (ASCII smuggling). */
const INVISIBLE = /[\u200B-\u200F\u2060-\u2064\u202A-\u202E\u2066-\u2069\uFEFF]|\uDB40[\uDC00-\uDC7F]/g;

function invisibleCount(line: string): number {
  let n = 0;
  for (const m of line.matchAll(INVISIBLE)) {
    const i = m.index ?? 0;
    if (m[0] === "\u200D") {
      // Zero-width joiner binnen een emoji-reeks is legitiem
      const prev = line.charCodeAt(i - 1);
      if ((prev >= 0xdc00 && prev <= 0xdfff) || prev === 0xfe0f) continue;
    }
    n++;
  }
  return n;
}

function showInvisible(line: string): string {
  return line.replace(INVISIBLE, (ch) => `<U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}>`);
}

/* ---------------------------------------------------------------- frontmatter */

interface FrontField {
  value: string;
  /** 1-based regelnummer in SKILL.md. */
  line: number;
}

interface Frontmatter {
  fields: Map<string, FrontField>;
  /** 0-based index van de afsluitende --- regel. */
  end: number;
}

function unquote(s: string): string {
  const t = s.trim();
  if (t.length >= 2 && t[0] === '"' && t[t.length - 1] === '"') return t.slice(1, -1).replace(/\\n/g, "\n").replace(/\\(["\\])/g, "$1");
  if (t.length >= 2 && t[0] === "'" && t[t.length - 1] === "'") return t.slice(1, -1).replace(/''/g, "'");
  return t;
}

/** Splitst op komma's en witruimte buiten haakjes ("Bash(git status:*), Read" → 2 items). */
function splitTools(value: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let buf = "";
  for (const ch of value) {
    if (ch === "(") depth++;
    else if (ch === ")") depth = Math.max(0, depth - 1);
    if (depth === 0 && (ch === "," || /\s/.test(ch))) {
      if (buf.trim()) out.push(unquote(buf));
      buf = "";
      continue;
    }
    buf += ch;
  }
  if (buf.trim()) out.push(unquote(buf));
  return out.filter((t) => t !== "");
}

/** Minimale YAML-parser voor top-level velden: scalars, quoted strings, block scalars en lijsten. */
function parseFrontmatter(lines: string[]): Frontmatter | null {
  if (!lines.length || lines[0].trim() !== "---") return null;
  let end = -1;
  for (let i = 1; i < lines.length; i++) {
    if (/^(?:---|\.\.\.)\s*$/.test(lines[i])) {
      end = i;
      break;
    }
  }
  if (end < 0) return null;

  const fields = new Map<string, FrontField>();
  let i = 1;
  while (i < end) {
    const m = /^([A-Za-z0-9_-]+)\s*:(?:\s+(.*?))?\s*$/.exec(lines[i]);
    if (!m) {
      i++;
      continue;
    }
    const key = m[1].toLowerCase();
    const raw = (m[2] ?? "").trim();
    const line = i + 1;
    i++;
    const cont: string[] = [];
    while (i < end && (/^\s+\S/.test(lines[i]) || /^-\s/.test(lines[i]) || lines[i].trim() === "")) {
      cont.push(lines[i]);
      i++;
    }
    const trimmed = cont.map((l) => l.trim());
    let value: string;
    if (/^[|>][-+]?\d*$/.test(raw)) {
      value = raw.startsWith("|") ? trimmed.join("\n").trim() : trimmed.filter((l) => l !== "").join(" ");
    } else if (raw === "" && trimmed.some((l) => /^-\s/.test(l))) {
      value = trimmed
        .map((l) => /^-\s+(.*)$/.exec(l))
        .filter((x): x is RegExpExecArray => x !== null)
        .map((x) => unquote(x[1]))
        .join(", ");
    } else {
      const joined = [raw, ...trimmed.filter((l) => l !== "")].join(" ").trim();
      if (raw === "") value = joined;
      else if (/^\[.*\]$/.test(joined)) value = splitTools(joined.slice(1, -1)).join(", ");
      else value = unquote(joined);
    }
    fields.set(key, { value, line });
  }
  return { fields, end };
}

/* ----------------------------------------------------------------- referenties */

interface Ref {
  target: string;
  line: number;
}

const MD_LINK = /!?\[[^\]\n]*\]\(\s*<?([^)\s>]+)>?(?:\s+["'][^"'\n]*["'])?\s*\)/g;
const PATH_MENTION = /(?:^|[\s`'"(\[])((?:\.\/)?(?:scripts|references?|assets|templates|examples|docs|resources|forms|lib|bin)\/[\w.\/-]*[\w-]\.[A-Za-z0-9]{1,8})(?![\w\/-])/g;
const MD_MENTION = /`((?:\.\/)?[\w-]+(?:\/[\w-]+)*\.md)`/g;
const PROJECT_DOCS = new Set(["readme.md", "changelog.md", "contributing.md", "license.md", "claude.md", "agents.md", "skill.md", "security.md", "code_of_conduct.md"]);
const BACKSLASH_PATH = /(?:^|[\s`'"(\[])((?:[A-Za-z]:\\|\.{1,2}\\)?(?:[\w.-]+\\)+[\w.-]+\.[A-Za-z0-9]{1,8})(?![\w\\])/;

function cleanTarget(raw: string): string | null {
  let t = raw.trim();
  if (!t || /^(?:[a-z][a-z0-9+.-]*:|#|\/|~|\$|\{|<)/i.test(t)) return null; // URL, anker, absoluut pad, variabele
  t = t.split("#")[0].split("?")[0];
  try {
    t = decodeURIComponent(t);
  } catch {
    /* ongeldige escape: ongewijzigd laten */
  }
  return t || null;
}

/** Relatieve bestandsverwijzingen in markdown (links + vermeldingen als `scripts/x.py`). */
function collectRefs(lines: string[], offset: number, linksOnly = false): Ref[] {
  const refs: Ref[] = [];
  const seen = new Set<string>();
  lines.forEach((line, i) => {
    if (line.length > MAX_LINE) return;
    const add = (raw: string) => {
      const t = cleanTarget(raw);
      if (!t || seen.has(t)) return;
      seen.add(t);
      refs.push({ target: t, line: offset + i + 1 });
    };
    for (const m of line.matchAll(MD_LINK)) add(m[1]);
    if (linksOnly) return;
    for (const m of line.matchAll(PATH_MENTION)) add(m[1]);
    for (const m of line.matchAll(MD_MENTION)) {
      if (!PROJECT_DOCS.has((m[1].split("/").pop() ?? "").toLowerCase())) add(m[1]);
    }
  });
  return refs;
}

/* -------------------------------------------------------- kwaliteitsheuristiek */

const WHEN_TO_USE =
  /\buse (?:this|it|when|for|to|if|whenever|on|during)\b|\bwhen (?:the )?(?:user|users|you|working|asked|handling|dealing|processing|creating|editing|reviewing|analy[sz]ing|needed|requested|a user)\b|\bwhenever\b|\btrigger(?:s|ed)? (?:when|on|by|for)\b|\bfor [a-z]+ing\b|\bapplies (?:when|to)\b|\buseful (?:when|for)\b|\b(?:ideal|best|intended|designed) for\b/i;
const FIRST_PERSON = /^\s*(?:I|I'm|I'll|we|we'll|you|you'll|let me|let's)\b|\b(?:I can|I will|I'll|I help|I am|we can|you can use me)\b/i;
const TIME_SENSITIVE =
  /\b(?:as of|since|until|till|before|after|by)\s+(?:(?:early|mid|late|the end of|end of)\s+)?(?:(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?|q[1-4]|h[12])[\s,-]+)?(?:19|20)\d{2}\b|\bcurrently\b|\bat the time of writing\b|\bas of (?:today|now|this writing)\b|\bright now\b|\b(?:this|next|last) (?:year|month|quarter)\b|\bthe (?:latest|newest) version\b/i;
const LEGACY_HEADING = /^#{1,6}\s+.*\b(?:old|legacy|deprecated|changelog|change log|history|previous versions?)\b/i;
const WORKFLOW_HEADING = /^#{1,6}\s+.*\b(?:examples?|workflow|steps|usage|how to|instructions|process|procedure|quick ?start|getting started)\b/i;
const TOC = /^#{1,6}\s*(?:table of )?contents\b/im;
const TOC_LINK = /^\s*(?:[-*+]|\d+[.)])\s+\[[^\]]+\]\(#/;

const PY_STDLIB = new Set(
  (
    "__future__ _thread abc aifc argparse array ast asyncio atexit base64 bdb binascii bisect builtins bz2 calendar cgi cgitb chunk " +
    "cmath cmd code codecs codeop collections colorsys compileall concurrent configparser contextlib contextvars copy copyreg cProfile " +
    "csv ctypes curses dataclasses datetime dbm decimal difflib dis doctest email encodings ensurepip enum errno faulthandler fcntl " +
    "filecmp fileinput fnmatch fractions ftplib functools gc getopt getpass gettext glob graphlib grp gzip hashlib heapq hmac html " +
    "http imaplib importlib inspect io ipaddress itertools json keyword linecache locale logging lzma mailbox marshal math mimetypes " +
    "mmap modulefinder msvcrt multiprocessing netrc ntpath numbers opcode operator optparse os pathlib pdb pickle pickletools pkgutil " +
    "platform plistlib poplib posix posixpath pprint profile pstats pty pwd py_compile pyclbr pydoc queue quopri random re readline " +
    "reprlib resource rlcompleter runpy sched secrets select selectors shelve shlex shutil signal site smtplib socket socketserver " +
    "sqlite3 ssl stat statistics string stringprep struct subprocess symtable sys sysconfig syslog tabnanny tarfile tempfile termios " +
    "textwrap threading time timeit tkinter token tokenize tomllib trace traceback tracemalloc tty turtle types typing unicodedata " +
    "unittest urllib uuid venv warnings wave weakref webbrowser winreg winsound wsgiref xml xmlrpc zipapp zipfile zipimport zlib zoneinfo"
  ).split(" "),
);

const NODE_BUILTINS = new Set(
  (
    "assert async_hooks buffer child_process cluster console constants crypto dgram diagnostics_channel dns domain events fs http " +
    "http2 https inspector module net os path perf_hooks process punycode querystring readline repl stream string_decoder sys test " +
    "timers tls trace_events tty url util v8 vm wasi worker_threads zlib"
  ).split(" "),
);

/** Importnaam → gangbare PyPI-naam (als die afwijkt). */
const PY_DIST: Record<string, string> = {
  yaml: "pyyaml", PIL: "pillow", cv2: "opencv-python", sklearn: "scikit-learn", bs4: "beautifulsoup4", docx: "python-docx",
  pptx: "python-pptx", fitz: "pymupdf", dateutil: "python-dateutil", dotenv: "python-dotenv", jwt: "pyjwt", magic: "python-magic",
  Crypto: "pycryptodome", win32api: "pywin32", attr: "attrs", serial: "pyserial", OpenSSL: "pyopenssl", git: "gitpython",
  jose: "python-jose", multipart: "python-multipart", pypdf2: "PyPDF2",
};

function externalImports(file: SourceFile, localModules: Set<string>): string[] {
  const text = file.text ?? "";
  const found = new Set<string>();
  if (file.ext === ".py") {
    for (const line of splitLines(text)) {
      const imp = /^\s*import\s+([A-Za-z_][\w.]*(?:\s+as\s+\w+)?(?:\s*,\s*[A-Za-z_][\w.]*(?:\s+as\s+\w+)?)*)/.exec(line);
      const from = /^\s*from\s+([A-Za-z_]\w*)[\w.]*\s+import\b/.exec(line);
      const mods = imp ? imp[1].split(",").map((s) => (s.trim().split(/\s+/)[0] ?? "").split(".")[0] ?? "") : from ? [from[1]] : [];
      for (const mod of mods) if (mod && !PY_STDLIB.has(mod) && !localModules.has(mod)) found.add(mod);
    }
  } else if ([".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"].includes(file.ext)) {
    for (const m of text.matchAll(/(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*\(\s*|^\s*import\s+)['"]([^'"\n]+)['"]/gm)) {
      const spec = m[1];
      if (/^(?:\.|\/|node:|bun:|https?:)/.test(spec)) continue;
      const parts = spec.split("/");
      const name = spec.startsWith("@") ? parts.slice(0, 2).join("/") : (parts[0] ?? spec);
      if (!NODE_BUILTINS.has(name)) found.add(name);
    }
  }
  return Array.from(found);
}

function hasErrorHandling(file: SourceFile): boolean {
  const t = file.text ?? "";
  switch (file.ext) {
    case ".py":
      return (/^\s*try\s*:/m.test(t) && /^\s*except\b/m.test(t)) || /\bsys\.exit\s*\(|\braise\s+SystemExit\b/.test(t);
    case ".sh":
    case ".bash":
    case ".zsh":
      return /^\s*set\s+-[a-zA-Z]*e/m.test(t) || /^\s*set\s+-o\s+errexit\b/m.test(t) || /^#!.*\s-[a-zA-Z]*e\b/.test(t) || /\|\|\s*(?:exit|return)\b/.test(t) || /^\s*trap\s/m.test(t);
    case ".ps1":
      return /\$ErrorActionPreference\s*=\s*['"]Stop['"]/i.test(t) || /\btry\s*\{/i.test(t);
    default:
      return /\btry\s*\{/.test(t) || /\.catch\s*\(/.test(t) || /process\.exit(?:Code)?\b/.test(t);
  }
}

/* ------------------------------------------------------------------ security */

type SecId =
  | "hidden-unicode"
  | "prompt-injection"
  | "exfiltration"
  | "credential-access"
  | "remote-code"
  | "destructive"
  | "obfuscation"
  | "unrestricted-tools"
  | "safety-bypass"
  | "network-access"
  | "embedded-credentials";

interface SecDef {
  label: string;
  severity: Severity;
  title: string;
  risk: string;
  remediation: string;
  refs: string[];
  pass: string;
}

const SEC: Record<SecId, SecDef> = {
  "hidden-unicode": {
    label: "No hidden or invisible Unicode characters",
    severity: "high",
    title: "Hidden Unicode characters in skill file",
    risk: "Invisible characters (zero-width spaces, bidirectional overrides, Unicode tag characters) are not shown in editors or code review but are read by the model. They are used to smuggle instructions past reviewers (\"Trojan Source\", ASCII smuggling) or to make code behave differently from how it reads.",
    remediation: "Remove every zero-width, bidirectional-control and tag character (a pre-commit hook can reject U+200B–U+200F, U+202A–U+202E, U+2060–U+2064, U+2066–U+2069 and U+FEFF) and review the surrounding text for hidden instructions.",
    refs: ["OWASP LLM01:2025", "CVE-2021-42574", "CWE-1007"],
    pass: "No zero-width, bidirectional-control or tag characters found in the skill files.",
  },
  "prompt-injection": {
    label: "No prompt-injection or instruction-override text",
    severity: "high",
    title: "Instruction-override text in skill",
    risk: "Skill instructions are loaded into the agent's context with the same authority as the user's request. Text that tells the model to ignore earlier instructions, hide actions from the user or bypass safeguards is a prompt-injection payload that hijacks every agent that loads the skill.",
    remediation: "Remove the instruction. A skill must describe a task; it must never override system or user instructions or conceal actions from the user. If the text is an attack example (e.g. in a security-testing skill), quote it in a clearly labelled example file.",
    refs: ["OWASP LLM01:2025", "MITRE ATLAS AML.T0051"],
    pass: "No instruction-override, concealment or jailbreak phrases found.",
  },
  exfiltration: {
    label: "No data exfiltration",
    severity: "critical",
    title: "Skill sends data to an external endpoint",
    risk: "An agent that runs this skill would transmit user data, files, conversation content, environment variables or secrets to a third party outside Capgemini's control — a data breach that runs with the user's own permissions.",
    remediation: "Remove the upload. A skill must not send conversation content, files, environment variables or credentials to external endpoints. If results must be shared, write them to an approved Capgemini destination (e.g. SharePoint or Azure Storage via managed identity) after explicit user confirmation, and document the data flow.",
    refs: ["OWASP LLM02:2025", "OWASP LLM06:2025", "CWE-200", "MITRE ATLAS AML.T0057"],
    pass: "No instructions or code that send data to webhooks, paste sites, tunnels or other external collectors.",
  },
  "credential-access": {
    label: "No access to credential stores",
    severity: "high",
    title: "Skill reads credentials or secrets from the machine",
    risk: "The skill reads SSH keys, cloud credential files, .env files, browser cookie stores or dumps the full environment. Agents run with the user's identity, so this exposes every secret on the workstation or build agent.",
    remediation: "Remove access to credential locations. If the skill needs a credential, read one named variable (or use a managed identity) and document it; never read ~/.ssh, ~/.aws, .env files, browser profiles or the complete environment.",
    refs: ["OWASP LLM02:2025", "OWASP LLM06:2025", "CWE-200"],
    pass: "No reads of SSH keys, cloud credential files, .env files, browser stores or full environment dumps.",
  },
  "remote-code": {
    label: "No remote code fetched at runtime",
    severity: "high",
    title: "Skill downloads and executes remote code",
    risk: "Code fetched at run time (curl | sh, pip install from a URL, npx -y) is not part of the reviewed skill: whoever controls the URL or package can change what the agent executes at any moment, on every machine that uses the skill.",
    remediation: "Bundle the required scripts in the skill so they are reviewed with it, or install pinned packages from the approved internal registry. Never pipe downloaded content into a shell or interpreter.",
    refs: ["OWASP LLM03:2025", "OWASP LLM06:2025", "CWE-494"],
    pass: "No curl|sh, pip/npm installs from URLs, npx -y or download-and-execute patterns.",
  },
  destructive: {
    label: "No destructive commands",
    severity: "high",
    title: "Destructive command in skill",
    risk: "The skill contains a command that can irreversibly delete data, wipe disks, open up file permissions or rewrite shared Git history. An agent executing it — through a mistake or a prompt injection — causes damage that cannot be undone.",
    remediation: "Remove the command or scope it to a path inside a temporary working directory, and require explicit user confirmation for any destructive operation.",
    refs: ["OWASP LLM06:2025"],
    pass: "No rm -rf on root/home, mkfs, dd, chmod -R 777 or force-push commands.",
  },
  obfuscation: {
    label: "No obfuscated payloads",
    severity: "high",
    title: "Obfuscated or encoded payload in skill",
    risk: "Encoded blobs and eval/exec of decoded data hide what the skill really does from reviewers and scanners; legitimate skills have no reason to obfuscate their instructions or code.",
    remediation: "Replace the encoded content with readable source code or text so it can be reviewed. Never execute decoded data.",
    refs: ["OWASP LLM01:2025", "OWASP LLM03:2025", "CWE-506"],
    pass: "No long base64 blobs, hex-encoded payloads or execution of decoded data.",
  },
  "unrestricted-tools": {
    label: "Tool permissions are scoped (allowed-tools)",
    severity: "medium",
    title: "Skill pre-approves unrestricted shell access (allowed-tools)",
    risk: "allowed-tools lets the agent use the listed tools without asking the user. Granting Bash (or another shell) without a command restriction means any command — including ones injected through documents the skill processes — runs without a permission prompt.",
    remediation: "Restrict the grant to the exact commands the skill needs, e.g. allowed-tools: Bash(python scripts/extract.py:*), Read — or remove allowed-tools so the user approves each command.",
    refs: ["OWASP LLM06:2025", "CWE-250"],
    pass: "allowed-tools is absent or only grants scoped tools.",
  },
  "safety-bypass": {
    label: "Does not disable safety or permission prompts",
    severity: "medium",
    title: "Skill disables safety or permission prompts",
    risk: "The skill tells the agent to skip permission prompts or confirmations (e.g. --dangerously-skip-permissions, auto-approve). That removes the human check that limits the impact of mistakes and prompt injection.",
    remediation: "Remove the instruction; let the agent ask the user before running commands or changing files.",
    refs: ["OWASP LLM06:2025"],
    pass: "No instructions to skip permission prompts or auto-approve actions.",
  },
  "network-access": {
    label: "Scripts do not contact unexpected hosts",
    severity: "low",
    title: "Skill scripts contact external hosts",
    risk: "Network calls from bundled scripts send data out of the user's environment. Every destination must be expected and approved for the data the skill handles.",
    remediation: "Document each external host and why it is needed in SKILL.md, prefer Capgemini-hosted endpoints, and remove calls that are not required.",
    refs: ["OWASP LLM06:2025"],
    pass: "Bundled scripts contain no http(s) URLs to external hosts.",
  },
  "embedded-credentials": {
    label: "No embedded credentials",
    severity: "high",
    title: "Credentials embedded in skill",
    risk: "",
    remediation: "",
    refs: ["CWE-798"],
    pass: "The secret scanner found no credentials in the skill folder.",
  },
};

type Target = "doc" | "script" | "any";

interface LineRule {
  check: SecId;
  target: Target;
  pattern: RegExp;
  unless?: RegExp;
  /** Wat er gebeurt, als bijzin: "pipes a downloaded script into a shell". */
  what: string;
}

const CRED_PATHS =
  /~\/\.ssh\b|\$HOME\/\.ssh\b|\.ssh\/(?:id_[a-z0-9]+|authorized_keys|config)\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws\/(?:credentials|config)\b|\.azure\/(?:accessTokens\.json|msal_token_cache)|\.kube\/config\b|\.docker\/config\.json|\.netrc\b|\.git-credentials\b|\.npmrc\b|\.pypirc\b|\bLogin Data\b|(?:Chrome|Chromium|Firefox|Edge|Brave|Mozilla)[^\n]{0,60}\bCookies\b|cookies\.sqlite|security\s+find-(?:generic|internet)-password/i;
const ENV_DUMP =
  /\bdict\s*\(\s*os\.environ\s*\)|\bos\.environ\.(?:copy|items|keys|values)\s*\(|\{\s*\*\*os\.environ|json\.dumps\s*\(\s*os\.environ|\bos\.environ\s*[,)}\]]|\bprintenv\b|\$\(\s*env\s*\)|`env`|\benv\s*\||JSON\.stringify\s*\(\s*process\.env\s*\)|Object\.(?:entries|keys|values)\s*\(\s*process\.env\s*\)|Get-ChildItem\s+env:/i;
const READ_DOTENV = /(?:\bcat|\bopen|read_?text|readFileSync|readFile|Get-Content|\bsource)\s*\(?\s*['"]?(?:[\w~.$\/-]*\/)?\.env(?:\.\w+)?['"]?(?=\s|\)|,|;|$)/i;
const SEND =
  /\b(?:requests|httpx|session|client|aiohttp)\.(?:post|put|patch)\s*\(|\burllib\.request\.urlopen\s*\(|\burlopen\s*\(\s*(?:urllib\.request\.)?Request\s*\(|\baxios\.(?:post|put)\s*\(|\bfetch\s*\(|\bcurl\b[^\n]*(?:\s-d\b|\s--data|\s-F\b|\s--form\b|\s-T\b|\s--upload-file\b|-X\s*POST)|\bwget\b[^\n]*--post-(?:data|file)|\bInvoke-(?:RestMethod|WebRequest)\b[^\n]*-Method\s+(?:Post|Put)/i;
const EXFIL_HOSTS =
  /(?:discord(?:app)?\.com\/api\/webhooks|hooks\.slack\.com\/(?:services|workflows)|webhook\.site|webhook\.office\.com|pastebin\.com|paste\.ee|hastebin\.|ghostbin\.|requestbin|pipedream\.net|ngrok(?:-free)?\.(?:io|app|dev)|\.ngrok\.|burpcollaborator\.net|interact\.sh|\boast\.(?:pro|live|site|online|fun|me)\b|transfer\.sh|\b0x0\.st\b|\bfile\.io\b|beeceptor\.com|requestcatcher\.com|hookbin\.com|trycloudflare\.com|serveo\.net|\bloca\.lt\b|api\.telegram\.org\/bot)/i;

const LINE_RULES: LineRule[] = [
  /* prompt injection (SKILL.md en reference-bestanden) */
  {
    check: "prompt-injection",
    target: "doc",
    pattern: /\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|every\s+)?(?:of\s+)?(?:the\s+|your\s+|my\s+)?(?:previous|prior|above|earlier|preceding|original|system|other|existing)\s+(?:instructions?|prompts?|rules?|messages?|guidelines?|directions?|context|guardrails?)\b/i,
    what: "tells the model to ignore its earlier instructions",
  },
  { check: "prompt-injection", target: "doc", pattern: /\bdisregard\s+(?:the\s+|your\s+)?system\s+prompt\b/i, what: "tells the model to disregard its system prompt" },
  {
    check: "prompt-injection",
    target: "doc",
    pattern: /\byou\s+are\s+now\s+(?:a|an|in|the|no\s+longer|free|unrestricted|DAN|operating|acting|allowed|jailbroken)\b/i,
    what: "tries to give the model a new identity (\"you are now …\")",
  },
  {
    check: "prompt-injection",
    target: "doc",
    pattern: /\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|alert|warn|show|reveal\s+(?:this\s+|it\s+)?to|mention\s+(?:this\s+|it\s+)?to)\s+the\s+user\b/i,
    what: "tells the model to hide an action from the user",
  },
  {
    check: "prompt-injection",
    target: "doc",
    pattern: /\bwithout\s+(?:asking|informing|telling|notifying|alerting)\s+the\s+user\b|\bwithout\s+the\s+user'?s?\s+(?:knowledge|consent|permission)\b/i,
    what: "tells the model to act without the user's knowledge",
  },
  {
    check: "prompt-injection",
    target: "doc",
    pattern: /\bbypass(?:ing)?\s+(?:the\s+|any\s+|all\s+)?(?:safety|security|guardrails?|content\s+(?:filters?|polic(?:y|ies))|filters?|restrictions?|permissions?|approvals?|polic(?:y|ies)|moderation)\b/i,
    what: "tells the model to bypass safeguards",
  },
  { check: "prompt-injection", target: "doc", pattern: /\bjailbr(?:ea|o)k/i, what: "contains jailbreak language" },
  { check: "prompt-injection", target: "doc", pattern: /\b(?:reveal|print|output|repeat|leak)\s+(?:your|the)\s+(?:full\s+)?system\s+prompt\b/i, what: "asks the model to leak its system prompt" },
  { check: "prompt-injection", target: "doc", pattern: /<\|im_(?:start|end)\|>|<\|system\|>|\[\/?INST\]|<<SYS>>/, what: "contains raw chat-template control tokens" },

  /* exfiltratie */
  { check: "exfiltration", target: "any", pattern: EXFIL_HOSTS, what: "sends data to a webhook, paste site or tunnelling service" },
  {
    check: "exfiltration",
    target: "any",
    pattern: /\bcurl\b[^\n]*\s(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file)\s+['"]?[^\s'"]*@/i,
    what: "uploads a local file with curl",
  },
  {
    check: "exfiltration",
    target: "any",
    pattern: /\b(?:requests|httpx|session|client)\.(?:post|put|patch)\s*\([^\n]*(?:os\.environ|os\.getenv|secret|token|api_?key|password|credential)/i,
    what: "posts environment variables or secrets to a remote endpoint",
  },
  {
    check: "exfiltration",
    target: "doc",
    pattern:
      /\b(?:send|upload|post|forward|transmit|copy|sync|share|report)\b[^.\n]{0,60}\b(?:conversation|chat history|transcript|environment variables|env vars|\.env\b|credentials|secrets|api keys?|access tokens?|ssh keys?|passwords?|the user'?s? files)\b[^.\n]{0,60}\b(?:to|via)\b[^.\n]{0,40}(?:https?:\/\/|webhook|external|remote server|endpoint|pastebin|discord|telegram)/i,
    what: "instructs the agent to send sensitive data to an external destination",
  },
  { check: "exfiltration", target: "any", pattern: /\bexfiltrat/i, what: "mentions exfiltrating data" },

  /* credential stores */
  { check: "credential-access", target: "any", pattern: CRED_PATHS, what: "reads SSH keys, cloud credential files or browser credential stores" },
  { check: "credential-access", target: "any", pattern: READ_DOTENV, what: "reads a .env file" },
  {
    check: "credential-access",
    target: "any",
    pattern: /\bprintenv\b|\bdict\s*\(\s*os\.environ\s*\)|\bos\.environ\.(?:copy|items|keys|values)\s*\(|\{\s*\*\*os\.environ|json\.dumps\s*\(\s*os\.environ|JSON\.stringify\s*\(\s*process\.env\s*\)|Object\.(?:entries|keys|values)\s*\(\s*process\.env\s*\)|Get-ChildItem\s+env:/i,
    what: "dumps all environment variables",
  },

  /* remote code */
  {
    check: "remote-code",
    target: "any",
    pattern: /\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:(?:ba|z|da|k|fi)?sh|python[0-9.]*|node|perl|ruby|php|iex|Invoke-Expression)\b/i,
    what: "pipes a downloaded script into a shell or interpreter",
  },
  { check: "remote-code", target: "any", pattern: /\b(?:ba|z)?sh\s+(?:-c\s+)?["']?(?:<\(|\$\()\s*(?:curl|wget)\b/i, what: "executes the output of curl/wget" },
  { check: "remote-code", target: "any", pattern: /\b(?:iex|Invoke-Expression)\b[^\n]*(?:DownloadString|DownloadFile|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b)/i, what: "executes a downloaded PowerShell script" },
  { check: "remote-code", target: "any", pattern: /\bpip3?\s+install\b[^\n]*(?:git\+|https?:\/\/|--extra-index-url|--index-url\s+http:|--trusted-host)/i, what: "installs a Python package from a URL, Git repository or untrusted index" },
  { check: "remote-code", target: "any", pattern: /\bnpm\s+(?:i|install|add)\b[^\n]*(?:https?:\/\/|git\+|github:)/i, what: "installs an npm package from a URL or Git repository" },
  { check: "remote-code", target: "any", pattern: /\bnpx\s+(?:-y|--yes)\b/i, what: "runs an npm package with npx -y (auto-installs without review)" },
  { check: "remote-code", target: "any", pattern: /\b(?:exec|eval)\s*\(\s*(?:requests\.get|httpx\.get|urllib\.request\.urlopen|urlopen)\s*\(/i, what: "executes code downloaded at run time" },
  {
    check: "remote-code",
    target: "any",
    pattern: /\b(?:curl|wget)\b[^\n]*(?:\s-o|\s-O|--output)\s*\S+[^\n]*(?:&&|;)\s*(?:chmod\s+\+x|(?:ba)?sh\s|python[0-9.]*\s|\.\/)/i,
    what: "downloads a script and executes it",
  },

  /* destructief */
  {
    check: "destructive",
    target: "any",
    pattern: /\brm\s+(?:-[a-zA-Z-]+\s+)*-[a-zA-Z]*[rR][a-zA-Z]*\s+(?:-[a-zA-Z-]+\s+)*["']?(?:\/|~\/?|\$HOME\/?|\$\{HOME\}\/?)\*?["']?(?=$|[\s;&|`)])/,
    what: "recursively deletes the root or home directory",
  },
  { check: "destructive", target: "any", pattern: /\bmkfs(?:\.[a-z0-9]+)?\b/i, what: "formats a file system (mkfs)" },
  { check: "destructive", target: "any", pattern: /\bdd\s+if=/, what: "writes raw disk data with dd" },
  { check: "destructive", target: "any", pattern: /\bchmod\s+(?:-R\s+0?777|0?777\s+-R|-R\s+a\+rwx)\b/, what: "makes files world-writable recursively (chmod -R 777)" },
  { check: "destructive", target: "any", pattern: /\bgit\s+push\b[^\n]*(?:--force(?![\w-])|\s-f\b)/, what: "force-pushes and can overwrite shared Git history" },
  { check: "destructive", target: "any", pattern: /\bshutil\.rmtree\s*\(\s*(?:['"](?:\/|~)['"]|os\.path\.expanduser\(\s*['"]~['"]\s*\)|Path\.home\(\))/, what: "deletes the root or home directory from Python" },
  { check: "destructive", target: "any", pattern: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, what: "contains a fork bomb" },
  { check: "destructive", target: "any", pattern: />\s*\/dev\/(?:sd[a-z]|nvme\d|disk\d|hd[a-z])\b/, what: "overwrites a raw disk device" },

  /* obfuscatie */
  { check: "obfuscation", target: "any", pattern: /[A-Za-z0-9+\/]{200,}={0,2}/, unless: /data:[\w.+-]+\/[\w.+-]+;base64,/i, what: "contains a long base64-encoded blob" },
  { check: "obfuscation", target: "any", pattern: /\bbase64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/i, what: "decodes base64 and pipes it into a shell" },
  {
    check: "obfuscation",
    target: "any",
    pattern: /\b(?:eval|exec)\s*\(\s*(?:compile\s*\(\s*)?(?:base64\.b64decode|b64decode|base64\.decodebytes|codecs\.decode|bytes\.fromhex|bytearray\.fromhex|zlib\.decompress|marshal\.loads|atob|Buffer\.from|unescape|String\.fromCharCode|decodeURIComponent)\b/,
    what: "executes decoded data with eval/exec",
  },
  { check: "obfuscation", target: "any", pattern: /(?:\\x[0-9a-fA-F]{2}){16,}/, what: "contains a hex-escaped payload" },
  { check: "obfuscation", target: "any", pattern: /\b(?:bytes|bytearray)\.fromhex\s*\(\s*['"][0-9a-fA-F\s]{60,}/, what: "decodes a long hex string" },
  { check: "obfuscation", target: "any", pattern: /\bpowershell(?:\.exe)?\b[^\n]*\s-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+\/=]{20,}/i, what: "runs a base64-encoded PowerShell command" },

  /* veiligheidsprompts uitschakelen */
  {
    check: "safety-bypass",
    target: "any",
    pattern: /--dangerously-skip-permissions\b|--dangerously-bypass[\w-]*|\bbypassPermissions\b|["']?permission_?mode["']?\s*[:=]\s*["']?(?:bypass|auto)/i,
    what: "runs the agent with permission checks disabled",
  },
  { check: "safety-bypass", target: "any", pattern: /\bauto[- ]?approv(?:e|al|ing)\b|\bauto[- ]?accept(?:s|ing)?\b/i, what: "tells the agent to auto-approve actions" },
  {
    check: "safety-bypass",
    target: "any",
    pattern: /\b(?:don'?t|do not|never|without)\s+(?:ask(?:ing)?|prompt(?:ing)?|wait(?:ing)?|request(?:ing)?|seek(?:ing)?)\s+(?:the\s+user\s+)?(?:for\s+)?(?:the\s+user'?s?\s+)?(?:confirmation|approval|permission|consent)\b/i,
    what: "tells the agent not to ask for confirmation",
  },
  {
    check: "safety-bypass",
    target: "any",
    pattern: /\b(?:skip|disable|turn off)\s+(?:all\s+|any\s+|the\s+)?(?:safety|permission|confirmation|approval)\s+(?:checks?|prompts?|dialogs?|steps?)\b|--yolo\b|--no-confirm\b|--yes-to-all\b/i,
    what: "tells the agent to skip confirmation prompts",
  },
];

const UNRESTRICTED_TOOL = /^(?:Bash|Shell|Sh|Zsh|PowerShell|Pwsh|Terminal|Execute|Exec|Run|Computer|\*)(?:\(\s*(?:\*|:\*|\*:\*)?\s*\))?$/i;
const URL_HOST = /\bhttps?:\/\/([A-Za-z0-9.-]+\.[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?/g;
const LOCAL_HOST = /^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|(?:[\w-]+\.)*example\.(?:com|org|net)|[\w.-]+\.(?:local|localhost|test|invalid|example))$/i;

interface Hit {
  check: SecId;
  file: SourceFile;
  line: number;
  text: string;
  what: string;
}

/* --------------------------------------------------------------------- review */

interface Ctx {
  dir: string;
  skillFile: SourceFile;
  files: SourceFile[];
  exists: (path: string) => boolean;
  secretFindings: readonly RawFinding[];
}

interface Scored {
  check: SkillCheck;
  penalty: number;
}

function makeCheck(category: SkillCheck["category"], id: string, label: string, passed: boolean, detail: string, suggestion?: string): SkillCheck {
  const c: SkillCheck = { id, category, label, passed, detail };
  if (!passed && suggestion) c.suggestion = suggestion;
  return c;
}

function validateName(name: string): string[] {
  const p: string[] = [];
  if (name.length > 64) p.push(`is ${name.length} characters long (maximum 64)`);
  if (/<\/?[A-Za-z][^>]*>/.test(name)) p.push("contains XML tags");
  if (!/^[a-z0-9-]+$/.test(name)) p.push("may only contain lowercase letters, digits and hyphens");
  else if (/^-|-$|--/.test(name)) p.push("must not start or end with a hyphen or contain consecutive hyphens");
  if (/anthropic|claude/i.test(name)) p.push('contains a reserved word ("anthropic" or "claude")');
  return p;
}

function validateDescription(desc: string): string[] {
  const p: string[] = [];
  if (desc.length > 1024) p.push(`is ${desc.length} characters long (maximum 1024)`);
  if (/<\/?[A-Za-z][^>]*>/.test(desc)) p.push("contains XML tags");
  return p;
}

function frontmatterFinding(ruleId: string, title: string, description: string, remediation: string, file: SourceFile, line: number, lines: string[]): RawFinding {
  const text = lines[line - 1];
  return {
    scanner: "skill",
    ruleId,
    severity: "medium",
    title,
    description,
    remediation,
    refs: ["Agent Skills specification (SKILL.md frontmatter)"],
    file: file.path,
    line,
    snippet: text !== undefined && text.trim() !== "" ? snippetOf(redact(text)) : undefined,
  };
}

function reviewSkill(ctx: Ctx, findings: RawFinding[]): SkillReview {
  const { dir, skillFile, files, exists } = ctx;
  const text = skillFile.text ?? "";
  const lines = splitLines(text);
  const fm = skillFile.text === undefined ? null : parseFrontmatter(lines);
  const nameField = fm?.fields.get("name");
  const descField = fm?.fields.get("description");
  const name = nameField && nameField.value.trim() ? nameField.value.trim() : null;
  const description = descField && descField.value.trim() ? descField.value.trim().replace(/\s+/g, " ") : null;
  const bodyStart = fm ? fm.end + 1 : 0;
  const body = lines.slice(bodyStart);
  const folder = dir ? (dir.split("/").pop() ?? dir) : "";
  const label = name ?? (folder || "root skill");
  const where = `skill "${label}"`;
  const rel = (path: string) => relPath(dir, path);
  const docs = files.filter((f) => f.text !== undefined && !SCRIPT_EXTS.has(f.ext));
  const mdDocs = docs.filter((f) => (f.ext === ".md" || f.ext === ".mdx") && f !== skillFile);
  const scripts = files.filter((f) => SCRIPT_EXTS.has(f.ext));
  const scored: Scored[] = [];
  const add = (check: SkillCheck, penalty: number) => scored.push({ check, penalty: check.passed ? 0 : penalty });

  /* ---------------------------------------------------------- structuur */

  const unreadable = skillFile.text === undefined;
  add(
    makeCheck(
      "structure",
      "frontmatter",
      "SKILL.md has YAML frontmatter",
      fm !== null,
      fm
        ? "SKILL.md starts with a YAML frontmatter block delimited by ---."
        : unreadable
          ? "SKILL.md could not be read (binary, too large or unreadable)."
          : lines[0]?.trim() === "---"
            ? "The frontmatter block opened with --- is never closed."
            : "SKILL.md does not start with a YAML frontmatter block (--- … ---).",
      "Start SKILL.md with a frontmatter block: ---, then name: your-skill-name and description: what it does and when to use it, then ---.",
    ),
    10,
  );

  const nameProblems = name ? validateName(name) : [];
  add(
    makeCheck(
      "structure",
      "name",
      "Valid name in frontmatter",
      name !== null && !nameProblems.length,
      !name ? "The frontmatter has no name field." : nameProblems.length ? `name "${name}" ${nameProblems.join("; ")}.` : `name "${name}" follows the naming rules.`,
      "Use a short, lowercase, hyphenated name of at most 64 characters without \"anthropic\" or \"claude\", e.g. summarising-invoices.",
    ),
    10,
  );
  if (!name) {
    findings.push(
      frontmatterFinding(
        "skill-name-missing",
        "SKILL.md frontmatter: name is missing",
        `${where} has no name in its SKILL.md frontmatter. Agents identify, select and load skills by name; without it the skill cannot be registered or is loaded under an unpredictable identifier.`,
        "Add name: <lowercase-hyphenated-name> (max 64 characters) to the frontmatter at the top of SKILL.md.",
        skillFile,
        nameField?.line ?? 1,
        lines,
      ),
    );
  } else if (nameProblems.length) {
    findings.push(
      frontmatterFinding(
        "skill-name-invalid",
        "SKILL.md frontmatter: name is invalid",
        `The name of ${where} ${nameProblems.join("; ")}. Skills with an invalid name are rejected by the Claude API and other Agent Skills runtimes.`,
        "Rename the skill to lowercase letters, digits and hyphens only (max 64 characters) and avoid the reserved words \"anthropic\" and \"claude\".",
        skillFile,
        nameField?.line ?? 1,
        lines,
      ),
    );
  }

  const descProblems = description ? validateDescription(description) : [];
  add(
    makeCheck(
      "structure",
      "description",
      "Valid description in frontmatter",
      description !== null && !descProblems.length,
      !description ? "The frontmatter has no (or an empty) description field." : descProblems.length ? `The description ${descProblems.join("; ")}.` : `The description is ${description.length} characters long.`,
      "Add a description of at most 1024 characters, without XML tags, that says what the skill does and when to use it.",
    ),
    10,
  );
  if (!description) {
    findings.push(
      frontmatterFinding(
        "skill-description-missing",
        "SKILL.md frontmatter: description is missing",
        `${where} has no description. The agent decides whether to load a skill based solely on its description, so without one the skill is never (or randomly) selected.`,
        "Add description: <what the skill does>. Use when <trigger situations>. (max 1024 characters, third person).",
        skillFile,
        descField?.line ?? 1,
        lines,
      ),
    );
  } else if (descProblems.length) {
    findings.push(
      frontmatterFinding(
        "skill-description-invalid",
        "SKILL.md frontmatter: description is invalid",
        `The description of ${where} ${descProblems.join("; ")}. Agent Skills runtimes reject or truncate such descriptions.`,
        "Shorten the description to at most 1024 characters and remove any XML tags.",
        skillFile,
        descField?.line ?? 1,
        lines,
      ),
    );
  }

  if (dir && name) {
    add(
      makeCheck(
        "structure",
        "folder-name",
        "Folder name matches the skill name",
        folder === name,
        folder === name ? `The folder "${folder}" matches the skill name.` : `Warning: the folder is called "${folder}" but the skill name is "${name}".`,
        `Rename the folder to "${name}" (or the name to "${folder}") so the skill is installed and referenced under one consistent name.`,
      ),
      5,
    );
  }

  const refs = collectRefs(body, bodyStart);
  const resolved = refs.map((r) => ({ ...r, path: resolveRel(dir, r.target) }));
  const broken = resolved.filter((r) => r.path === null || !exists(r.path));
  add(
    makeCheck(
      "structure",
      "references-exist",
      "Referenced files exist",
      broken.length === 0,
      broken.length
        ? `SKILL.md references ${plural(broken.length, "file")} that ${broken.length === 1 ? "is" : "are"} not in the archive: ${listShort(broken.map((b) => `${b.target} (line ${b.line})`))}.`
        : refs.length
          ? `All ${plural(refs.length, "file reference")} in SKILL.md resolve to files in the skill.`
          : "SKILL.md does not reference other files.",
      "Add the missing files to the skill or correct the paths; the agent fails or improvises when a referenced file is missing.",
    ),
    10,
  );

  // Eén niveau diep: reference-bestanden mogen niet naar nog meer .md-bestanden doorverwijzen
  const direct = new Set(resolved.filter((r) => r.path !== null && exists(r.path)).map((r) => (r.path ?? "").toLowerCase()));
  const nested: string[] = [];
  for (const f of mdDocs) {
    if (!direct.has(f.path.toLowerCase()) || !f.text) continue;
    for (const r of collectRefs(splitLines(f.text), 0, true)) {
      const p = resolveRel(f.dir, r.target);
      if (!p || !/\.mdx?$/i.test(p) || !exists(p) || !within(dir, p)) continue;
      const lower = p.toLowerCase();
      if (direct.has(lower) || lower === skillFile.path.toLowerCase()) continue;
      nested.push(`${rel(f.path)} → ${rel(p)}`);
    }
  }
  add(
    makeCheck(
      "structure",
      "references-depth",
      "References are at most one level deep",
      nested.length === 0,
      nested.length
        ? `Reference files link on to further files that SKILL.md does not reference directly: ${listShort(nested)}. Agents often only preview such nested files and miss information.`
        : "Every reference file is linked directly from SKILL.md.",
      "Link every reference file directly from SKILL.md instead of chaining SKILL.md → a.md → b.md.",
    ),
    10,
  );

  const backslashes: string[] = [];
  for (const f of [skillFile, ...mdDocs]) {
    splitLines(f.text ?? "").forEach((l, i) => {
      if (l.length > MAX_LINE) return;
      const m = BACKSLASH_PATH.exec(l);
      if (m) backslashes.push(`${m[1]} (${rel(f.path)}:${i + 1})`);
    });
  }
  add(
    makeCheck(
      "structure",
      "forward-slashes",
      "Paths use forward slashes",
      backslashes.length === 0,
      backslashes.length ? `Windows-style paths found: ${listShort(backslashes)}.` : "No Windows-style backslash paths found.",
      "Use forward slashes (scripts/helper.py) in all paths; backslash paths break on Linux and macOS, where skills normally run.",
    ),
    10,
  );

  /* ---------------------------------------------------------- kwaliteit */

  if (description) {
    const when = WHEN_TO_USE.test(description);
    add(
      makeCheck(
        "quality",
        "description-when",
        "Description says what it does and when to use it",
        when,
        when ? "The description includes when the skill should be used." : "The description says what the skill does but not when to use it, so the agent has no clear trigger for loading it.",
        'Add a trigger sentence, e.g. "Use when the user asks to … or mentions …", with the key terms users actually type.',
      ),
      5,
    );
    const firstPerson = FIRST_PERSON.test(description);
    add(
      makeCheck(
        "quality",
        "third-person",
        "Description is written in the third person",
        !firstPerson,
        firstPerson ? "The description is written in the first or second person (\"I can …\", \"You can …\"); it is injected into the system prompt, where this reads inconsistently and hurts skill selection." : "The description is written in the third person.",
        'Rewrite it in the third person, e.g. "Extracts text and tables from PDF files. Use when …".',
      ),
      5,
    );
    const words = description.split(/\s+/).filter(Boolean).length;
    const specific = description.length >= 40 && words >= 6;
    add(
      makeCheck(
        "quality",
        "description-specific",
        "Description is specific",
        specific,
        specific ? `The description has ${words} words and names concrete capabilities.` : `The description is only ${description.length} characters (${plural(words, "word")}) — too vague for the agent to pick this skill among many others.`,
        "Describe the concrete operations and inputs (file types, systems, outputs) and include the terms users will use.",
      ),
      5,
    );
  }

  const bodyLines = lineCount(body.join("\n"));
  add(
    makeCheck(
      "quality",
      "body-length",
      "SKILL.md body under 500 lines",
      bodyLines < 500,
      `The SKILL.md body is ${plural(bodyLines, "line")} long.`,
      "Keep SKILL.md under 500 lines: move detailed reference material, API docs and long examples into separate files that SKILL.md links to, so they are only loaded when needed.",
    ),
    5,
  );

  const numbered = body.filter((l) => /^\s*\d+[.)]\s+\S/.test(l)).length;
  const hasWorkflow = body.some((l) => WORKFLOW_HEADING.test(l)) || numbered >= 2 || body.some((l) => /^\s*(?:```|~~~)/.test(l));
  add(
    makeCheck(
      "quality",
      "examples",
      "Has concrete examples or a step-by-step workflow",
      hasWorkflow,
      hasWorkflow ? "SKILL.md contains a workflow, numbered steps or code examples." : "SKILL.md has no examples, numbered steps or code blocks; the agent has to infer the procedure.",
      "Add a short workflow (numbered steps or a checklist) and at least one concrete input/output example or code block.",
    ),
    5,
  );

  const timeHits: string[] = [];
  for (const f of [skillFile, ...mdDocs]) {
    let legacy = false;
    let details = 0;
    splitLines(f.text ?? "").forEach((l, i) => {
      if (l.length > MAX_LINE) return;
      if (/^#{1,6}\s/.test(l)) legacy = LEGACY_HEADING.test(l);
      details += (l.match(/<details\b/gi) ?? []).length - (l.match(/<\/details>/gi) ?? []).length;
      if (legacy || details > 0) return;
      const m = TIME_SENSITIVE.exec(l);
      if (m) timeHits.push(`"${m[0]}" (${rel(f.path)}:${i + 1})`);
    });
  }
  add(
    makeCheck(
      "quality",
      "time-sensitive",
      "No time-sensitive information",
      timeHits.length === 0,
      timeHits.length ? `Time-sensitive wording found: ${listShort(timeHits)}. Such statements silently become wrong.` : "No date-dependent statements found.",
      'Describe the current method without dates, and move superseded behaviour into a collapsible "Old patterns" section.',
    ),
    5,
  );

  const noHandling = scripts.filter((f) => f.text !== undefined && !hasErrorHandling(f)).map((f) => rel(f.path));
  add(
    makeCheck(
      "quality",
      "script-errors",
      "Scripts handle errors explicitly",
      noHandling.length === 0,
      !scripts.length
        ? "The skill bundles no scripts."
        : noHandling.length
          ? `No error handling found in ${listShort(noHandling)}; failures surface as raw stack traces or are silently ignored, and the agent has to guess what went wrong.`
          : `All ${plural(scripts.length, "script")} handle errors (try/except, exit codes or set -e).`,
      "Handle expected failures in the script itself (try/except with a clear message and non-zero exit code in Python; set -euo pipefail in shell) instead of leaving them to the agent.",
    ),
    5,
  );

  const longNoToc = mdDocs
    .filter((f) => {
      const t = f.text ?? "";
      if (lineCount(t) <= 100) return false;
      return !TOC.test(t) && splitLines(t).filter((l) => TOC_LINK.test(l)).length < 3;
    })
    .map((f) => `${rel(f.path)} (${lineCount(f.text ?? "")} lines)`);
  add(
    makeCheck(
      "quality",
      "reference-toc",
      "Long reference files have a table of contents",
      longNoToc.length === 0,
      longNoToc.length ? `Reference files over 100 lines without a table of contents: ${listShort(longNoToc)}.` : "Reference files are short or start with a table of contents.",
      "Start every reference file longer than 100 lines with a table of contents, so the agent sees its full scope even when it only previews the file.",
    ),
    5,
  );

  const localModules = new Set<string>();
  for (const f of files) {
    if (f.ext === ".py") localModules.add(f.name.slice(0, -3));
    for (const seg of rel(f.dir).split("/")) if (seg) localModules.add(seg);
  }
  const manifests = files
    .filter((f) => /^(?:requirements[^/]*\.txt|pyproject\.toml|package\.json|Pipfile)$/i.test(f.name))
    .map((f) => f.text ?? "")
    .join("\n");
  const declaredText = `${text}\n${manifests}`;
  const mentioned = (n: string) => new RegExp(`(?:^|[^\\w-])${escapeRegExp(n)}(?:$|[^\\w-])`, "i").test(declaredText);
  const undeclared = new Set<string>();
  for (const f of scripts) {
    for (const mod of externalImports(f, localModules)) {
      const dist = PY_DIST[mod];
      if (!mentioned(mod) && !(dist && mentioned(dist))) undeclared.add(dist ?? mod);
    }
  }
  const missingDeps = Array.from(undeclared).sort();
  add(
    makeCheck(
      "quality",
      "dependencies-declared",
      "Script dependencies are declared",
      missingDeps.length === 0,
      missingDeps.length
        ? `Scripts import third-party packages that SKILL.md does not mention: ${listShort(missingDeps, 8)}.`
        : scripts.length
          ? "All third-party packages used by the scripts are mentioned in SKILL.md or a requirements file."
          : "The skill bundles no scripts.",
      `List the required packages and how to install them in SKILL.md (e.g. "pip install ${missingDeps.slice(0, 3).join(" ") || "<package>"}") and check they are available in the target runtime; the Claude API code-execution environment has no network access to install packages.`,
    ),
    5,
  );

  /* ----------------------------------------------------------- security */

  const hits: Hit[] = [];
  const hitKeys = new Set<string>();
  const addHit = (h: Hit) => {
    const key = `${h.check}|${h.file.path}|${h.line}`;
    if (hitKeys.has(key)) return;
    hitKeys.add(key);
    hits.push(h);
  };
  const invisibleHits: { file: SourceFile; line: number; text: string; count: number }[] = [];
  const hostLines = new Map<string, { file: SourceFile; line: number; text: string }>();

  for (const f of files) {
    if (f.text === undefined || f.text === "") continue;
    const isScript = SCRIPT_EXTS.has(f.ext);
    const rules = LINE_RULES.filter((r) => r.target === "any" || (r.target === "script") === isScript);
    const flines = splitLines(f.text);
    let invisible = 0;
    let firstInvisible = -1;
    let sendLine = -1;
    flines.forEach((raw, i) => {
      const l = raw.length > MAX_LINE ? raw.slice(0, MAX_LINE) : raw;
      const n = invisibleCount(l);
      if (n) {
        invisible += n;
        if (firstInvisible < 0) firstInvisible = i;
      }
      for (const r of rules) {
        if (r.pattern.test(l) && !(r.unless && r.unless.test(l))) addHit({ check: r.check, file: f, line: i + 1, text: l, what: r.what });
      }
      if (isScript) {
        if (sendLine < 0 && SEND.test(l)) sendLine = i;
        for (const m of l.matchAll(URL_HOST)) {
          const host = m[1].toLowerCase();
          if (!LOCAL_HOST.test(host) && !hostLines.has(host)) hostLines.set(host, { file: f, line: i + 1, text: l });
        }
      }
    });
    if (invisible) invisibleHits.push({ file: f, line: firstInvisible + 1, text: flines[firstInvisible] ?? "", count: invisible });
    // Script dat de omgeving of credentials verzamelt én iets verstuurt: exfiltratie
    if (isScript && sendLine >= 0 && (ENV_DUMP.test(f.text) || CRED_PATHS.test(f.text))) {
      addHit({
        check: "exfiltration",
        file: f,
        line: sendLine + 1,
        text: flines[sendLine] ?? "",
        what: "sends environment variables or credentials collected by the script to a remote endpoint",
      });
    }
  }

  for (const v of invisibleHits) {
    addHit({
      check: "hidden-unicode",
      file: v.file,
      line: v.line,
      text: showInvisible(v.text),
      what: `contains ${plural(v.count, "invisible Unicode character")} (first occurrence shown as <U+…>)`,
    });
  }

  const toolsField = fm?.fields.get("allowed-tools") ?? fm?.fields.get("allowed_tools");
  if (toolsField) {
    const broad = splitTools(toolsField.value).filter((t) => UNRESTRICTED_TOOL.test(t));
    if (broad.length) {
      addHit({
        check: "unrestricted-tools",
        file: skillFile,
        line: toolsField.line,
        text: lines[toolsField.line - 1] ?? "",
        what: `pre-approves ${broad.map((b) => `"${b}"`).join(", ")} without a command restriction`,
      });
    }
  }

  const hosts = Array.from(hostLines.keys()).sort();
  if (hosts.length) {
    const first = Array.from(hostLines.values()).sort((a, b) => (a.file.path === b.file.path ? a.line - b.line : a.file.path < b.file.path ? -1 : 1))[0];
    if (first) addHit({ check: "network-access", file: first.file, line: first.line, text: first.text, what: `contacts ${plural(hosts.length, "external host")}: ${listShort(hosts, 10)}` });
  }

  const secIds: SecId[] = ["hidden-unicode", "prompt-injection", "exfiltration", "credential-access", "remote-code", "destructive", "obfuscation", "unrestricted-tools", "safety-bypass", "network-access"];
  for (const id of secIds) {
    const def = SEC[id];
    const list = hits.filter((h) => h.check === id).sort((a, b) => (a.file.path === b.file.path ? a.line - b.line : a.file.path < b.file.path ? -1 : 1));
    const penalty = RANK[def.severity] >= RANK.high ? 25 : 10;
    const locations = list.map((h) => `${rel(h.file.path)}:${h.line}`);
    add(
      makeCheck(
        "security",
        id,
        def.label,
        list.length === 0,
        list.length ? `${list[0].what.charAt(0).toUpperCase()}${list[0].what.slice(1)} (${listShort(locations)}).` : def.pass,
        def.remediation,
      ),
      penalty,
    );
    list.slice(0, MAX_FINDINGS_PER_CHECK).forEach((h, idx) => {
      const extra = idx === MAX_FINDINGS_PER_CHECK - 1 && list.length > MAX_FINDINGS_PER_CHECK ? ` (+${list.length - MAX_FINDINGS_PER_CHECK} more occurrence(s) in this skill not listed individually.)` : "";
      findings.push({
        scanner: "skill",
        ruleId: `skill-${id}`,
        severity: def.severity,
        title: def.title,
        description: `In ${where}, ${rel(h.file.path)} line ${h.line} ${h.what}. ${def.risk}${extra}`,
        remediation: def.remediation,
        refs: def.refs,
        file: h.file.path,
        line: h.line,
        snippet: snippetOf(redact(h.text)),
      });
    });
  }

  // Secrets: al gemeld door de secret-scanner, hier alleen meegeteld in de skill-score
  const skillPaths = new Set(files.map((f) => f.path));
  const secrets = ctx.secretFindings.filter((f) => f.file !== undefined && skillPaths.has(f.file));
  let worst: Severity = "low";
  for (const s of secrets) if (RANK[s.severity] > RANK[worst]) worst = s.severity;
  const secretFiles = Array.from(new Set(secrets.map((s) => rel(s.file ?? "")))).sort();
  add(
    makeCheck(
      "security",
      "embedded-credentials",
      SEC["embedded-credentials"].label,
      secrets.length === 0,
      secrets.length ? `The secret scanner found ${plural(secrets.length, "credential")} in ${listShort(secretFiles)} (reported under Secret detection).` : SEC["embedded-credentials"].pass,
      "Remove the credentials from the skill, rotate them, and let scripts read a single named environment variable or use a managed identity instead.",
    ),
    RANK[worst] >= RANK.high ? 25 : 10,
  );

  /* --------------------------------------------------------- score & samenvatting */

  const checks = scored.map((s) => s.check);
  const score = Math.max(0, Math.min(100, 100 - scored.reduce((sum, s) => sum + s.penalty, 0)));
  return {
    path: dir,
    name,
    description,
    files: files.length,
    scripts: scripts.map((f) => rel(f.path)),
    lines: lineCount(text),
    checks,
    score,
    summary: summarise(checks),
  };
}

function summarise(checks: SkillCheck[]): string {
  const failed = (cat: SkillCheck["category"]) => checks.filter((c) => c.category === cat && !c.passed).length;
  const structure = failed("structure");
  const quality = failed("quality");
  const security = failed("security");
  const descIds = new Set(["description", "description-when", "description-specific", "third-person"]);
  const clearDescription = checks.filter((c) => descIds.has(c.id)).every((c) => c.passed);

  const first =
    structure === 0
      ? clearDescription
        ? "Well-structured skill with a clear description."
        : "Well-structured skill, but its description needs work."
      : `Skill has ${plural(structure, "structural problem")}${clearDescription ? "" : " and an unclear description"}.`;
  const improvements = quality ? `${plural(quality, "quality improvement")} suggested` : "No quality improvements needed";
  const second = security
    ? `${improvements}; ${plural(security, "security issue")} must be fixed before publication.`
    : `${improvements}; no security issues found.`;
  return `${first} ${second.charAt(0).toUpperCase()}${second.slice(1)}`;
}

/* ----------------------------------------------------------------------- scan */

/**
 * Zoekt elke SKILL.md (hoofdletterongevoelig) en reviewt de bijbehorende map. Bestanden horen bij de
 * diepst geneste skill-map waarin ze staan. `secretFindings` (van de secret-scanner) tellen mee in de
 * check "No embedded credentials" zonder opnieuw als Finding gemeld te worden.
 */
export function scanSkills(archive: Archive, secretFindings: readonly RawFinding[] = []): SkillScanResult {
  const skillFiles = archive.files.filter(isSkillMd);
  if (!skillFiles.length) {
    return { findings: [], skills: [], status: "skipped", note: "No SKILL.md found; the upload does not contain an Agent Skill." };
  }

  const byDir = new Map<string, SourceFile>();
  for (const f of skillFiles) if (!byDir.has(f.dir)) byDir.set(f.dir, f);
  const deepestFirst = Array.from(byDir.keys()).sort((a, b) => b.length - a.length);
  const members = new Map<string, SourceFile[]>();
  for (const d of deepestFirst) members.set(d, []);
  for (const f of archive.files) {
    const d = deepestFirst.find((x) => within(x, f.path));
    if (d !== undefined) members.get(d)?.push(f);
  }

  const paths = new Set<string>();
  const dirs = new Set<string>();
  for (const f of archive.files) {
    const lower = f.path.toLowerCase();
    paths.add(lower);
    const segs = lower.split("/");
    for (let i = 1; i < segs.length; i++) dirs.add(segs.slice(0, i).join("/"));
  }
  const exists = (path: string) => {
    const p = path.toLowerCase().replace(/\/+$/, "");
    return p === "" || paths.has(p) || dirs.has(p);
  };

  const findings: RawFinding[] = [];
  const skills: SkillReview[] = [];
  for (const dir of Array.from(byDir.keys()).sort()) {
    const skillFile = byDir.get(dir);
    if (!skillFile) continue;
    skills.push(reviewSkill({ dir, skillFile, files: members.get(dir) ?? [], exists, secretFindings }, findings));
  }

  const overview = skills.map((s) => `${s.name ?? (s.path || "root skill")} (score ${s.score})`);
  return {
    findings,
    skills,
    note: `Reviewed ${plural(skills.length, "skill")}: ${listShort(overview, 8)}.`,
  };
}
