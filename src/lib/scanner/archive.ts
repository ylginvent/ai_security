import JSZip from "jszip";
import type { Finding, ScanStats, ScannerRun } from "../types";

/* ------------------------------------------------------------ gedeelde types */

export type RawFinding = Omit<Finding, "id">;

export interface ScannerResult {
  findings: RawFinding[];
  status?: ScannerRun["status"];
  note?: string;
}

export interface SourceFile {
  /** Genormaliseerd pad, zonder gemeenschappelijke top-level map. */
  path: string;
  /** Bestandsnaam zonder map. */
  name: string;
  /** Map ("" voor de root). */
  dir: string;
  /** Extensie in lowercase inclusief punt (".py"); dotfiles zoals ".env" krijgen hun eigen naam. */
  ext: string;
  size: number;
  language?: string;
  /** Tekstinhoud (alleen tekstbestanden ≤ 1 MB). Voor notebooks: de code cells. */
  text?: string;
  /** Ruwe bytes (alleen modelbestanden ≤ 60 MB). */
  bytes?: Uint8Array;
}

export interface Archive {
  kind: "zip" | "file";
  files: SourceFile[];
  stats: ScanStats;
  notes: string[];
}

/* ------------------------------------------------------------------- limieten */

const MB = 1024 * 1024;
export const LIMITS = {
  maxEntries: 5000,
  maxTotalBytes: 300 * MB,
  maxTextBytes: 1 * MB,
  maxModelBytes: 60 * MB,
  /** Totale hoeveelheid tekst die door de regex-scanners gaat (houdt de scan binnen de serverless timeout). */
  maxScanTextBytes: 80 * MB,
};

export const MODEL_EXTENSIONS = new Set([
  ".pkl", ".pickle", ".joblib", ".dill", ".pt", ".pth", ".ckpt", ".bin",
  ".h5", ".keras", ".onnx", ".safetensors", ".gguf", ".npy", ".npz", ".pb",
]);

const SKIP_DIRS = new Set([
  "node_modules", ".git", "venv", ".venv", "env", "__pycache__", "dist", "build",
  ".next", "site-packages", ".idea", ".vscode",
]);

/** Binaire formaten die we niet eens uitpakken. */
const BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tif", ".tiff", ".psd",
  ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
  ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".whl", ".jar", ".war", ".egg",
  ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".lib", ".class", ".pyc", ".pyo", ".pyd",
  ".woff", ".woff2", ".ttf", ".otf", ".eot",
  ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".flac", ".ogg", ".webm",
  ".parquet", ".feather", ".arrow", ".avro", ".orc", ".db", ".sqlite", ".sqlite3",
  ".faiss", ".index", ".tflite", ".mlmodel", ".msgpack",
]);

const LANGUAGES: Record<string, string> = {
  ".py": "Python", ".pyi": "Python", ".ipynb": "Notebook",
  ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
  ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
  ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin", ".scala": "Scala",
  ".cs": "C#", ".fs": "F#", ".go": "Go", ".rs": "Rust", ".rb": "Ruby", ".php": "PHP",
  ".c": "C", ".h": "C", ".cpp": "C++", ".cc": "C++", ".hpp": "C++", ".swift": "Swift",
  ".r": "R", ".jl": "Julia", ".sql": "SQL", ".sh": "Shell", ".bash": "Shell", ".ps1": "PowerShell",
  ".yaml": "YAML", ".yml": "YAML", ".json": "JSON", ".toml": "TOML", ".xml": "XML",
  ".csproj": "XML", ".tf": "Terraform", ".tfvars": "Terraform", ".bicep": "Bicep",
  ".md": "Markdown", ".mdx": "Markdown", ".rst": "reStructuredText",
  ".html": "HTML", ".htm": "HTML", ".css": "CSS", ".scss": "CSS", ".vue": "Vue", ".svelte": "Svelte",
};

/* -------------------------------------------------------------------- helpers */

export function normalisePath(p: string): string {
  return p
    .replace(/\\/g, "/")
    .split("/")
    .filter((s) => s !== "" && s !== "." && s !== "..")
    .join("/");
}

export function extOf(name: string): string {
  const lower = name.toLowerCase();
  const i = lower.lastIndexOf(".");
  if (i > 0) return lower.slice(i);
  return i === 0 ? lower : "";
}

export function isDockerfile(name: string): boolean {
  const n = name.toLowerCase();
  return n === "dockerfile" || n.startsWith("dockerfile.") || n.endsWith(".dockerfile") || n === "containerfile";
}

function languageOf(name: string, ext: string): string | undefined {
  if (isDockerfile(name)) return "Dockerfile";
  return LANGUAGES[ext];
}

export function splitLines(text: string): string[] {
  return text.split(/\r?\n/);
}

/** Regels die alleen commentaar zijn (Python/shell/YAML, C-stijl, HTML). */
export const COMMENT_LINE = /^\s*(?:#|\/\/|\/\*|\*|<!--)/;

export function snippetOf(line: string, max = 160): string {
  const t = line.trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}

export function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

const utf8 = new TextDecoder("utf-8");

export function decodeUtf8(bytes: Uint8Array): string {
  const text = utf8.decode(bytes);
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

function looksBinary(bytes: Uint8Array): boolean {
  const n = Math.min(bytes.length, 8192);
  for (let i = 0; i < n; i++) if (bytes[i] === 0) return true;
  return false;
}

/** Code cells uit een Jupyter notebook, zodat de regels erop kunnen draaien. */
function notebookCode(raw: string): string | null {
  try {
    const nb = JSON.parse(raw) as { cells?: unknown };
    if (!Array.isArray(nb.cells)) return null;
    const cells: string[] = [];
    for (const c of nb.cells as { cell_type?: unknown; source?: unknown }[]) {
      if (!c || c.cell_type !== "code") continue;
      const src = Array.isArray(c.source) ? c.source.filter((s): s is string => typeof s === "string").join("") : typeof c.source === "string" ? c.source : "";
      cells.push(src);
    }
    return cells.join("\n");
  } catch {
    return null;
  }
}

function declaredSize(f: JSZip.JSZipObject): number | undefined {
  const d = (f as unknown as { _data?: { uncompressedSize?: unknown } })._data;
  return d && typeof d.uncompressedSize === "number" ? d.uncompressedSize : undefined;
}

function isZip(data: Uint8Array): boolean {
  return data.length >= 4 && data[0] === 0x50 && data[1] === 0x4b && (data[2] === 3 || data[2] === 5 || data[2] === 7);
}

function describe(path: string, size: number): SourceFile {
  const slash = path.lastIndexOf("/");
  const name = slash >= 0 ? path.slice(slash + 1) : path;
  const ext = extOf(name);
  return { path, name, dir: slash >= 0 ? path.slice(0, slash) : "", ext, size, language: languageOf(name, ext) };
}

interface Entry {
  path: string;
  size?: number;
  read: () => Promise<Uint8Array>;
}

/* ------------------------------------------------------------------- uitpakken */

/**
 * Leest een zip (of één los bestand) in met limieten tegen zip-bombs en misbruik.
 * Mappen met vendored code of build-output worden overgeslagen.
 */
export async function readArchive(fileName: string, data: Uint8Array): Promise<Archive> {
  const notes: string[] = [];
  const stats: ScanStats = {
    filesTotal: 0, filesScanned: 0, filesSkipped: 0, bytesScanned: 0, linesScanned: 0,
    languages: {}, modelFiles: 0, packages: 0,
  };
  const baseName = normalisePath(fileName).split("/").pop() || "upload.bin";

  let kind: Archive["kind"] = "file";
  let entries: Entry[];
  if (isZip(data) && !MODEL_EXTENSIONS.has(extOf(baseName))) {
    let zip: JSZip;
    try {
      zip = await JSZip.loadAsync(data);
    } catch (e) {
      throw new Error(`The upload could not be read as a ZIP archive (${errorMessage(e)}).`);
    }
    kind = "zip";
    const objects = Object.values(zip.files).filter((f) => !f.dir && !/(^|\/)__MACOSX\//.test(f.name) && !/(^|\/)\.DS_Store$/.test(f.name));
    stats.filesTotal = objects.length;
    if (objects.length > LIMITS.maxEntries) {
      notes.push(`Archive contains ${objects.length} files; only the first ${LIMITS.maxEntries} were processed.`);
      stats.filesSkipped += objects.length - LIMITS.maxEntries;
    }
    const kept = objects.slice(0, LIMITS.maxEntries);
    const paths = kept.map((f) => normalisePath(f.name));
    // Eén gemeenschappelijke top-level map weghalen voor nette paden
    const first = paths.length ? paths[0].split("/")[0] : "";
    const strip = first !== "" && paths.every((p) => p.startsWith(`${first}/`));
    entries = kept.map((f, i) => ({
      path: strip ? paths[i].slice(first.length + 1) : paths[i],
      size: declaredSize(f),
      read: () => f.async("uint8array"),
    }));
  } else {
    stats.filesTotal = 1;
    entries = [{ path: baseName, size: data.length, read: async () => data }];
  }

  const files: SourceFile[] = [];
  let totalRead = 0;
  let textRead = 0;
  let vendored = 0;
  let tooLarge = 0;
  let unreadable = 0;
  let budgetHit = false;
  let textBudgetHit = false;

  for (const entry of entries) {
    if (!entry.path) {
      stats.filesSkipped++;
      continue;
    }
    const segments = entry.path.split("/");
    if (segments.slice(0, -1).some((s) => SKIP_DIRS.has(s.toLowerCase()))) {
      vendored++;
      stats.filesSkipped++;
      continue;
    }
    const file = describe(entry.path, entry.size ?? 0);
    files.push(file);
    const isModel = MODEL_EXTENSIONS.has(file.ext);
    if (isModel) stats.modelFiles++;
    else if (file.language) stats.languages[file.language] = (stats.languages[file.language] ?? 0) + 1;

    const limit = isModel ? LIMITS.maxModelBytes : LIMITS.maxTextBytes;
    if (budgetHit || (!isModel && BINARY_EXTENSIONS.has(file.ext))) {
      stats.filesSkipped++;
      continue;
    }
    if (entry.size !== undefined && entry.size > limit) {
      if (!isModel) tooLarge++;
      stats.filesSkipped++;
      continue;
    }
    if (totalRead + (entry.size ?? 0) > LIMITS.maxTotalBytes) {
      budgetHit = true;
      notes.push(`Stopped reading after ${Math.round(totalRead / MB)} MB of uncompressed content (limit ${LIMITS.maxTotalBytes / MB} MB); remaining files were not scanned.`);
      stats.filesSkipped++;
      continue;
    }

    let bytes: Uint8Array;
    try {
      bytes = await entry.read();
    } catch {
      unreadable++;
      stats.filesSkipped++;
      continue;
    }
    totalRead += bytes.length;
    file.size = bytes.length;
    if (bytes.length > limit) {
      if (!isModel) tooLarge++;
      stats.filesSkipped++;
      continue;
    }

    if (isModel) {
      file.bytes = bytes;
      stats.filesScanned++;
      stats.bytesScanned += bytes.length;
      continue;
    }
    if (looksBinary(bytes)) {
      stats.filesSkipped++;
      continue;
    }
    if (textRead + bytes.length > LIMITS.maxScanTextBytes) {
      textBudgetHit = true;
      stats.filesSkipped++;
      continue;
    }

    let text = decodeUtf8(bytes);
    if (file.ext === ".ipynb") text = notebookCode(text) ?? text;
    file.text = text;
    textRead += bytes.length;
    stats.filesScanned++;
    stats.bytesScanned += bytes.length;
    stats.linesScanned += text === "" ? 0 : text.split("\n").length;
  }

  if (vendored) notes.push(`${vendored} file(s) in dependency, VCS or build-output folders (node_modules, .git, venv, dist …) were skipped.`);
  if (tooLarge) notes.push(`${tooLarge} text file(s) larger than 1 MB were not content-scanned.`);
  if (unreadable) notes.push(`${unreadable} archive entr${unreadable === 1 ? "y" : "ies"} could not be decompressed (encrypted or corrupt).`);
  if (textBudgetHit) notes.push(`Content scanning stopped after ${LIMITS.maxScanTextBytes / MB} MB of source text; remaining files were inventoried only.`);

  return { kind, files, stats, notes };
}
