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
  /**
   * True als limieten een deel van de upload buiten de scan hielden: de entry-limiet, het totale
   * groottebudget, het tekstbudget, of een (niet-lockfile) tekstbestand boven de groottelimiet.
   * Overgeslagen vendored mappen, binaire bestanden en geneste archieven tellen niet mee.
   */
  truncated: boolean;
}

/* ------------------------------------------------------------------- limieten */

const MB = 1024 * 1024;
export const LIMITS = {
  maxEntries: 5000,
  maxTotalBytes: 300 * MB,
  maxTextBytes: 1 * MB,
  maxModelBytes: 60 * MB,
  /** Lockfiles zijn vaak groter dan 1 MB, maar de SCA heeft ze nodig voor exacte versies. */
  maxLockfileBytes: 16 * MB,
  /** Totale hoeveelheid tekst die door de regex-scanners gaat (houdt de scan binnen de serverless timeout). */
  maxScanTextBytes: 80 * MB,
};

export const MODEL_EXTENSIONS = new Set([
  ".pkl", ".pickle", ".joblib", ".dill", ".pt", ".pth", ".ckpt", ".bin",
  ".h5", ".keras", ".onnx", ".safetensors", ".gguf", ".npy", ".npz", ".pb",
]);

/** Lockfiles die de dependency-scanner parseert; ze krijgen een ruimere groottelimiet. */
export const LOCKFILE_NAMES = new Set([
  "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
  "poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "Cargo.lock", "packages.lock.json", "gradle.lockfile",
]);

/** Geneste archieven: worden niet uitgepakt, de gebruiker krijgt dat te horen. */
const ARCHIVE_EXTENSIONS = new Set([".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".whl", ".jar", ".war", ".egg"]);
/** Gecompileerde code die niet als broncode te beoordelen is. */
const COMPILED_EXTENSIONS = new Set([".exe", ".dll", ".so", ".dylib", ".o", ".a", ".lib", ".class", ".pyc", ".pyo", ".pyd"]);

const SKIP_DIRS = new Set([
  "node_modules", ".git", "venv", ".venv", "env", "__pycache__", "dist", "build",
  ".next", "site-packages", ".idea", ".vscode",
]);
/** Mappen die nooit eigen broncode bevatten, ook niet als ze de top-level map van de zip zijn. */
const ALWAYS_VENDORED = new Set(["node_modules", "site-packages", ".git", "__pycache__", ".venv", "venv"]);

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

const utf16le = new TextDecoder("utf-16le");

/**
 * UTF-16-tekst herkennen (BOM, of ASCII-achtige tekst met om-en-om nul-bytes). Windows PowerShell 5.1
 * schrijft `pip freeze > requirements.txt` bijvoorbeeld als UTF-16LE; zonder deze stap zou het bestand
 * door de nul-bytes als binair worden overgeslagen.
 */
function decodeUtf16(bytes: Uint8Array): string | null {
  if (bytes.length < 2) return null;
  let le = bytes[0] === 0xff && bytes[1] === 0xfe;
  let be = bytes[0] === 0xfe && bytes[1] === 0xff;
  if (!le && !be && bytes.length >= 8) {
    const n = Math.min(bytes.length, 1024) & ~1;
    let zeroEven = 0;
    let zeroOdd = 0;
    for (let i = 0; i < n; i += 2) {
      if (bytes[i] === 0) zeroEven++;
      if (bytes[i + 1] === 0) zeroOdd++;
    }
    const pairs = n / 2;
    le = zeroEven === 0 && zeroOdd >= pairs * 0.9;
    be = zeroOdd === 0 && zeroEven >= pairs * 0.9;
  }
  if (le) return utf16le.decode(bytes);
  if (be) {
    const swapped = new Uint8Array(bytes.length & ~1);
    for (let i = 0; i + 1 < bytes.length; i += 2) {
      swapped[i] = bytes[i + 1];
      swapped[i + 1] = bytes[i];
    }
    return utf16le.decode(swapped);
  }
  return null;
}

function isSymlink(f: JSZip.JSZipObject): boolean {
  const p = (f as unknown as { unixPermissions?: unknown }).unixPermissions;
  return typeof p === "number" && (p & 0o170000) === 0o120000;
}

type NodeStreamFn = (type: "nodebuffer") => NodeJS.ReadableStream;

/**
 * Leest één zip-entry met een harde limiet op de uitgepakte grootte. De grootte in de zip-header kan
 * vervalst zijn (zip-bomb), dus er wordt gestreamd en afgebroken zodra `cap` wordt overschreden.
 * Geeft null terug als de entry groter is dan `cap`.
 */
export function readZipEntry(f: JSZip.JSZipObject, cap: number): Promise<Uint8Array | null> {
  const declared = declaredSize(f);
  if (declared !== undefined && declared > cap) return Promise.resolve(null);
  const nodeStream = (f as unknown as { nodeStream?: NodeStreamFn }).nodeStream;
  let stream: NodeJS.ReadableStream;
  try {
    if (typeof nodeStream !== "function") throw new Error("streams unavailable");
    stream = nodeStream.call(f, "nodebuffer");
  } catch {
    // Geen Node-streams beschikbaar: volledig uitpakken en achteraf controleren
    return f.async("uint8array").then((b) => (b.length > cap ? null : b));
  }
  return new Promise<Uint8Array | null>((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    let total = 0;
    let done = false;
    stream.on("data", (chunk: unknown) => {
      if (done) return;
      const buf = typeof chunk === "string" ? Buffer.from(chunk, "latin1") : (chunk as Uint8Array);
      total += buf.length;
      if (total > cap) {
        done = true;
        chunks.length = 0;
        stream.pause();
        const destroy = (stream as unknown as { destroy?: () => void }).destroy;
        if (typeof destroy === "function") destroy.call(stream);
        resolve(null);
        return;
      }
      chunks.push(buf);
    });
    stream.on("error", (e: unknown) => {
      if (done) return;
      done = true;
      reject(e instanceof Error ? e : new Error(String(e)));
    });
    stream.on("end", () => {
      if (done) return;
      done = true;
      const out = new Uint8Array(total);
      let offset = 0;
      for (const c of chunks) {
        out.set(c, offset);
        offset += c.length;
      }
      resolve(out);
    });
  });
}

function sample(paths: string[], max = 5): string {
  const shown = paths.slice(0, max).join(", ");
  return paths.length > max ? `${shown} and ${paths.length - max} more` : shown;
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

/** Herkent archiefformaten die we niet kunnen uitpakken aan hun magic bytes. */
function archiveFormat(b: Uint8Array): string | undefined {
  const at = (offset: number, sig: number[]) => b.length >= offset + sig.length && sig.every((v, i) => b[offset + i] === v);
  if (at(0, [0x1f, 0x8b])) return "gzip (.gz / .tar.gz)";
  if (at(0, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return "7-Zip (.7z)";
  if (at(0, [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07])) return "RAR";
  if (at(0, [0x42, 0x5a, 0x68]) && b[3] >= 0x31 && b[3] <= 0x39 && at(4, [0x31, 0x41, 0x59, 0x26, 0x53, 0x59])) return "bzip2";
  if (at(0, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) return "xz";
  if (at(0, [0x28, 0xb5, 0x2f, 0xfd])) return "Zstandard";
  if (at(257, [0x75, 0x73, 0x74, 0x61, 0x72])) return "tar";
  return undefined;
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
  /** Leest de inhoud; null als die groter is dan `cap`. */
  read: (cap: number) => Promise<Uint8Array | null>;
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
  let truncated = false;
  let vendored = 0;
  let symlinks = 0;
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
    const paths = objects.map((f) => normalisePath(f.name));
    // Eén gemeenschappelijke top-level map weghalen voor nette paden
    const first = paths.length ? paths[0].split("/")[0] : "";
    const strip = first !== "" && paths.every((p) => p.startsWith(`${first}/`));
    // Vendored mappen en symlinks eerst wegfilteren, zodat een meegezipte node_modules
    // de entry-limiet niet opsoupeert voordat de eigen broncode aan de beurt is.
    const candidates: Entry[] = [];
    objects.forEach((f, i) => {
      const path = strip ? paths[i].slice(first.length + 1) : paths[i];
      if (!path) {
        stats.filesSkipped++;
        return;
      }
      // Ook de weggehaalde top-level map meetellen: een zip met alleen node_modules/ heeft die als gemeenschappelijke map.
      // Alleen eenduidige dependency-mappen; een projectmap die toevallig "build" of "env" heet blijft gescand.
      const strippedVendored = strip && ALWAYS_VENDORED.has(first.toLowerCase());
      if (strippedVendored || path.split("/").slice(0, -1).some((s) => SKIP_DIRS.has(s.toLowerCase()))) {
        vendored++;
        stats.filesSkipped++;
        return;
      }
      if (isSymlink(f)) {
        symlinks++;
        stats.filesSkipped++;
        return;
      }
      candidates.push({ path, size: declaredSize(f), read: (cap) => readZipEntry(f, cap) });
    });
    if (candidates.length > LIMITS.maxEntries) {
      notes.push(
        `The archive contains ${candidates.length} files outside dependency and build folders; only the first ${LIMITS.maxEntries} were processed. Remove data sets, test fixtures or generated files from the upload to get full coverage.`,
      );
      stats.filesSkipped += candidates.length - LIMITS.maxEntries;
      truncated = true;
    }
    entries = candidates.slice(0, LIMITS.maxEntries);
  } else {
    // Eén los bestand: alleen bron/tekst of een modelbestand. Andere archiefformaten en binaire bestanden
    // zouden anders als één ondoorzichtig bestand "schoon" uit de scan komen.
    const ext = extOf(baseName);
    if (!MODEL_EXTENSIONS.has(ext)) {
      const format = archiveFormat(data);
      if (ext === ".zip") throw new Error("The upload could not be read as a ZIP archive (the file is not a valid zip).");
      if (format || ARCHIVE_EXTENSIONS.has(ext)) {
        throw new Error(`The upload could not be read as a ZIP archive: it is a ${format ?? ext} archive, which cannot be unpacked. Compress the folder as a .zip file instead.`);
      }
      if (BINARY_EXTENSIONS.has(ext) || (decodeUtf16(data) === null && looksBinary(data))) {
        throw new Error(`The upload could not be read as a ZIP archive or as a source file: ${baseName} is a binary file without scannable source code.`);
      }
    }
    stats.filesTotal = 1;
    entries = [{ path: baseName, size: data.length, read: async (cap) => (data.length > cap ? null : data) }];
  }

  const files: SourceFile[] = [];
  let totalRead = 0;
  let textRead = 0;
  const tooLarge: string[] = [];
  const nested: string[] = [];
  const compiled: string[] = [];
  let unreadable = 0;
  let budgetHit = false;
  let textBudgetHit = false;

  for (const entry of entries) {
    if (!entry.path) {
      stats.filesSkipped++;
      continue;
    }
    const file = describe(entry.path, entry.size ?? 0);
    files.push(file);
    const isModel = MODEL_EXTENSIONS.has(file.ext);
    if (isModel) stats.modelFiles++;
    else if (file.language) stats.languages[file.language] = (stats.languages[file.language] ?? 0) + 1;

    const limit = isModel ? LIMITS.maxModelBytes : LOCKFILE_NAMES.has(file.name) ? LIMITS.maxLockfileBytes : LIMITS.maxTextBytes;
    if (budgetHit) {
      stats.filesSkipped++;
      continue;
    }
    if (!isModel && BINARY_EXTENSIONS.has(file.ext)) {
      if (ARCHIVE_EXTENSIONS.has(file.ext)) nested.push(file.path);
      else if (COMPILED_EXTENSIONS.has(file.ext)) compiled.push(file.path);
      stats.filesSkipped++;
      continue;
    }
    // Te grote modelbestanden meldt de model-scanner zelf (als niet-geïnspecteerd)
    if (entry.size !== undefined && entry.size > limit) {
      if (!isModel) tooLarge.push(file.path);
      stats.filesSkipped++;
      continue;
    }
    if (totalRead + (entry.size ?? 0) > LIMITS.maxTotalBytes) {
      budgetHit = true;
      notes.push(`Stopped reading after ${Math.round(totalRead / MB)} MB of uncompressed content (limit ${LIMITS.maxTotalBytes / MB} MB); ${file.path} and all files after it were not scanned.`);
      stats.filesSkipped++;
      continue;
    }

    let bytes: Uint8Array | null;
    try {
      bytes = await entry.read(limit);
    } catch {
      unreadable++;
      stats.filesSkipped++;
      continue;
    }
    if (bytes === null) {
      // Werkelijke inhoud groter dan de limiet (of een vervalste grootte in de zip-header)
      file.size = Math.max(file.size, limit + 1);
      if (!isModel) tooLarge.push(file.path);
      stats.filesSkipped++;
      continue;
    }
    totalRead += bytes.length;
    file.size = bytes.length;

    if (isModel) {
      file.bytes = bytes;
      stats.filesScanned++;
      stats.bytesScanned += bytes.length;
      continue;
    }
    const utf16 = decodeUtf16(bytes);
    if (utf16 === null && looksBinary(bytes)) {
      stats.filesSkipped++;
      continue;
    }
    if (textRead + bytes.length > LIMITS.maxScanTextBytes) {
      textBudgetHit = true;
      stats.filesSkipped++;
      continue;
    }

    let text = utf16 ?? decodeUtf8(bytes);
    if (file.ext === ".ipynb") text = notebookCode(text) ?? text;
    file.text = text;
    textRead += bytes.length;
    stats.filesScanned++;
    stats.bytesScanned += bytes.length;
    stats.linesScanned += text === "" ? 0 : text.split("\n").length;
  }

  if (budgetHit || textBudgetHit || tooLarge.length) truncated = true;
  if (vendored) notes.push(`${vendored} file(s) in dependency, VCS or build-output folders (node_modules, .git, venv, dist …) were skipped.`);
  if (tooLarge.length) {
    notes.push(`${tooLarge.length} text file(s) larger than ${LIMITS.maxTextBytes / MB} MB (${LIMITS.maxLockfileBytes / MB} MB for lockfiles) were not content-scanned: ${sample(tooLarge)}.`);
  }
  if (nested.length) notes.push(`${nested.length} nested archive(s) were not unpacked or scanned: ${sample(nested)}. If they are part of the application, upload their contents unpacked.`);
  if (compiled.length) notes.push(`${compiled.length} compiled binary file(s) cannot be reviewed as source code: ${sample(compiled)}.`);
  if (symlinks) notes.push(`${symlinks} symbolic link(s) were not followed.`);
  if (unreadable) notes.push(`${unreadable} archive entr${unreadable === 1 ? "y" : "ies"} could not be decompressed (encrypted or corrupt).`);
  if (textBudgetHit) notes.push(`Content scanning stopped after ${LIMITS.maxScanTextBytes / MB} MB of source text; remaining files were inventoried only.`);

  return { kind, files, stats, notes, truncated };
}
