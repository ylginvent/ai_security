import JSZip from "jszip";
import { gunzipSync, inflateSync } from "node:zlib";
import { decodeUtf8, LIMITS, MODEL_EXTENSIONS, type Archive, type RawFinding, type ScannerResult, type SourceFile } from "./archive";

/**
 * Model artefact scanning in de stijl van ModelScan (Protect AI): pickle-opcodes worden
 * echt geparsed om te zien welke Python-globals bij het laden worden geïmporteerd.
 */

const REFS = ["CWE-502", "OWASP LLM03:2025", "MITRE ATLAS AML.T0011"];

/* -------------------------------------------------------- unsafe / safe globals */

const ALL = "*";
const BUILTIN_DANGER = ["eval", "exec", "compile", "open", "getattr", "__import__", "apply", "breakpoint", "execfile", "input"];

/** ModelScan's unsafe-globals lijst (module → functies, of "*" voor de hele module). */
const UNSAFE: Record<string, string[] | typeof ALL> = {
  builtins: BUILTIN_DANGER,
  __builtin__: BUILTIN_DANGER,
  os: ALL, posix: ALL, nt: ALL, subprocess: ALL, sys: ALL, socket: ALL, shutil: ALL,
  runpy: ALL, pty: ALL, webbrowser: ALL, httplib: ALL, "http.client": ALL,
  "requests.api": ALL, "aiohttp.client": ALL, importlib: ALL, pickle: ALL, _pickle: ALL,
  bdb: ALL, pdb: ALL, asyncio: ALL, code: ALL, commands: ALL, ctypes: ALL,
  operator: ["attrgetter", "methodcaller"],
};

const SAFE_EXACT = new Set([
  "collections.OrderedDict", "collections.defaultdict", "collections.Counter", "collections.deque",
  "_codecs.encode", "copyreg._reconstructor", "copy_reg._reconstructor", "copyreg.__newobj__",
  "datetime.datetime", "datetime.date", "datetime.time", "datetime.timedelta", "datetime.timezone", "decimal.Decimal",
  "builtins.set", "builtins.frozenset", "builtins.slice", "builtins.bytearray", "builtins.complex", "builtins.range",
  "builtins.object", "builtins.list", "builtins.dict", "builtins.tuple", "builtins.int", "builtins.float",
  "builtins.str", "builtins.bytes", "builtins.bool",
  "__builtin__.set", "__builtin__.frozenset", "__builtin__.slice", "__builtin__.bytearray", "__builtin__.complex",
  "__builtin__.object", "__builtin__.list", "__builtin__.dict", "__builtin__.tuple", "__builtin__.int",
  "__builtin__.float", "__builtin__.long", "__builtin__.unicode", "__builtin__.str", "__builtin__.bool",
  "joblib.numpy_pickle.NumpyArrayWrapper", "joblib.numpy_pickle.NDArrayWrapper",
]);

const SAFE_PATTERNS = [
  /^torch\.(?:_utils\._rebuild_\w+|_tensor\._rebuild_from_type_v2|(?:storage\.)?\w*Storage|Size|device|dtype|(?:b?float|int|uint|complex)\d*|half|bool|nn\.parameter\.Parameter)$/,
  /^numpy\.(?:_?core\.(?:multiarray\.(?:_reconstruct|scalar)|numeric\._frombuffer)|dtype|ndarray|dtypes\.\w+|random\._pickle\.\w+)$/,
  /^(?:sklearn|scipy\.sparse|xgboost|lightgbm|catboost|pandas|transformers|tokenizers)\./,
];

type Verdict = "dangerous" | "safe" | "unknown";

function classify(module: string, name: string): Verdict {
  const full = `${module}.${name}`;
  const root = Object.keys(UNSAFE).find((m) => module === m || module.startsWith(`${m}.`));
  if (root !== undefined) {
    const rule = UNSAFE[root];
    if (rule === ALL || rule.includes(name.split(".")[0])) return "dangerous";
  }
  if (SAFE_EXACT.has(full) || SAFE_PATTERNS.some((p) => p.test(full))) return "safe";
  return "unknown";
}

/* ------------------------------------------------------------- pickle walker */

interface PickleGlobal {
  module: string;
  name: string;
  arg?: string;
}

interface WalkResult {
  globals: PickleGlobal[];
  /** Alle pickle-streams volledig geparsed? */
  complete: boolean;
  error?: string;
}

class Truncated extends Error {}

const latin1 = (b: Uint8Array, start: number, end: number) => {
  let s = "";
  for (let i = start; i < end; i += 8192) s += String.fromCharCode.apply(null, Array.from(b.subarray(i, Math.min(end, i + 8192))));
  return s;
};

/**
 * Minimale opcode-walker voor pickle protocol 0–5. Houdt GLOBAL/INST en STACK_GLOBAL bij
 * (met de twee laatst gepushte strings, inclusief memo-lookups) en slaat van elk opcode
 * de argumentbytes correct over.
 */
export function walkPickle(b: Uint8Array): WalkResult {
  const globals: PickleGlobal[] = [];
  let p = 0;
  let streams = 0;
  const need = (n: number) => {
    if (n < 0 || p + n > b.length) throw new Truncated("truncated pickle stream");
  };
  const u8 = () => {
    need(1);
    return b[p++];
  };
  const u16 = () => {
    need(2);
    const v = b[p] | (b[p + 1] << 8);
    p += 2;
    return v;
  };
  const u32 = () => {
    need(4);
    const v = (b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24)) >>> 0;
    p += 4;
    return v;
  };
  const u64 = () => {
    const lo = u32();
    const hi = u32();
    return hi * 0x100000000 + lo;
  };
  const line = () => {
    let e = p;
    while (e < b.length && b[e] !== 0x0a) e++;
    if (e >= b.length) throw new Truncated("unterminated text argument");
    const s = latin1(b, p, e);
    p = e + 1;
    return s;
  };
  const bytesStr = (n: number, utf: boolean) => {
    need(n);
    const end = p + n;
    const view = b.subarray(p, Math.min(end, p + 256));
    p = end;
    return utf ? decodeUtf8(view) : latin1(view, 0, view.length);
  };

  try {
    while (p < b.length && streams < 16) {
      // Nieuwe stream (legacy torch.save schrijft meerdere pickles achter elkaar)
      if (streams > 0 && b[p] !== 0x80) break;
      streams++;
      const recent: (string | null)[] = [];
      const memo = new Map<number, string | null>();
      let pending: PickleGlobal | null = null;
      const top = () => (recent.length ? recent[recent.length - 1] : null);
      const push = (v: string | null) => {
        recent.push(v);
        if (recent.length > 8) recent.shift();
        if (v !== null && pending && pending.arg === undefined) {
          pending.arg = v;
          pending = null;
        }
      };
      const addGlobal = (module: string, name: string) => {
        const g: PickleGlobal = { module: module.trim(), name: name.trim() };
        globals.push(g);
        pending = g;
        push(null);
      };

      let stop = false;
      while (!stop) {
        if (p >= b.length) throw new Truncated("pickle stream ended without STOP");
        const op = u8();
        switch (op) {
          case 0x2e: // STOP .
            stop = true;
            break;
          case 0x80: // PROTO
            u8();
            break;
          case 0x95: // FRAME
            u64();
            break;
          // geen argument, pusht een (niet-string) waarde
          case 0x28: case 0x4e: case 0x29: case 0x5d: case 0x7d: case 0x88: case 0x89: case 0x8f: case 0x51: case 0x52:
          case 0x81: case 0x92: case 0x85: case 0x86: case 0x87: case 0x74: case 0x6c: case 0x64: case 0x6f: case 0x91:
          case 0x97: case 0x98:
            push(null);
            break;
          // geen argument, wijzigt de stack zonder nieuwe waarde
          case 0x30: case 0x31: case 0x61: case 0x62: case 0x65: case 0x73: case 0x75: case 0x90:
            break;
          case 0x32: // DUP
            push(top());
            break;
          case 0x94: // MEMOIZE
            memo.set(memo.size, top());
            break;
          case 0x4b: case 0x82: // BININT1, EXT1
            u8();
            push(null);
            break;
          case 0x4d: case 0x83: // BININT2, EXT2
            u16();
            push(null);
            break;
          case 0x4a: case 0x84: // BININT, EXT4
            u32();
            push(null);
            break;
          case 0x47: // BINFLOAT
            need(8);
            p += 8;
            push(null);
            break;
          case 0x49: case 0x4c: case 0x46: case 0x50: // INT, LONG, FLOAT, PERSID (tekstregel)
            line();
            push(null);
            break;
          case 0x68: // BINGET
            push(memo.get(u8()) ?? null);
            break;
          case 0x6a: // LONG_BINGET
            push(memo.get(u32()) ?? null);
            break;
          case 0x67: // GET
            push(memo.get(parseInt(line(), 10)) ?? null);
            break;
          case 0x71: // BINPUT
            memo.set(u8(), top());
            break;
          case 0x72: // LONG_BINPUT
            memo.set(u32(), top());
            break;
          case 0x70: // PUT
            memo.set(parseInt(line(), 10), top());
            break;
          case 0x53: { // STRING 'repr'
            const s = line().trim();
            push(/^(['"]).*\1$/.test(s) ? s.slice(1, -1) : s);
            break;
          }
          case 0x56: // UNICODE (raw-unicode-escape)
            push(line());
            break;
          case 0x55: // SHORT_BINSTRING
            push(bytesStr(u8(), false));
            break;
          case 0x54: // BINSTRING
            push(bytesStr(u32(), false));
            break;
          case 0x8c: // SHORT_BINUNICODE
            push(bytesStr(u8(), true));
            break;
          case 0x58: // BINUNICODE
            push(bytesStr(u32(), true));
            break;
          case 0x8d: // BINUNICODE8
            push(bytesStr(u64(), true));
            break;
          case 0x43: // SHORT_BINBYTES
            bytesStr(u8(), false);
            push(null);
            break;
          case 0x42: // BINBYTES
            bytesStr(u32(), false);
            push(null);
            break;
          case 0x8e: case 0x96: // BINBYTES8, BYTEARRAY8
            bytesStr(u64(), false);
            push(null);
            break;
          case 0x8a: // LONG1
            bytesStr(u8(), false);
            push(null);
            break;
          case 0x8b: // LONG4
            bytesStr(u32(), false);
            push(null);
            break;
          case 0x63: // GLOBAL
          case 0x69: { // INST
            const module = line();
            const name = line();
            addGlobal(module, name);
            break;
          }
          case 0x93: { // STACK_GLOBAL
            const name = recent.length >= 1 ? recent[recent.length - 1] : null;
            const module = recent.length >= 2 ? recent[recent.length - 2] : null;
            addGlobal(module ?? "<unresolved>", name ?? "<unresolved>");
            break;
          }
          default:
            throw new Error(`unknown opcode 0x${op.toString(16).padStart(2, "0")} at offset ${p - 1}`);
        }
      }
    }
    return { globals, complete: true };
  } catch (e) {
    return { globals, complete: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/** Conservatieve fallback als de walker vastloopt (bijv. joblib met ingebedde array-data). */
const HEURISTIC = /\b(os|posix|nt|subprocess|builtins|__builtin__|socket|shutil|runpy|pty|webbrowser|importlib|commands)\b(?:[^A-Za-z0-9_]|[qhr][\s\S]){1,12}?\b(system|popen|execv?p?e?|execl\w*|spawn\w*|eval|exec|compile|getattr|__import__|apply|run|call|Popen|check_output|check_call|getoutput|create_connection|rmtree|run_path|run_module|import_module|open_new\w*)\b/g;

function heuristicGlobals(b: Uint8Array): PickleGlobal[] {
  const text = latin1(b, 0, b.length);
  const out: PickleGlobal[] = [];
  for (const m of text.matchAll(HEURISTIC)) {
    if (classify(m[1], m[2]) === "dangerous") out.push({ module: m[1], name: m[2] });
    if (out.length >= 20) break;
  }
  return out;
}

/* ------------------------------------------------------------------- helpers */

const isZipBytes = (b: Uint8Array) => b.length > 4 && b[0] === 0x50 && b[1] === 0x4b && b[2] === 3 && b[3] === 4;

function indexOfBytes(hay: Uint8Array, needle: string): number {
  const n = Array.from(needle, (c) => c.charCodeAt(0));
  const first = n[0];
  outer: for (let i = hay.indexOf(first); i >= 0 && i <= hay.length - n.length; i = hay.indexOf(first, i + 1)) {
    for (let j = 1; j < n.length; j++) if (hay[i + j] !== n[j]) continue outer;
    return i;
  }
  return -1;
}

const describeGlobal = (g: PickleGlobal) => {
  const call = `${g.module}.${g.name}`;
  if (g.arg === undefined) return `\`${call}\``;
  const arg = g.arg.length > 80 ? `${g.arg.slice(0, 79)}…` : g.arg;
  return `\`${call}(${JSON.stringify(arg)})\``;
};

const uniq = (gs: PickleGlobal[]) => {
  const seen = new Set<string>();
  return gs.filter((g) => {
    const k = `${g.module}.${g.name}|${g.arg ?? ""}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
};

/* --------------------------------------------------------------- per bestand */

interface PickleSource {
  label: string;
  bytes: Uint8Array;
}

/** Pickle-streams in een bestand: direct, gecomprimeerd (joblib) of binnen een torch-zip. */
async function pickleSources(file: SourceFile, b: Uint8Array): Promise<PickleSource[] | null> {
  if (isZipBytes(b)) {
    if (file.ext === ".keras" || file.ext === ".npz") return null;
    const zip = await JSZip.loadAsync(b);
    const out: PickleSource[] = [];
    for (const entry of Object.values(zip.files)) {
      if (entry.dir || !/\.pkl$/i.test(entry.name)) continue;
      out.push({ label: entry.name, bytes: await entry.async("uint8array") });
    }
    return out;
  }
  if (b[0] === 0x80) return [{ label: "", bytes: b }];
  const opts = { maxOutputLength: LIMITS.maxModelBytes * 2 };
  if (b[0] === 0x1f && b[1] === 0x8b) return [{ label: "gzip", bytes: new Uint8Array(gunzipSync(b, opts)) }];
  if (b[0] === 0x78 && (b[1] === 0x01 || b[1] === 0x5e || b[1] === 0x9c || b[1] === 0xda)) return [{ label: "zlib", bytes: new Uint8Array(inflateSync(b, opts)) }];
  // Protocol 0/1 begint met een tekst-opcode
  if ([".pkl", ".pickle", ".joblib", ".dill"].includes(file.ext) && b.length && "(c]}lNdKJ".includes(String.fromCharCode(b[0]))) return [{ label: "", bytes: b }];
  return file.ext === ".bin" ? null : [];
}

async function scanPickleFile(file: SourceFile, b: Uint8Array): Promise<RawFinding[]> {
  const sources = await pickleSources(file, b);
  if (sources === null) return [];
  if (!sources.length) {
    if (file.ext === ".bin") return [];
    return [
      {
        scanner: "model",
        ruleId: "pickle-unparsed",
        severity: "low",
        title: "Pickle-based model file could not be parsed",
        description: "The file has a pickle-family extension but its content is not a recognisable pickle stream (unknown compression or format), so it could not be verified to be free of executable payloads.",
        remediation: "Re-export the model in safetensors or ONNX format, or provide it uncompressed so it can be inspected.",
        refs: REFS,
        file: file.path,
      },
    ];
  }

  const dangerous: PickleGlobal[] = [];
  const unknown: PickleGlobal[] = [];
  let partial = false;
  for (const src of sources) {
    const res = walkPickle(src.bytes);
    let globals = res.globals;
    if (!res.complete) {
      partial = true;
      globals = globals.concat(heuristicGlobals(src.bytes));
    }
    for (const g of globals) {
      const v = classify(g.module, g.name);
      if (v === "dangerous") dangerous.push(g);
      else if (v === "unknown") unknown.push(g);
    }
  }

  const findings: RawFinding[] = [];
  const d = uniq(dangerous);
  const u = uniq(unknown.map((g) => ({ module: g.module, name: g.name })));
  if (d.length) {
    const first = d[0];
    findings.push({
      scanner: "model",
      ruleId: "pickle-dangerous-global",
      severity: "critical",
      title: `Model file executes code on load (${first.module}.${first.name})`,
      description: `The pickle stream imports ${d.slice(0, 6).map(describeGlobal).join(", ")}${d.length > 6 ? ` and ${d.length - 6} more` : ""}. Python resolves and calls these globals while deserialising, so loading the file with pickle, joblib or torch.load runs them before any model object is returned. This is the signature of a weaponised model artefact.`,
      remediation: "Do not load this file. Quarantine it, establish where it came from, and rebuild or re-export the model from a trusted source in a non-executable format (safetensors, ONNX, GGUF). Scan every third-party model before use and load PyTorch checkpoints with weights_only=True.",
      refs: REFS,
      file: file.path,
      snippet: d.slice(0, 3).map((g) => describeGlobal(g).replace(/`/g, "")).join("; "),
    });
  }
  if (u.length) {
    findings.push({
      scanner: "model",
      ruleId: "pickle-unknown-global",
      severity: "medium",
      title: "Unrecognised global imported by pickle",
      description: `The pickle stream imports ${u.slice(0, 8).map(describeGlobal).join(", ")}${u.length > 8 ? ` and ${u.length - 8} more` : ""}, which ${u.length === 1 ? "is" : "are"} not on the allow-list of known-safe ML reconstruction functions. Any importable callable can run code during unpickling, so these need to be reviewed.`,
      remediation: "Verify that each listed class or function is part of your own trusted code base. Prefer exporting weights to safetensors and reconstructing the model in code.",
      refs: REFS,
      file: file.path,
      snippet: u.slice(0, 4).map((g) => `${g.module}.${g.name}`).join(", "),
    });
  }
  if (!d.length && !u.length) {
    findings.push({
      scanner: "model",
      ruleId: "pickle-format",
      severity: "low",
      title: "Pickle-based model format",
      description: `No dangerous imports were found${partial ? " (the stream was only partially parseable; a byte-pattern check was applied to the rest)" : ""}, but pickle-based formats can execute code by design and every consumer of this artefact must trust its full supply chain.`,
      remediation: "Publish the weights in safetensors (or ONNX) format instead; for PyTorch use safetensors.torch.save_file, and load any remaining checkpoints with torch.load(..., weights_only=True).",
      refs: REFS,
      file: file.path,
    });
  }
  return findings;
}

async function scanKeras(file: SourceFile, b: Uint8Array): Promise<RawFinding[]> {
  let hay = b;
  if (isZipBytes(b)) {
    const zip = await JSZip.loadAsync(b);
    const cfg = zip.file("config.json");
    hay = cfg ? await cfg.async("uint8array") : new Uint8Array(0);
  }
  const found = ['"class_name": "Lambda"', '"class_name":"Lambda"', '\\"class_name\\": \\"Lambda\\"'].some((n) => indexOfBytes(hay, n) >= 0);
  if (!found) return [];
  return [
    {
      scanner: "model",
      ruleId: "keras-lambda-layer",
      severity: "high",
      title: "Keras model contains a Lambda layer",
      description: "Lambda layers store serialised Python bytecode in the model file. Loading the model (with safe_mode disabled, or with Keras < 2.13 / TensorFlow < 2.13) executes that code.",
      remediation: "Replace the Lambda layer with a registered custom layer class defined in source code, keep keras.models.load_model(..., safe_mode=True), and verify the artefact's origin.",
      refs: [...REFS, "CVE-2024-3660"],
      file: file.path,
    },
  ];
}

function npyObjectDtype(b: Uint8Array): boolean {
  if (b.length < 12 || b[0] !== 0x93 || latin1(b, 1, 6) !== "NUMPY") return false;
  const major = b[6];
  const len = major === 1 ? b[8] | (b[9] << 8) : (b[8] | (b[9] << 8) | (b[10] << 16) | (b[11] << 24)) >>> 0;
  const start = major === 1 ? 10 : 12;
  const header = latin1(b, start, Math.min(b.length, start + len, start + 4096));
  return /['"]descr['"]\s*:\s*['"][|<>=]?O/.test(header);
}

async function scanNumpy(file: SourceFile, b: Uint8Array): Promise<RawFinding[]> {
  const hits: string[] = [];
  if (file.ext === ".npz" && isZipBytes(b)) {
    const zip = await JSZip.loadAsync(b);
    for (const entry of Object.values(zip.files)) {
      if (!entry.dir && entry.name.endsWith(".npy") && npyObjectDtype(await entry.async("uint8array"))) hits.push(entry.name);
    }
  } else if (npyObjectDtype(b)) hits.push(file.name);
  if (!hits.length) return [];
  return [
    {
      scanner: "model",
      ruleId: "numpy-object-array",
      severity: "medium",
      title: "NumPy array with object dtype (requires allow_pickle)",
      description: `${hits.slice(0, 5).join(", ")} store${hits.length === 1 ? "s" : ""} Python objects, which NumPy can only load with allow_pickle=True — that unpickles the data and can execute embedded code.`,
      remediation: "Store numeric arrays with a numeric dtype, keep allow_pickle=False when loading, and use JSON or Parquet for non-numeric data.",
      refs: REFS,
      file: file.path,
    },
  ];
}

const PICKLE_EXT = new Set([".pkl", ".pickle", ".joblib", ".dill", ".pt", ".pth", ".ckpt", ".bin"]);

export async function scanModels(archive: Archive): Promise<ScannerResult> {
  const models = archive.files.filter((f) => MODEL_EXTENSIONS.has(f.ext));
  if (!models.length) return { findings: [], status: "skipped", note: "No model artefacts found in the upload." };

  const findings: RawFinding[] = [];
  let inspected = 0;
  const failures: string[] = [];
  for (const file of models) {
    const b = file.bytes;
    if (!b) {
      if (PICKLE_EXT.has(file.ext) && file.size > 0) {
        findings.push({
          scanner: "model",
          ruleId: "model-not-inspected",
          severity: "low",
          title: "Model artefact too large to inspect",
          description: `This ${file.ext} file (${Math.round(file.size / 1048576)} MB) exceeds the ${LIMITS.maxModelBytes / 1048576} MB inspection limit. It uses a pickle-capable format, so it may contain code that runs on load and could not be verified.`,
          remediation: "Publish large weights in safetensors format, or attach a ModelScan / picklescan report for this file to the submission.",
          refs: REFS,
          file: file.path,
        });
      }
      continue;
    }
    try {
      inspected++;
      if (PICKLE_EXT.has(file.ext)) findings.push(...(await scanPickleFile(file, b)));
      else if (file.ext === ".h5" || file.ext === ".keras") findings.push(...(await scanKeras(file, b)));
      else if (file.ext === ".npy" || file.ext === ".npz") findings.push(...(await scanNumpy(file, b)));
      // safetensors, onnx, gguf, pb: geen code-uitvoering bij laden → alleen geteld
    } catch (e) {
      failures.push(`${file.path}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  const notes = [`${inspected} of ${models.length} model file(s) inspected.`];
  if (failures.length) notes.push(`Could not parse: ${failures.slice(0, 3).join("; ")}.`);
  return { findings, note: notes.join(" ") };
}
