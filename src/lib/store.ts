import "server-only";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { readCapped, UpstreamError } from "./server/http";
import type { AuditEvent, CatalogStatus, ReviewStatus, Submission, SubmissionStatus, VersionRef } from "./types";

export type NewSubmission = Pick<
  Submission,
  "asset_name" | "asset_version" | "owner_name" | "owner_email" | "business_unit" | "asset_type" | "answers" | "file_name" | "file_size" | "file_path" | "file_sha256"
> & { previous_id?: string | null };

export interface UploadTarget {
  path: string;
  token: string;
  supabaseUrl: string;
  publishableKey: string;
  bucket: string;
}

/** Verwachte huidige waarden voor een conditionele update (optimistic concurrency). */
export interface UpdateExpectation {
  status?: SubmissionStatus;
  review_status?: ReviewStatus;
  catalog_status?: CatalogStatus;
}

export interface ListOptions {
  /** Zonder report, answers en file_path: veel lichter voor overzichten. */
  summary?: boolean;
}

/** Opslag van submissions, audit-events en geüploade bestanden. Supabase in productie, geheugen als fallback. */
export interface Store {
  kind: "supabase" | "memory";
  /** idempotencyKey: dezelfde sleutel levert bij een retry de bestaande submission op (zie findByIdempotencyKey). */
  create(row: NewSubmission, opts?: { idempotencyKey?: string }): Promise<Submission>;
  findByIdempotencyKey(key: string): Promise<Submission | null>;
  update(id: string, patch: Partial<Submission>): Promise<Submission>;
  /** Update alleen als de rij nog de verwachte status heeft. Null = iemand anders was eerder (of de rij bestaat niet). */
  updateIf(id: string, expect: UpdateExpectation, patch: Partial<Submission>): Promise<Submission | null>;
  get(id: string): Promise<Submission | null>;
  /** Nieuwste submission die als nieuwe versie van deze is ingediend (null zonder migratie 0003). */
  findNewerVersion(id: string): Promise<VersionRef | null>;
  list(limit?: number, opts?: ListOptions): Promise<Submission[]>;
  /** True als er al een submission naar dit opslagpad verwijst (een upload mag maar één keer gescand worden). */
  pathInUse(path: string): Promise<boolean>;
  addEvent(submissionId: string, actor: string, action: string, detail?: Record<string, unknown>): Promise<void>;
  events(submissionId: string): Promise<AuditEvent[]>;
  /** Signed upload URL zodat de browser grote bestanden direct naar de private bucket kan sturen. Null in geheugenmodus. */
  createUploadTarget(fileName: string): Promise<UploadTarget | null>;
  putFile(path: string, data: Uint8Array, contentType: string): Promise<void>;
  /** Leest een bestand met een harde groottelimiet (HttpError 413 als het groter is). */
  getFile(path: string, maxBytes: number): Promise<Uint8Array>;
  /** Best effort opruimen (bijv. een upload die niet tot een submission leidde). */
  removeFile(path: string): Promise<void>;
}

/** Grootste bestand dat via de API-route zelf mag (Vercel body limit is 4.5 MB). */
export const INLINE_MAX_BYTES = 4 * 1024 * 1024;
/** Grootste upload via de signed URL. Moet passen bij de bucket-limiet in de migratie. */
export const STORAGE_MAX_BYTES = 50 * 1024 * 1024;

const BUCKET = process.env.SUPABASE_BUCKET || "ai-assets";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** Na deze tijd kan een scan niet meer lopen (de functie heeft een maxDuration); de rij is dan blijven hangen. */
// Moet groter zijn dan maxDuration van /api/submissions (60 s) plus marge; verhoog mee als die omhoog gaat.
const STALE_SCAN_MS = 2 * 60 * 1000;
/** Kolom uit migratie 0002 ontbreekt nog: 42703 (Postgres) of PGRST204 (PostgREST schema cache). */
const missingColumn = (e: { code?: string } | null) => !!e && (e.code === "42703" || e.code === "PGRST204");
/** Optionele kolommen uit latere migraties, met de migratie die ze toevoegt. */
const OPTIONAL_COLUMNS: Record<string, string> = { idempotency_key: "0002_hardening.sql", previous_id: "0003_versions.sql" };
const VERSION_COLUMNS = "id,created_at,asset_version,status,decision,score";
const FILE_TIMEOUT_MS = 20_000;

/** Alle kolommen behalve de zware (report, answers) en het interne opslagpad. */
const SUMMARY_COLUMNS = [
  "id",
  "created_at",
  "asset_name",
  "asset_version",
  "owner_name",
  "owner_email",
  "business_unit",
  "asset_type",
  "file_name",
  "file_size",
  "file_sha256",
  "status",
  "decision",
  "score",
  "ai_act_tier",
  "counts",
  "error",
  "review_status",
  "reviewer",
  "review_comment",
  "reviewed_at",
  "catalog_status",
  "published_at",
].join(",");

export function uploadPath(fileName: string) {
  const safe = fileName.replace(/[^A-Za-z0-9._-]+/g, "_").slice(-80) || "upload.zip";
  const day = new Date().toISOString().slice(0, 10);
  return `submissions/${day}/${crypto.randomUUID()}/${safe}`;
}

/** Een scan die nooit is afgerond (functie gecrasht of time-out) als mislukt tonen in plaats van eeuwig "bezig". */
function normalize(s: Submission): Submission {
  if (s.status === "scanning" && Date.now() - Date.parse(s.created_at) > STALE_SCAN_MS) {
    return {
      ...s,
      status: "failed",
      error:
        s.error ??
        "The scan did not finish: the server stopped it at the time limit. Large archives and projects with many dependencies take longer; upload a zip without node_modules, build output, datasets or model weights.",
    };
  }
  return s;
}

function normalizeRef(r: VersionRef): VersionRef {
  if (r.status === "scanning" && Date.now() - Date.parse(r.created_at) > STALE_SCAN_MS) return { ...r, status: "failed" };
  return r;
}

/* ------------------------------------------------------------------ Supabase */

function supabaseStore(url: string, secretKey: string, publishableKey: string): Store {
  const db: SupabaseClient = createClient(url, secretKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const fail = (what: string, e: { message: string; code?: string } | null) => {
    if (e) throw new UpstreamError(`${what}: ${e.message}`, e.code);
  };
  return {
    kind: "supabase",
    async create(row, opts = {}) {
      const { previous_id, ...base } = row;
      const insert: Record<string, unknown> = { ...base };
      if (opts.idempotencyKey) insert.idempotency_key = opts.idempotencyKey;
      if (previous_id) insert.previous_id = previous_id;
      // Ontbreekt een kolom uit een latere migratie, dan zonder die kolom opnieuw proberen (en waarschuwen).
      for (;;) {
        const { data, error } = await db.from("submissions").insert(insert).select().single();
        if (!missingColumn(error)) {
          fail("insert submission", error);
          return data as Submission;
        }
        const optional = Object.keys(OPTIONAL_COLUMNS).filter((c) => c in insert);
        if (optional.length === 0) fail("insert submission", error);
        const named = optional.filter((c) => error?.message.includes(c));
        for (const c of named.length ? named : optional) {
          console.warn(`submissions.${c} is missing; run supabase/migrations/${OPTIONAL_COLUMNS[c]}`);
          delete insert[c];
        }
      }
    },
    async findByIdempotencyKey(key) {
      const { data, error } = await db.from("submissions").select("*").eq("idempotency_key", key).limit(1).maybeSingle();
      if (missingColumn(error)) return null;
      fail("find submission by idempotency key", error);
      return data ? normalize(data as Submission) : null;
    },
    async update(id, patch) {
      const { data, error } = await db.from("submissions").update(patch).eq("id", id).select().single();
      fail("update submission", error);
      return data as Submission;
    },
    async updateIf(id, expect, patch) {
      let q = db.from("submissions").update(patch).eq("id", id);
      if (expect.status !== undefined) q = q.eq("status", expect.status);
      if (expect.review_status !== undefined) q = q.eq("review_status", expect.review_status);
      if (expect.catalog_status !== undefined) q = q.eq("catalog_status", expect.catalog_status);
      const { data, error } = await q.select().maybeSingle();
      fail("update submission", error);
      return (data as Submission | null) ?? null;
    },
    async get(id) {
      if (!UUID.test(id)) return null;
      const { data, error } = await db.from("submissions").select("*").eq("id", id).maybeSingle();
      fail("get submission", error);
      return data ? normalize(data as Submission) : null;
    },
    async findNewerVersion(id) {
      if (!UUID.test(id)) return null;
      const { data, error } = await db
        .from("submissions")
        .select(VERSION_COLUMNS)
        .eq("previous_id", id)
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle();
      if (missingColumn(error)) return null;
      fail("find newer version", error);
      return data ? normalizeRef(data as unknown as VersionRef) : null;
    },
    async list(limit = 100, opts = {}) {
      if (opts.summary) {
        const { data, error } = await db.from("submissions").select(SUMMARY_COLUMNS).order("created_at", { ascending: false }).limit(limit);
        fail("list submissions", error);
        const rows = (data ?? []) as unknown as Omit<Submission, "report" | "answers" | "file_path">[];
        return rows.map((r) => normalize({ ...r, answers: {}, report: null, file_path: null }));
      }
      const { data, error } = await db.from("submissions").select("*").order("created_at", { ascending: false }).limit(limit);
      fail("list submissions", error);
      return ((data ?? []) as Submission[]).map(normalize);
    },
    async pathInUse(path) {
      const { data, error } = await db.from("submissions").select("id").eq("file_path", path).limit(1);
      fail("check upload reference", error);
      return (data ?? []).length > 0;
    },
    async addEvent(submission_id, actor, action, detail = {}) {
      const { error } = await db.from("audit_events").insert({ submission_id, actor, action, detail });
      fail("insert audit event", error);
    },
    async events(submissionId) {
      if (!UUID.test(submissionId)) return [];
      const { data, error } = await db.from("audit_events").select("*").eq("submission_id", submissionId).order("created_at", { ascending: true });
      fail("list audit events", error);
      return (data ?? []) as AuditEvent[];
    },
    async createUploadTarget(fileName) {
      const path = uploadPath(fileName);
      const { data, error } = await db.storage.from(BUCKET).createSignedUploadUrl(path);
      fail("create signed upload url", error);
      if (!data) throw new UpstreamError("create signed upload url: empty response");
      return { path, token: data.token, supabaseUrl: url, publishableKey, bucket: BUCKET };
    },
    async putFile(path, data, contentType) {
      const { error } = await db.storage.from(BUCKET).upload(path, data, { contentType, upsert: false });
      fail("upload file", error);
    },
    async getFile(path, maxBytes) {
      // via een kortlevende signed URL streamen, zodat de groottelimiet tijdens het downloaden geldt
      const { data, error } = await db.storage.from(BUCKET).createSignedUrl(path, 60);
      if (error || !data) throw new Error(`file not found: ${error?.message ?? "no signed url"}`);
      const res = await fetch(data.signedUrl, { signal: AbortSignal.timeout(FILE_TIMEOUT_MS), cache: "no-store" });
      if (!res.ok) {
        await res.body?.cancel().catch(() => undefined);
        throw new Error(`file download failed: HTTP ${res.status}`);
      }
      return readCapped(res, maxBytes, `Files are limited to ${Math.round(maxBytes / 1024 / 1024)} MB.`);
    },
    async removeFile(path) {
      const { error } = await db.storage.from(BUCKET).remove([path]);
      if (error) console.warn("remove file failed", path, error.message);
    },
  };
}

/* ------------------------------------------------------------------ geheugen (demo zonder Supabase) */

interface Mem {
  subs: Map<string, Submission>;
  events: AuditEvent[];
  files: Map<string, Uint8Array>;
  /** idempotency key -> submission id (optioneel: een globale Mem van vóór deze versie heeft hem nog niet). */
  idem?: Map<string, string>;
}
const g = globalThis as unknown as { __aagMem?: Mem };
/** Demo-modus bewaart bestanden alleen kort; zonder limiet groeit het geheugen van de instance onbeperkt. */
const MEMORY_MAX_FILES = 20;

function memoryStore(): Store {
  const mem: Mem = (g.__aagMem ??= { subs: new Map(), events: [], files: new Map() });
  const idem: Map<string, string> = (mem.idem ??= new Map());
  const copy = <T,>(v: T): T => structuredClone(v);
  const matches = (s: Submission, expect: UpdateExpectation) =>
    (expect.status === undefined || s.status === expect.status) &&
    (expect.review_status === undefined || s.review_status === expect.review_status) &&
    (expect.catalog_status === undefined || s.catalog_status === expect.catalog_status);
  return {
    kind: "memory",
    async create(row, opts = {}) {
      const s: Submission = {
        ...row,
        id: crypto.randomUUID(),
        created_at: new Date().toISOString(),
        status: "scanning",
        decision: null,
        score: null,
        ai_act_tier: null,
        counts: null,
        report: null,
        error: null,
        review_status: "pending",
        reviewer: null,
        review_comment: null,
        reviewed_at: null,
        catalog_status: "not_published",
        published_at: null,
        previous_id: row.previous_id ?? null,
      };
      if (opts.idempotencyKey) {
        if (idem.has(opts.idempotencyKey)) throw new UpstreamError("duplicate idempotency key", "23505");
        idem.set(opts.idempotencyKey, s.id);
      }
      mem.subs.set(s.id, copy(s));
      return copy(s);
    },
    async findByIdempotencyKey(key) {
      const id = idem.get(key);
      const s = id ? mem.subs.get(id) : undefined;
      return s ? normalize(copy(s)) : null;
    },
    async update(id, patch) {
      const s = mem.subs.get(id);
      if (!s) throw new Error("submission not found");
      const next = { ...s, ...copy(patch), id: s.id };
      mem.subs.set(id, next);
      return copy(next);
    },
    async updateIf(id, expect, patch) {
      // synchroon tussen get en set: in één Node-proces is dit atomair
      const s = mem.subs.get(id);
      if (!s || !matches(s, expect)) return null;
      const next = { ...s, ...copy(patch), id: s.id };
      mem.subs.set(id, next);
      return copy(next);
    },
    async get(id) {
      const s = mem.subs.get(id);
      return s ? normalize(copy(s)) : null;
    },
    async findNewerVersion(id) {
      let best: Submission | null = null;
      for (const s of mem.subs.values()) if (s.previous_id === id && (!best || s.created_at > best.created_at)) best = s;
      if (!best) return null;
      const { created_at, asset_version, status, decision, score } = best;
      return normalizeRef({ id: best.id, created_at, asset_version, status, decision, score });
    },
    async list(limit = 100, opts = {}) {
      return [...mem.subs.values()]
        .sort((a, b) => b.created_at.localeCompare(a.created_at))
        .slice(0, limit)
        .map((s) => normalize(opts.summary ? { ...copy({ ...s, report: null }), answers: {}, file_path: null } : copy(s)));
    },
    async pathInUse(path) {
      for (const s of mem.subs.values()) if (s.file_path === path) return true;
      return false;
    },
    async addEvent(submission_id, actor, action, detail = {}) {
      mem.events.push({ id: crypto.randomUUID(), submission_id, created_at: new Date().toISOString(), actor, action, detail: copy(detail) });
    },
    async events(submissionId) {
      return mem.events.filter((e) => e.submission_id === submissionId).map(copy);
    },
    async createUploadTarget() {
      return null;
    },
    async putFile(path, data) {
      mem.files.set(path, data);
      while (mem.files.size > MEMORY_MAX_FILES) {
        const oldest = mem.files.keys().next().value;
        if (oldest === undefined) break;
        mem.files.delete(oldest);
      }
    },
    async getFile(path, maxBytes) {
      const f = mem.files.get(path);
      if (!f) throw new Error("file not found");
      if (f.byteLength > maxBytes) throw new Error("file too large");
      return f;
    },
    async removeFile(path) {
      mem.files.delete(path);
    },
  };
}

let cached: Store | null = null;

export function getStore(): Store {
  if (cached) return cached;
  const url = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL;
  const secret = process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY;
  const publishable =
    process.env.SUPABASE_PUBLISHABLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || process.env.SUPABASE_ANON_KEY;
  if (url && secret && publishable) {
    cached = supabaseStore(url, secret, publishable);
  } else {
    if (url || secret || publishable) {
      // half geconfigureerd: niet stilletjes in demo-modus draaien zonder dat iemand het merkt
      console.warn("Supabase is partially configured (need SUPABASE_URL, SUPABASE_SECRET_KEY and SUPABASE_PUBLISHABLE_KEY); falling back to in-memory demo mode.");
    }
    cached = memoryStore();
  }
  return cached;
}
