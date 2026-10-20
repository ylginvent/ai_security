import "server-only";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { AuditEvent, Submission } from "./types";

export type NewSubmission = Pick<
  Submission,
  "asset_name" | "asset_version" | "owner_name" | "owner_email" | "business_unit" | "asset_type" | "answers" | "file_name" | "file_size" | "file_path" | "file_sha256"
>;

export interface UploadTarget {
  path: string;
  token: string;
  supabaseUrl: string;
  publishableKey: string;
  bucket: string;
}

/** Opslag van submissions, audit-events en geüploade bestanden. Supabase in productie, geheugen als fallback. */
export interface Store {
  kind: "supabase" | "memory";
  create(row: NewSubmission): Promise<Submission>;
  update(id: string, patch: Partial<Submission>): Promise<Submission>;
  get(id: string): Promise<Submission | null>;
  list(limit?: number): Promise<Submission[]>;
  addEvent(submissionId: string, actor: string, action: string, detail?: Record<string, unknown>): Promise<void>;
  events(submissionId: string): Promise<AuditEvent[]>;
  /** Signed upload URL zodat de browser grote bestanden direct naar de private bucket kan sturen. Null in geheugenmodus. */
  createUploadTarget(fileName: string): Promise<UploadTarget | null>;
  putFile(path: string, data: Uint8Array, contentType: string): Promise<void>;
  getFile(path: string): Promise<Uint8Array>;
}

const BUCKET = process.env.SUPABASE_BUCKET || "ai-assets";

export function uploadPath(fileName: string) {
  const safe = fileName.replace(/[^A-Za-z0-9._-]+/g, "_").slice(-80) || "upload.zip";
  const day = new Date().toISOString().slice(0, 10);
  return `submissions/${day}/${crypto.randomUUID()}/${safe}`;
}

/* ------------------------------------------------------------------ Supabase */

function supabaseStore(url: string, secretKey: string, publishableKey: string): Store {
  const db: SupabaseClient = createClient(url, secretKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const fail = (what: string, e: { message: string } | null) => {
    if (e) throw new Error(`${what}: ${e.message}`);
  };
  return {
    kind: "supabase",
    async create(row) {
      const { data, error } = await db.from("submissions").insert(row).select().single();
      fail("insert submission", error);
      return data as Submission;
    },
    async update(id, patch) {
      const { data, error } = await db.from("submissions").update(patch).eq("id", id).select().single();
      fail("update submission", error);
      return data as Submission;
    },
    async get(id) {
      if (!/^[0-9a-f-]{36}$/i.test(id)) return null;
      const { data, error } = await db.from("submissions").select("*").eq("id", id).maybeSingle();
      fail("get submission", error);
      return (data as Submission) ?? null;
    },
    async list(limit = 100) {
      const { data, error } = await db.from("submissions").select("*").order("created_at", { ascending: false }).limit(limit);
      fail("list submissions", error);
      return (data ?? []) as Submission[];
    },
    async addEvent(submission_id, actor, action, detail = {}) {
      const { error } = await db.from("audit_events").insert({ submission_id, actor, action, detail });
      fail("insert audit event", error);
    },
    async events(submissionId) {
      const { data, error } = await db.from("audit_events").select("*").eq("submission_id", submissionId).order("created_at", { ascending: true });
      fail("list audit events", error);
      return (data ?? []) as AuditEvent[];
    },
    async createUploadTarget(fileName) {
      const path = uploadPath(fileName);
      const { data, error } = await db.storage.from(BUCKET).createSignedUploadUrl(path);
      fail("create signed upload url", error);
      return { path, token: data!.token, supabaseUrl: url, publishableKey, bucket: BUCKET };
    },
    async putFile(path, data, contentType) {
      const { error } = await db.storage.from(BUCKET).upload(path, data, { contentType, upsert: false });
      fail("upload file", error);
    },
    async getFile(path) {
      const { data, error } = await db.storage.from(BUCKET).download(path);
      fail("download file", error);
      return new Uint8Array(await data!.arrayBuffer());
    },
  };
}

/* ------------------------------------------------------------------ geheugen (demo zonder Supabase) */

interface Mem {
  subs: Map<string, Submission>;
  events: AuditEvent[];
  files: Map<string, Uint8Array>;
}
const g = globalThis as unknown as { __aagMem?: Mem };

function memoryStore(): Store {
  const mem: Mem = (g.__aagMem ??= { subs: new Map(), events: [], files: new Map() });
  const copy = <T,>(v: T): T => structuredClone(v);
  return {
    kind: "memory",
    async create(row) {
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
      };
      mem.subs.set(s.id, s);
      return copy(s);
    },
    async update(id, patch) {
      const s = mem.subs.get(id);
      if (!s) throw new Error("submission not found");
      const next = { ...s, ...patch };
      mem.subs.set(id, next);
      return copy(next);
    },
    async get(id) {
      const s = mem.subs.get(id);
      return s ? copy(s) : null;
    },
    async list(limit = 100) {
      return [...mem.subs.values()].sort((a, b) => b.created_at.localeCompare(a.created_at)).slice(0, limit).map(copy);
    },
    async addEvent(submission_id, actor, action, detail = {}) {
      mem.events.push({ id: crypto.randomUUID(), submission_id, created_at: new Date().toISOString(), actor, action, detail });
    },
    async events(submissionId) {
      return mem.events.filter((e) => e.submission_id === submissionId).map(copy);
    },
    async createUploadTarget() {
      return null;
    },
    async putFile(path, data) {
      mem.files.set(path, data);
    },
    async getFile(path) {
      const f = mem.files.get(path);
      if (!f) throw new Error("file not found");
      return f;
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
  cached = url && secret && publishable ? supabaseStore(url, secret, publishable) : memoryStore();
  return cached;
}

/** Grootste bestand dat via de API-route zelf mag (Vercel body limit is 4.5 MB). */
export const INLINE_MAX_BYTES = 4 * 1024 * 1024;
/** Grootste upload via de signed URL. Moet passen bij de bucket-limiet in de migratie. */
export const STORAGE_MAX_BYTES = 50 * 1024 * 1024;
