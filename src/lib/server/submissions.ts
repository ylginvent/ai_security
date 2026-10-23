import "server-only";
import { createHash } from "node:crypto";
import { compareWithPrevious } from "../compare";
import { consistencyFindings } from "../consistency";
import { ALL_QUESTIONS, isVisible, questionnaireFindings, validateAnswers } from "../questionnaire";
import { evaluate } from "../scoring";
import { ENGINE_VERSION, scanArchive, type ScanOutput } from "../scanner";
import { getStore, INLINE_MAX_BYTES, STORAGE_MAX_BYTES, uploadPath, type UpdateExpectation } from "../store";
import type { Answers, Report, ReviewStatus, Submission } from "../types";
import { HttpError, str, UpstreamError } from "./http";

/** Houdt alleen bekende, zichtbare vragen over en alleen geldige optiewaarden. Alles van de client is onbetrouwbaar. */
export function sanitizeAnswers(input: unknown): Answers {
  const raw = input && typeof input === "object" && !Array.isArray(input) ? (input as Record<string, unknown>) : {};
  const out: Answers = {};
  for (const q of ALL_QUESTIONS) {
    const v = raw[q.id];
    if (v === undefined || v === null) continue;
    if (q.options) {
      const allowed = new Set(q.options.map((o) => o.value));
      if (q.kind === "multi") {
        const list = (Array.isArray(v) ? v : [v]).filter((x): x is string => typeof x === "string" && allowed.has(x));
        if (list.length) out[q.id] = [...new Set(list)];
      } else if (typeof v === "string" && allowed.has(v)) {
        out[q.id] = v;
      }
    } else {
      const s = str(v, q.kind === "textarea" ? 4000 : 200);
      if (s) out[q.id] = s;
    }
  }
  // verborgen vragen (showIf) tellen niet mee
  for (const q of ALL_QUESTIONS) if (!isVisible(q, out)) delete out[q.id];
  return out;
}

export interface IncomingFile {
  fileName: string;
  size: number;
  /** Inline upload: de bytes zitten in het request. */
  data?: Uint8Array;
  /** Storage upload: de browser heeft het bestand al naar de bucket gestuurd. */
  path?: string;
  /** Snapshot die de server zelf van een Git-repository downloadde. */
  origin?: { type: "git"; url: string; ref: string | null };
}

export interface SubmitOptions {
  /** Epoch-ms waarop de scan uiterlijk klaar moet zijn (ruim vóór de maxDuration van de functie). */
  deadline?: number;
  /** Idempotency-Key van de client: een retry van hetzelfde verzoek levert de bestaande submission op. */
  idempotencyKey?: string;
  /** Submission waarvan dit een nieuwe versie is: het rapport toont dan wat er is opgelost, nieuw en nog open. */
  previousId?: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Leest de vorige versie in. Een onbekende of ongeldige verwijzing blokkeert de indiening niet: die wordt dan genegeerd. */
async function loadPrevious(previousId: string | undefined): Promise<Submission | null> {
  if (!previousId || !UUID.test(previousId)) return null;
  try {
    return await getStore().get(previousId);
  } catch (e) {
    console.warn("previous version could not be loaded", previousId, e);
    return null;
  }
}

/** Alleen paden die /api/uploads zelf uitgeeft (zie uploadPath): geen traversal, geen andere prefixen. */
const UPLOAD_PATH = /^submissions\/\d{4}-\d{2}-\d{2}\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/[A-Za-z0-9._-]{1,80}$/;
const DEFAULT_SCAN_MS = 50_000;
/** Minimale scantijd, ook als de download al veel tijd kostte. */
const MIN_SCAN_MS = 5_000;

class ScanTimeout extends Error {
  constructor() {
    super("scan timeout");
    this.name = "ScanTimeout";
  }
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new ScanTimeout()), ms);
  });
  return Promise.race([p, timeout]).finally(() => clearTimeout(timer));
}

/** Gebruikersvriendelijke uitleg bij een mislukte scan (de technische details gaan naar de audit trail en de logs). */
function scanErrorMessage(e: unknown): string {
  if (e instanceof ScanTimeout) {
    return "The scan did not finish within the time limit. Large archives and projects with many dependencies take longer: upload a zip without node_modules, build output, datasets or model weights.";
  }
  const msg = e instanceof Error ? e.message : "";
  // De archieflezer formuleert deze melding zelf voor de gebruiker (met het herkende formaat); niet vervangen.
  if (msg.startsWith("The upload could not be read as a ZIP archive")) return msg.slice(0, 500);
  return "The scan could not be completed because of an internal error.";
}

export async function submitAsset(rawAnswers: unknown, file: IncomingFile, opts: SubmitOptions = {}): Promise<Submission> {
  const answers = sanitizeAnswers(rawAnswers);
  const errors = validateAnswers(answers);
  const store = getStore();
  if (Object.keys(errors).length) {
    // de browser vraagt bij een nieuwe poging een nieuwe upload-URL aan; dit object zou anders blijven slingeren
    if (file.path && UPLOAD_PATH.test(file.path) && !(await store.pathInUse(file.path).catch(() => true))) {
      await store.removeFile(file.path).catch(() => undefined);
    }
    throw new HttpError(400, "The questionnaire is incomplete.", errors);
  }

  const fileName = str(file.fileName, 200) || "upload.zip";
  let data: Uint8Array;
  let path: string;

  if (file.data) {
    const max = file.origin ? STORAGE_MAX_BYTES : INLINE_MAX_BYTES;
    if (file.data.byteLength > max) throw new HttpError(413, `Files are limited to ${Math.round(max / 1024 / 1024)} MB.`);
    data = file.data;
    path = uploadPath(fileName);
    await store.putFile(path, data, "application/zip");
  } else if (file.path) {
    if (!UPLOAD_PATH.test(file.path)) throw new HttpError(400, "Invalid upload reference. Please upload the file again.");
    path = file.path;
    // een upload hoort bij precies één submission; hergebruik (ook van andermans pad) weigeren
    if (await store.pathInUse(path)) throw new HttpError(409, "This upload has already been submitted. Please upload the file again.");
    try {
      data = await store.getFile(path, STORAGE_MAX_BYTES);
    } catch (e) {
      if (e instanceof HttpError) throw e;
      throw new HttpError(400, "The uploaded file was not found. Please upload it again.");
    }
  } else {
    throw new HttpError(400, "No file supplied. Upload a zip archive or link a repository.");
  }
  if (data.byteLength === 0) throw new HttpError(400, "The uploaded file is empty.");

  const sha256 = createHash("sha256").update(data).digest("hex");
  const owner = String(answers.owner_name);
  const previous = await loadPrevious(opts.previousId);

  let sub: Submission;
  try {
    sub = await store.create({
      asset_name: String(answers.asset_name),
      asset_version: (answers.asset_version as string | undefined) ?? null,
      owner_name: owner,
      owner_email: String(answers.owner_email),
      business_unit: (answers.business_unit as string | undefined) ?? null,
      asset_type: (answers.asset_type as string | undefined) ?? null,
      answers,
      file_name: fileName,
      file_size: data.byteLength,
      file_path: path,
      file_sha256: sha256,
      previous_id: previous?.id ?? null,
    }, { idempotencyKey: opts.idempotencyKey });
  } catch (e) {
    // unieke index op idempotency_key of file_path (migratie 0002): gelijktijdige retry van hetzelfde verzoek
    if (e instanceof UpstreamError && e.code === "23505") {
      if (opts.idempotencyKey) {
        const existing = await store.findByIdempotencyKey(opts.idempotencyKey);
        if (existing) return existing;
      }
      throw new HttpError(409, "This upload has already been submitted. Please upload the file again.");
    }
    throw e;
  }

  try {
    await store.addEvent(sub.id, owner, "submitted", {
      file: fileName,
      size: data.byteLength,
      sha256,
      ...(file.origin ? { repository: file.origin.url, ref: file.origin.ref ?? "default branch" } : {}),
      ...(previous ? { previousId: previous.id, ...(previous.asset_version ? { previousVersion: previous.asset_version } : {}) } : {}),
    });
    const budget = Math.max(MIN_SCAN_MS, (opts.deadline ?? Date.now() + DEFAULT_SCAN_MS) - Date.now());
    // De scanner stopt trage netwerkcontroles iets vóór de harde time-out en levert dan een gedeeltelijk resultaat
    // (dependency-check gemarkeerd als onvolledig) in plaats van een mislukte scan.
    const scan: ScanOutput = await withTimeout(scanArchive(fileName, data, { deadline: Date.now() + budget - 2_000 }), budget);
    const findings = [...scan.findings, ...questionnaireFindings(answers), ...consistencyFindings(answers, scan.findings)];
    const ev = evaluate(findings, answers);
    const comparison = previous ? compareWithPrevious(previous, findings) : undefined;
    const report: Report = {
      findings,
      scanners: scan.scanners,
      stats: scan.stats,
      packages: scan.packages,
      gates: ev.gates,
      generatedAt: new Date().toISOString(),
      engineVersion: ENGINE_VERSION,
      skills: scan.skills,
      ...(comparison ? { comparison } : {}),
    };
    const done = await store.update(sub.id, {
      status: "completed",
      decision: ev.decision,
      score: ev.score,
      ai_act_tier: ev.tier,
      counts: ev.counts,
      report,
      error: null,
    });
    await store.addEvent(sub.id, "AI Asset Gate", "scan_completed", {
      decision: ev.decision,
      score: ev.score,
      findings: findings.length,
      failedGates: ev.gates.filter((g) => !g.passed).map((g) => g.id),
      engineVersion: ENGINE_VERSION,
      ...(comparison ? { fixedSincePrevious: comparison.fixedTotal, newSincePrevious: comparison.added.length, stillOpen: comparison.open.length } : {}),
    });
    return done;
  } catch (e) {
    console.error("scan failed", sub.id, e);
    const failed = await store.update(sub.id, { status: "failed", error: scanErrorMessage(e) });
    await store
      .addEvent(sub.id, "AI Asset Gate", "scan_failed", {
        reason: e instanceof ScanTimeout ? "timeout" : "error",
        message: e instanceof Error ? e.message.slice(0, 300) : "unknown",
      })
      .catch((err) => console.error("audit event failed", sub.id, err));
    return failed;
  }
}

export type ReviewAction = "approve" | "reject" | "publish";

const norm = (s: string | null | undefined) => (s ?? "").normalize("NFKC").replace(/\s+/g, " ").trim().toLowerCase();

/**
 * Review-acties met server-side regels; de client bepaalt nooit de uitkomst zelf.
 * Let op: er is nog geen authenticatie, dus de reviewernaam is niet geverifieerd.
 */
export async function reviewSubmission(id: string, action: ReviewAction, reviewer: string, comment: string): Promise<Submission> {
  const store = getStore();
  const sub = await store.get(id);
  if (!sub) throw new HttpError(404, "Submission not found.");
  if (!reviewer) throw new HttpError(400, "Reviewer name is required.", { reviewer: "Required" });
  if (sub.status !== "completed" || !sub.decision) throw new HttpError(409, "Only completed scans can be reviewed.");
  // vier-ogenprincipe: de eigenaar keurt zijn eigen asset niet goed
  const r = norm(reviewer);
  if (r === norm(sub.owner_name) || r === norm(sub.owner_email)) {
    throw new HttpError(403, "The asset owner cannot review or publish their own submission. Ask another reviewer.");
  }

  const now = new Date().toISOString();
  let patch: Partial<Submission>;
  let expect: UpdateExpectation;
  if (action === "approve" || action === "reject") {
    if (sub.catalog_status === "published") throw new HttpError(409, "This asset is already published.");
    if (action === "approve") {
      if (sub.decision === "blocked") throw new HttpError(409, "Blocked submissions cannot be approved. Fix the blocking findings and resubmit.");
      if (sub.review_status === "approved") throw new HttpError(409, "This submission is already approved.");
      if (sub.decision === "conditional" && !comment) {
        throw new HttpError(400, "Explain why the remaining risk is acceptable before approving.", { comment: "Required" });
      }
    } else {
      if (sub.review_status === "rejected") throw new HttpError(409, "This submission is already rejected.");
      if (!comment) throw new HttpError(400, "Please explain why the submission is rejected.", { comment: "Required" });
    }
    const status: ReviewStatus = action === "approve" ? "approved" : "rejected";
    patch = { review_status: status, reviewer, review_comment: comment || null, reviewed_at: now };
    expect = { status: "completed", review_status: sub.review_status, catalog_status: "not_published" };
  } else {
    if (sub.review_status !== "approved") throw new HttpError(409, "A reviewer must approve the submission before publication.");
    if (sub.catalog_status === "published") throw new HttpError(409, "This asset is already published.");
    if (sub.decision === "blocked") throw new HttpError(409, "Blocked submissions cannot be published.");
    patch = { catalog_status: "published", published_at: now };
    expect = { status: "completed", review_status: "approved", catalog_status: "not_published" };
  }

  // conditionele update: twee gelijktijdige acties kunnen niet allebei slagen
  const updated = await store.updateIf(id, expect, patch);
  if (!updated) throw new HttpError(409, "This submission was changed by someone else. Refresh the page and try again.");
  await store.addEvent(id, reviewer, action === "publish" ? "published_to_catalogue" : action === "approve" ? "review_approved" : "review_rejected", {
    decision: sub.decision,
    score: sub.score,
    previousReviewStatus: sub.review_status,
    ...(comment ? { comment } : {}),
    ...(action === "publish" ? { catalogueId: `aicat-${id.slice(0, 8)}` } : {}),
  });
  return updated;
}
