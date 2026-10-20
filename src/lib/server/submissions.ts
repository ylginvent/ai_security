import "server-only";
import { createHash } from "node:crypto";
import { ALL_QUESTIONS, isVisible, questionnaireFindings, validateAnswers } from "../questionnaire";
import { evaluate } from "../scoring";
import { ENGINE_VERSION, scanArchive } from "../scanner";
import { getStore, INLINE_MAX_BYTES, STORAGE_MAX_BYTES, uploadPath } from "../store";
import type { Answers, Report, ReviewStatus, Submission } from "../types";
import { HttpError, str } from "./http";

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
}

export async function submitAsset(rawAnswers: unknown, file: IncomingFile): Promise<Submission> {
  const answers = sanitizeAnswers(rawAnswers);
  const errors = validateAnswers(answers);
  if (Object.keys(errors).length) throw new HttpError(400, "The questionnaire is incomplete.", errors);

  const fileName = str(file.fileName, 200) || "upload.zip";
  const store = getStore();
  let data: Uint8Array;
  let path: string;

  if (file.data) {
    if (file.data.byteLength > INLINE_MAX_BYTES) throw new HttpError(413, "File too large for direct upload.");
    data = file.data;
    path = uploadPath(fileName);
    await store.putFile(path, data, "application/octet-stream");
  } else if (file.path) {
    if (!/^submissions\/\d{4}-\d{2}-\d{2}\/[0-9a-f-]{36}\/[A-Za-z0-9._-]+$/.test(file.path)) throw new HttpError(400, "Invalid upload reference.");
    path = file.path;
    try {
      data = await store.getFile(path);
    } catch {
      throw new HttpError(400, "Uploaded file not found. Please upload again.");
    }
    if (data.byteLength > STORAGE_MAX_BYTES) throw new HttpError(413, "File too large.");
  } else {
    throw new HttpError(400, "No file supplied.");
  }
  if (data.byteLength === 0) throw new HttpError(400, "The uploaded file is empty.");

  const sha256 = createHash("sha256").update(data).digest("hex");
  const owner = String(answers.owner_name);

  const sub = await store.create({
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
  });
  await store.addEvent(sub.id, owner, "submitted", { file: fileName, size: data.byteLength, sha256 });

  try {
    const scan = await scanArchive(fileName, data);
    const findings = [...scan.findings, ...questionnaireFindings(answers)];
    const ev = evaluate(findings, answers);
    const report: Report = {
      findings,
      scanners: scan.scanners,
      stats: scan.stats,
      packages: scan.packages,
      gates: ev.gates,
      generatedAt: new Date().toISOString(),
      engineVersion: ENGINE_VERSION,
    };
    const done = await store.update(sub.id, {
      status: "completed",
      decision: ev.decision,
      score: ev.score,
      ai_act_tier: ev.tier,
      counts: ev.counts,
      report,
    });
    await store.addEvent(sub.id, "AI Asset Gate", "scan_completed", {
      decision: ev.decision,
      score: ev.score,
      findings: findings.length,
      failedGates: ev.gates.filter((g) => !g.passed).map((g) => g.id),
    });
    return done;
  } catch (e) {
    console.error("scan failed", e);
    const failed = await store.update(sub.id, { status: "failed", error: "The scan could not be completed. Check that the upload is a valid zip archive." });
    await store.addEvent(sub.id, "AI Asset Gate", "scan_failed", { message: e instanceof Error ? e.message.slice(0, 300) : "unknown" });
    return failed;
  }
}

export type ReviewAction = "approve" | "reject" | "publish";

export async function reviewSubmission(id: string, action: ReviewAction, reviewer: string, comment: string): Promise<Submission> {
  const store = getStore();
  const sub = await store.get(id);
  if (!sub) throw new HttpError(404, "Submission not found.");
  if (!reviewer) throw new HttpError(400, "Reviewer name is required.", { reviewer: "Required" });
  if (sub.status !== "completed") throw new HttpError(409, "Only completed scans can be reviewed.");

  const now = new Date().toISOString();
  let patch: Partial<Submission>;
  if (action === "approve" || action === "reject") {
    if (sub.catalog_status === "published") throw new HttpError(409, "This asset is already published.");
    if (action === "approve" && sub.decision === "blocked") throw new HttpError(409, "Blocked submissions cannot be approved. Fix the blocking findings and resubmit.");
    if (action === "reject" && !comment) throw new HttpError(400, "Please explain why the submission is rejected.", { comment: "Required" });
    const status: ReviewStatus = action === "approve" ? "approved" : "rejected";
    patch = { review_status: status, reviewer, review_comment: comment || null, reviewed_at: now };
  } else {
    if (sub.review_status !== "approved") throw new HttpError(409, "A reviewer must approve the submission before publication.");
    if (sub.catalog_status === "published") throw new HttpError(409, "This asset is already published.");
    patch = { catalog_status: "published", published_at: now };
  }

  const updated = await store.update(id, patch);
  await store.addEvent(id, reviewer, action === "publish" ? "published_to_catalogue" : action === "approve" ? "review_approved" : "review_rejected", {
    ...(comment ? { comment } : {}),
    ...(action === "publish" ? { catalogueId: `aicat-${id.slice(0, 8)}` } : {}),
  });
  return updated;
}
