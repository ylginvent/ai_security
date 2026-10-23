import { assertSameOrigin, handle, HttpError, json, readJson, str } from "@/lib/server/http";
import { downloadRepository, parseGitUrl } from "@/lib/server/git";
import { sanitizeAnswers, submitAsset } from "@/lib/server/submissions";
import { validateAnswers } from "@/lib/questionnaire";
import { getStore, INLINE_MAX_BYTES } from "@/lib/store";
import type { Submission } from "@/lib/types";

// De scan draait synchroon in dit request. 60 s past op elk Vercel-plan; met Fluid compute (of Pro) kan dit
// omhoog naar 300, de interne deadline hieronder schuift dan automatisch mee.
export const maxDuration = 60;

/** Reserve voor het wegschrijven van het resultaat na de scan. */
const WRITE_RESERVE_MS = 8_000;
const GIT_TIMEOUT_MS = 20_000;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9_-]{16,100}$/;

/** Antwoord van POST: genoeg om door te sturen naar het rapport (status kan "failed" zijn met een uitleg in error). */
function summary(s: Submission) {
  return { id: s.id, status: s.status, decision: s.decision, score: s.score, error: s.error };
}

export async function POST(req: Request) {
  const started = Date.now();
  const deadline = started + maxDuration * 1000 - WRITE_RESERVE_MS;
  return handle(async () => {
    assertSameOrigin(req);
    // Optionele Idempotency-Key (bijv. crypto.randomUUID() per verzending, hergebruikt bij een retry):
    // een retry na een time-out of netwerkfout levert de bestaande submission op in plaats van een duplicaat.
    const rawKey = req.headers.get("idempotency-key");
    let idempotencyKey: string | undefined;
    if (rawKey !== null) {
      if (!IDEMPOTENCY_KEY.test(rawKey.trim())) throw new HttpError(400, "Invalid Idempotency-Key header (16-100 characters: letters, digits, '-' or '_').");
      idempotencyKey = rawKey.trim();
      const existing = await getStore().findByIdempotencyKey(idempotencyKey);
      if (existing) return json(summary(existing), 200, { "idempotent-replayed": "true" });
    }
    const type = req.headers.get("content-type") ?? "";
    let sub: Submission;
    if (type.startsWith("multipart/form-data")) {
      const declared = Number(req.headers.get("content-length"));
      if (Number.isFinite(declared) && declared > INLINE_MAX_BYTES + 512 * 1024) {
        throw new HttpError(413, `Direct uploads are limited to ${INLINE_MAX_BYTES / 1024 / 1024} MB.`);
      }
      let form: FormData;
      try {
        form = await req.formData();
      } catch {
        throw new HttpError(400, "Invalid form data.");
      }
      const file = form.get("file");
      if (!(file instanceof File)) throw new HttpError(400, "No file supplied.");
      if (file.size > INLINE_MAX_BYTES) throw new HttpError(413, `Direct uploads are limited to ${INLINE_MAX_BYTES / 1024 / 1024} MB.`);
      let answers: unknown;
      try {
        answers = JSON.parse(String(form.get("answers") ?? "{}"));
      } catch {
        throw new HttpError(400, "Invalid answers.");
      }
      const previousId = str(form.get("previousId"), 64) || undefined;
      sub = await submitAsset(
        answers,
        { fileName: file.name, size: file.size, data: new Uint8Array(await file.arrayBuffer()) },
        { deadline, idempotencyKey, previousId },
      );
    } else {
      const body = await readJson(req);
      const previousId = str(body.previousId, 64) || undefined;
      const source = body.source && typeof body.source === "object" && !Array.isArray(body.source) ? (body.source as Record<string, unknown>) : null;
      if (source && source.type === "git") {
        // eerst de intake controleren, dan pas downloaden
        const errors = validateAnswers(sanitizeAnswers(body.answers));
        if (Object.keys(errors).length) throw new HttpError(400, "The questionnaire is incomplete.", errors);
        const git = parseGitUrl(str(source.url, 500), str(source.ref, 200));
        const { fileName, data, ref } = await downloadRepository(git, GIT_TIMEOUT_MS);
        sub = await submitAsset(
          body.answers,
          { fileName, size: data.byteLength, data, origin: { type: "git", url: git.url, ref } },
          { deadline, idempotencyKey, previousId },
        );
      } else {
        const upload = body.upload && typeof body.upload === "object" && !Array.isArray(body.upload) ? (body.upload as Record<string, unknown>) : {};
        sub = await submitAsset(body.answers, { fileName: str(upload.fileName), size: Number(upload.size) || 0, path: str(upload.path, 300) }, { deadline, idempotencyKey, previousId });
      }
    }
    return json(summary(sub), 201);
  });
}

export async function GET() {
  return handle(async () => {
    // lijstweergave zonder rapporten, antwoorden en interne opslagpaden
    const list = await getStore().list(200, { summary: true });
    return json({
      submissions: list.map((s) => {
        const { report, answers, file_path, ...rest } = s;
        void report;
        void answers;
        void file_path;
        return rest;
      }),
    });
  });
}
