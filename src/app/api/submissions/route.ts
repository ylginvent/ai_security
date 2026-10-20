import { handle, HttpError, json, readJson, str } from "@/lib/server/http";
import { downloadRepository, parseGitUrl } from "@/lib/server/git";
import { sanitizeAnswers, submitAsset } from "@/lib/server/submissions";
import { validateAnswers } from "@/lib/questionnaire";
import { getStore, INLINE_MAX_BYTES } from "@/lib/store";
import type { Submission } from "@/lib/types";

// De scan draait synchroon in dit request.
export const maxDuration = 60;

export async function POST(req: Request) {
  return handle(async () => {
    const type = req.headers.get("content-type") ?? "";
    let sub: Submission;
    if (type.startsWith("multipart/form-data")) {
      let form: FormData;
      try {
        form = await req.formData();
      } catch {
        throw new HttpError(400, "Invalid form data.");
      }
      const file = form.get("file");
      if (!(file instanceof File)) throw new HttpError(400, "No file supplied.");
      if (file.size > INLINE_MAX_BYTES) throw new HttpError(413, "File too large for direct upload.");
      let answers: unknown;
      try {
        answers = JSON.parse(String(form.get("answers") ?? "{}"));
      } catch {
        throw new HttpError(400, "Invalid answers.");
      }
      sub = await submitAsset(answers, { fileName: file.name, size: file.size, data: new Uint8Array(await file.arrayBuffer()) });
    } else {
      const body = await readJson(req);
      const source = (body.source ?? null) as Record<string, unknown> | null;
      if (source && source.type === "git") {
        // eerst de intake controleren, dan pas downloaden
        const errors = validateAnswers(sanitizeAnswers(body.answers));
        if (Object.keys(errors).length) throw new HttpError(400, "The questionnaire is incomplete.", errors);
        const git = parseGitUrl(str(source.url, 500), str(source.ref, 200));
        const { fileName, data } = await downloadRepository(git);
        sub = await submitAsset(body.answers, { fileName, size: data.byteLength, data, origin: { type: "git", url: git.url, ref: git.ref } });
      } else {
        const upload = (body.upload ?? {}) as Record<string, unknown>;
        sub = await submitAsset(body.answers, { fileName: str(upload.fileName), size: Number(upload.size) || 0, path: str(upload.path, 300) });
      }
    }
    return json({ id: sub.id, decision: sub.decision, score: sub.score }, 201);
  });
}

export async function GET() {
  return handle(async () => {
    const list = await getStore().list(200);
    // lijstweergave zonder volledige rapporten en antwoorden
    return json({
      submissions: list.map((s) => {
        const { report, answers, ...rest } = s;
        void report;
        void answers;
        return rest;
      }),
    });
  });
}
