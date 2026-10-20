import { handle, HttpError, json, readJson, str } from "@/lib/server/http";
import { getStore, INLINE_MAX_BYTES, STORAGE_MAX_BYTES } from "@/lib/store";

/** Bepaalt hoe de browser het bestand aanlevert: via een signed URL naar de private bucket, of inline in het submit-request. */
export async function POST(req: Request) {
  return handle(async () => {
    const body = await readJson(req);
    const fileName = str(body.fileName, 200);
    const size = Number(body.size);
    if (!fileName || !Number.isFinite(size) || size <= 0) throw new HttpError(400, "fileName and size are required.");

    const target = await getStore().createUploadTarget(fileName);
    if (!target) {
      if (size > INLINE_MAX_BYTES) throw new HttpError(413, `In demo mode files are limited to ${INLINE_MAX_BYTES / 1024 / 1024} MB.`);
      return json({ mode: "inline", maxBytes: INLINE_MAX_BYTES });
    }
    if (size > STORAGE_MAX_BYTES) throw new HttpError(413, `Files are limited to ${STORAGE_MAX_BYTES / 1024 / 1024} MB.`);
    return json({ mode: "storage", ...target });
  });
}
