import { assertSameOrigin, handle, HttpError, json, readJson, str } from "@/lib/server/http";
import { getStore, INLINE_MAX_BYTES, STORAGE_MAX_BYTES } from "@/lib/store";

const MB = 1024 * 1024;

/** Bepaalt hoe de browser het bestand aanlevert: via een signed URL naar de private bucket, of inline in het submit-request. */
export async function POST(req: Request) {
  return handle(async () => {
    assertSameOrigin(req);
    const body = await readJson(req);
    const fileName = str(body.fileName, 200);
    const size = Number(body.size);
    if (!fileName || !Number.isSafeInteger(size) || size <= 0) throw new HttpError(400, "fileName and size are required.");

    const store = getStore();
    if (store.kind === "memory") {
      if (size > INLINE_MAX_BYTES) throw new HttpError(413, `In demo mode files are limited to ${INLINE_MAX_BYTES / MB} MB.`);
      return json({ mode: "inline", maxBytes: INLINE_MAX_BYTES });
    }
    // de opgegeven grootte is een hint voor een snelle foutmelding; de bucket-limiet en de server-side download handhaven het echt
    if (size > STORAGE_MAX_BYTES) throw new HttpError(413, `Files are limited to ${STORAGE_MAX_BYTES / MB} MB.`);
    const target = await store.createUploadTarget(fileName);
    if (!target) return json({ mode: "inline", maxBytes: INLINE_MAX_BYTES });
    return json({ mode: "storage", ...target });
  });
}
