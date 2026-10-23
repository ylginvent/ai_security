import "server-only";

export class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
    public fields?: Record<string, string>,
  ) {
    super(message);
  }
}

/** Fout van een achterliggende dienst (database, storage). Wordt als 503 met een algemene melding teruggegeven. */
export class UpstreamError extends Error {
  constructor(
    message: string,
    public code?: string,
  ) {
    super(message);
    this.name = "UpstreamError";
  }
}

export function json(data: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
  });
}

/** Vangt fouten af tot een nette JSON-response; interne fouten lekken geen details naar de client. */
export async function handle(fn: () => Promise<Response>): Promise<Response> {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message, fields: e.fields }, e.status);
    // korte referentie zodat een gebruiker de fout kan melden en wij hem in de logs terugvinden
    const ref = crypto.randomUUID().slice(0, 8);
    console.error(`[${ref}]`, e);
    if (e instanceof UpstreamError) {
      return json({ error: `The storage service is not available right now. Please try again in a minute. (Reference ${ref})` }, 503);
    }
    return json({ error: `Internal error. Please try again. (Reference ${ref})` }, 500);
  }
}

/**
 * Weigert state-changing requests die vanaf een andere site komen (CSRF).
 * Browsers sturen bij POST altijd Origin en Sec-Fetch-Site mee; scripts zonder die headers worden niet geblokkeerd.
 */
export function assertSameOrigin(req: Request): void {
  const site = req.headers.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") throw new HttpError(403, "Cross-site requests are not allowed.");
  const origin = req.headers.get("origin");
  if (!origin || origin === "null") {
    if (origin === "null") throw new HttpError(403, "Cross-site requests are not allowed.");
    return;
  }
  const host = req.headers.get("x-forwarded-host") ?? req.headers.get("host");
  let originHost: string;
  try {
    originHost = new URL(origin).host;
  } catch {
    throw new HttpError(403, "Cross-site requests are not allowed.");
  }
  if (host && originHost.toLowerCase() !== host.split(",")[0].trim().toLowerCase()) {
    throw new HttpError(403, "Cross-site requests are not allowed.");
  }
}

export async function readJson(req: Request): Promise<Record<string, unknown>> {
  // application/json afdwingen: een cross-site <form> kan dat content-type niet zonder CORS-preflight versturen
  const type = req.headers.get("content-type") ?? "";
  if (!/^application\/(?:[\w.+-]+\+)?json\b/i.test(type)) throw new HttpError(415, "Content-Type must be application/json.");
  try {
    const body = await req.json();
    if (body && typeof body === "object" && !Array.isArray(body)) return body as Record<string, unknown>;
  } catch {
    /* valt door naar de fout hieronder */
  }
  throw new HttpError(400, "Request body must be a JSON object.");
}

/** Veilige, ASCII-only bestandsnaam voor Content-Disposition (geen quotes, slashes of header-injectie). */
export function downloadName(asset: string, suffix: string): string {
  const base =
    asset
      .replace(/[^A-Za-z0-9._-]+/g, "-")
      .replace(/^[-.]+|[-.]+$/g, "")
      .toLowerCase()
      .slice(0, 80) || "submission";
  return `${base}-${suffix}`;
}

export function str(v: unknown, max = 200): string {
  return typeof v === "string" ? v.trim().slice(0, max) : "";
}

/** Leest een response-body met een harde bovengrens, zodat een grote of eindeloze stream het geheugen niet vult. */
export async function readCapped(res: Response, max: number, tooLargeMessage: string): Promise<Uint8Array> {
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > max) {
    await res.body?.cancel().catch(() => undefined);
    throw new HttpError(413, tooLargeMessage);
  }
  if (!res.body) return new Uint8Array(await res.arrayBuffer());
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => undefined);
      throw new HttpError(413, tooLargeMessage);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}
