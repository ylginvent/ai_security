import { handle, HttpError, json } from "@/lib/server/http";
import { getStore } from "@/lib/store";

/**
 * Wat de wizard nodig heeft om een nieuwe versie in te dienen: de antwoorden, de versie en (bij een Git-indiening) de
 * repository. Bewust zonder rapport en opslagpad.
 */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  return handle(async () => {
    const { id } = await params;
    const store = getStore();
    const s = await store.get(id);
    if (!s) throw new HttpError(404, "Submission not found.");
    let source: { type: "git"; url: string; ref: string | null } | null = null;
    try {
      const submitted = (await store.events(s.id)).find((e) => e.action === "submitted");
      const repo = submitted?.detail?.repository;
      const ref = submitted?.detail?.ref;
      if (typeof repo === "string") source = { type: "git", url: repo, ref: typeof ref === "string" && ref !== "default branch" ? ref : null };
    } catch (e) {
      console.warn("audit events", e);
    }
    return json({
      id: s.id,
      created_at: s.created_at,
      asset_name: s.asset_name,
      asset_version: s.asset_version,
      status: s.status,
      decision: s.decision,
      score: s.score,
      answers: s.answers,
      source,
    });
  });
}
