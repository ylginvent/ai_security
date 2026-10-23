import { assertSameOrigin, handle, HttpError, json, readJson, str } from "@/lib/server/http";
import { reviewSubmission, type ReviewAction } from "@/lib/server/submissions";

const ACTIONS: ReviewAction[] = ["approve", "reject", "publish"];

/** Stuurtekens weg (behalve regeleinden in het commentaar), zodat audit-regels en rapporten leesbaar blijven. */
const clean = (s: string, keepNewlines: boolean) =>
  (keepNewlines ? s.replace(/[\u0000-\u0009\u000b-\u001f\u007f]/g, " ") : s.replace(/[\u0000-\u001f\u007f]/g, " ")).trim();

/**
 * Review-acties. Er is nog geen authenticatie: de reviewernaam is niet geverifieerd.
 * De regels (geen goedkeuring van Blocked, eerst goedkeuren dan publiceren, vier-ogen) worden server-side afgedwongen.
 */
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  return handle(async () => {
    assertSameOrigin(req);
    const { id } = await params;
    const body = await readJson(req);
    const action = typeof body.action === "string" ? (body.action as ReviewAction) : null;
    if (!action || !ACTIONS.includes(action)) throw new HttpError(400, "Unknown action.");
    const submission = await reviewSubmission(id, action, clean(str(body.reviewer, 100), false), clean(str(body.comment, 2000), true));
    // alleen wat de client nodig heeft; geen volledig rapport of antwoorden terugsturen
    return json({
      submission: {
        id: submission.id,
        review_status: submission.review_status,
        reviewer: submission.reviewer,
        review_comment: submission.review_comment,
        reviewed_at: submission.reviewed_at,
        catalog_status: submission.catalog_status,
        published_at: submission.published_at,
      },
    });
  });
}
