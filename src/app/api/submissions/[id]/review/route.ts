import { handle, HttpError, json, readJson, str } from "@/lib/server/http";
import { reviewSubmission, type ReviewAction } from "@/lib/server/submissions";

const ACTIONS: ReviewAction[] = ["approve", "reject", "publish"];

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  return handle(async () => {
    const { id } = await params;
    const body = await readJson(req);
    const action = body.action as ReviewAction;
    if (!ACTIONS.includes(action)) throw new HttpError(400, "Unknown action.");
    const submission = await reviewSubmission(id, action, str(body.reviewer, 100), str(body.comment, 2000));
    return json({ submission });
  });
}
