import { DECISION_LABEL } from "@/lib/scoring";
import { handle, HttpError, json } from "@/lib/server/http";
import { getStore } from "@/lib/store";

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  return handle(async () => {
    const { id } = await params;
    const s = await getStore().get(id);
    if (!s) throw new HttpError(404, "Submission not found.");
    const doc = {
      schema: "ai-asset-gate/report@1",
      submission: {
        id: s.id,
        submittedAt: s.created_at,
        asset: { name: s.asset_name, version: s.asset_version, type: s.asset_type, businessUnit: s.business_unit },
        owner: { name: s.owner_name, email: s.owner_email },
        file: { name: s.file_name, size: s.file_size, sha256: s.file_sha256 },
      },
      result: {
        status: s.status,
        decision: s.decision,
        decisionLabel: s.decision ? DECISION_LABEL[s.decision] : null,
        trustScore: s.score,
        euAiActTier: s.ai_act_tier,
        counts: s.counts,
      },
      review: { status: s.review_status, reviewer: s.reviewer, comment: s.review_comment, reviewedAt: s.reviewed_at },
      catalogue: { status: s.catalog_status, publishedAt: s.published_at },
      questionnaire: s.answers,
      report: s.report,
    };
    const name = `${s.asset_name.replace(/[^A-Za-z0-9._-]+/g, "-").toLowerCase()}-report.json`;
    return json(doc, 200, { "content-disposition": `attachment; filename="${name}"` });
  });
}
