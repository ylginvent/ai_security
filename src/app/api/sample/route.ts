import { buildSampleSkillZip, buildSampleZip, SAMPLE_FILE_NAME, SAMPLE_SKILL_FILE_NAME } from "@/lib/sample";

/** Bewust kwetsbare demo-assets: een applicatie (default) of een Agent Skill (?kind=skill). */
export async function GET(req: Request) {
  const skill = new URL(req.url).searchParams.get("kind") === "skill";
  const zip = skill ? await buildSampleSkillZip() : await buildSampleZip();
  return new Response(new Blob([zip as BlobPart], { type: "application/zip" }), {
    headers: {
      "content-type": "application/zip",
      "content-disposition": `attachment; filename="${skill ? SAMPLE_SKILL_FILE_NAME : SAMPLE_FILE_NAME}"`,
      "cache-control": "public, max-age=3600",
    },
  });
}
