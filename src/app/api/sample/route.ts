import { buildSampleZip, SAMPLE_FILE_NAME } from "@/lib/sample";

/** Bewust kwetsbare demo-applicatie om de gate mee te laten zien. */
export async function GET() {
  const zip = await buildSampleZip();
  return new Response(new Blob([zip as BlobPart], { type: "application/zip" }), {
    headers: {
      "content-type": "application/zip",
      "content-disposition": `attachment; filename="${SAMPLE_FILE_NAME}"`,
      "cache-control": "public, max-age=3600",
    },
  });
}
