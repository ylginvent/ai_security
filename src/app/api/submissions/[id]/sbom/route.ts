import { ENGINE_VERSION } from "@/lib/scanner";
import { handle, HttpError, json } from "@/lib/server/http";
import { getStore } from "@/lib/store";
import type { PackageRef } from "@/lib/types";

const PURL_TYPE: Record<PackageRef["ecosystem"], string> = {
  npm: "npm",
  PyPI: "pypi",
  Maven: "maven",
  NuGet: "nuget",
  Go: "golang",
  "crates.io": "cargo",
};

function purl(p: PackageRef) {
  const v = encodeURIComponent(p.version);
  if (p.ecosystem === "Maven") {
    const [group, artifact] = p.name.split(":");
    return `pkg:maven/${encodeURIComponent(group ?? "")}/${encodeURIComponent(artifact ?? p.name)}@${v}`;
  }
  const parts = p.name.split("/").map((x) => (x.startsWith("@") ? `%40${encodeURIComponent(x.slice(1))}` : encodeURIComponent(x)));
  return `pkg:${PURL_TYPE[p.ecosystem]}/${parts.join("/")}@${v}`;
}

const VULN_ID = /^(GHSA|CVE|PYSEC|GO|RUSTSEC|OSV|MAL)-/;

/** CycloneDX 1.5 SBOM met de gevonden componenten en kwetsbaarheden. */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  return handle(async () => {
    const { id } = await params;
    const s = await getStore().get(id);
    if (!s?.report) throw new HttpError(404, "No scan report available.");
    const pkgs = s.report.packages;

    const components = pkgs.map((p) => ({
      type: "library",
      "bom-ref": purl(p),
      name: p.name,
      version: p.version,
      purl: purl(p),
      properties: [
        { name: "ai-asset-gate:source", value: p.source },
        ...(p.approximate ? [{ name: "ai-asset-gate:approximate-version", value: "true" }] : []),
      ],
    }));

    const vulnerabilities = s.report.findings
      .filter((f) => f.scanner === "dependencies")
      .map((f) => {
        const vid = f.refs.find((r) => VULN_ID.test(r)) ?? (VULN_ID.test(f.ruleId) ? f.ruleId : null);
        if (!vid) return null;
        // titel begint met "<naam> <versie>"
        const pkg = pkgs.find((p) => f.title.startsWith(`${p.name} ${p.version}`));
        return {
          id: vid,
          source: { name: "OSV", url: `https://osv.dev/vulnerability/${vid}` },
          ratings: [{ severity: f.severity }],
          description: f.title,
          recommendation: f.remediation,
          ...(pkg ? { affects: [{ ref: purl(pkg) }] } : {}),
        };
      })
      .filter((v) => v !== null);

    const bom = {
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      serialNumber: `urn:uuid:${crypto.randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [{ vendor: "AI Asset Gate", name: "ai-asset-gate", version: ENGINE_VERSION }],
        component: {
          type: "application",
          name: s.asset_name,
          version: s.asset_version ?? "unversioned",
          hashes: s.file_sha256 ? [{ alg: "SHA-256", content: s.file_sha256 }] : [],
        },
      },
      components,
      vulnerabilities,
    };
    const name = `${s.asset_name.replace(/[^A-Za-z0-9._-]+/g, "-").toLowerCase()}-sbom.cdx.json`;
    return json(bom, 200, { "content-disposition": `attachment; filename="${name}"` });
  });
}
