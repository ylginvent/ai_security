import { ENGINE_VERSION } from "@/lib/scanner";
import { downloadName, handle, HttpError, json } from "@/lib/server/http";
import { getStore } from "@/lib/store";
import type { PackageRef, Severity } from "@/lib/types";

const PURL_TYPE: Record<PackageRef["ecosystem"], string> = {
  npm: "npm",
  PyPI: "pypi",
  Maven: "maven",
  NuGet: "nuget",
  Go: "golang",
  "crates.io": "cargo",
};

/** Package URL volgens de purl-spec (namespace/name per segment ge-encodeerd, PyPI-namen genormaliseerd). */
function purl(p: PackageRef): string {
  const version = p.version ? `@${encodeURIComponent(p.version)}` : "";
  if (p.ecosystem === "Maven") {
    const [group, artifact] = p.name.split(":");
    return artifact
      ? `pkg:maven/${encodeURIComponent(group ?? "")}/${encodeURIComponent(artifact)}${version}`
      : `pkg:maven/${encodeURIComponent(p.name)}${version}`;
  }
  const name = p.ecosystem === "PyPI" ? p.name.toLowerCase().replace(/[-_.]+/g, "-") : p.name;
  const parts = name
    .split("/")
    .filter(Boolean)
    .map((x) => (x.startsWith("@") ? `%40${encodeURIComponent(x.slice(1))}` : encodeURIComponent(x)));
  return `pkg:${PURL_TYPE[p.ecosystem]}/${parts.join("/")}${version}`;
}

const VULN_ID = /^(GHSA|CVE|PYSEC|GO|RUSTSEC|OSV|MAL)-/;
/** CycloneDX 1.5 severity-enum: critical, high, medium, low, info, none, unknown. */
const CDX_SEVERITY: Record<Severity, string> = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info" };

interface CdxVulnerability {
  id: string;
  source: { name: string; url: string };
  ratings: { source: { name: string }; severity: string }[];
  description: string;
  recommendation: string;
  affects?: { ref: string }[];
}

/** CycloneDX 1.5 SBOM met de gevonden componenten en kwetsbaarheden. */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  return handle(async () => {
    const { id } = await params;
    const s = await getStore().get(id);
    if (!s) throw new HttpError(404, "Submission not found.");
    if (s.status !== "completed" || !s.report) throw new HttpError(409, "The SBOM is available once the scan has completed.");
    const pkgs = s.report.packages ?? [];

    // bom-ref moet uniek zijn: hetzelfde package uit manifest én lockfile maar één keer opnemen
    const components = new Map<string, { type: string; "bom-ref": string; name: string; version?: string; purl: string; properties: { name: string; value: string }[] }>();
    for (const p of pkgs) {
      const ref = purl(p);
      const existing = components.get(ref);
      if (existing) {
        existing.properties.push({ name: "ai-asset-gate:source", value: p.source });
        continue;
      }
      components.set(ref, {
        type: "library",
        "bom-ref": ref,
        name: p.name,
        ...(p.version ? { version: p.version } : {}),
        purl: ref,
        properties: [
          { name: "ai-asset-gate:ecosystem", value: p.ecosystem },
          { name: "ai-asset-gate:source", value: p.source },
          ...(p.approximate ? [{ name: "ai-asset-gate:approximate-version", value: "true" }] : []),
        ],
      });
    }

    // één vulnerability per id, met alle getroffen componenten
    const vulns = new Map<string, CdxVulnerability>();
    for (const f of s.report.findings) {
      if (f.scanner !== "dependencies") continue;
      const vid = f.refs.find((r) => VULN_ID.test(r)) ?? (VULN_ID.test(f.ruleId) ? f.ruleId : null);
      if (!vid) continue;
      // titel begint met "<naam> <versie>"
      const pkg = pkgs.find((p) => f.title.startsWith(`${p.name} ${p.version}`));
      const ref = pkg ? purl(pkg) : null;
      const existing = vulns.get(vid);
      if (existing) {
        if (ref && !existing.affects?.some((a) => a.ref === ref)) existing.affects = [...(existing.affects ?? []), { ref }];
        continue;
      }
      vulns.set(vid, {
        id: vid,
        source: { name: "OSV", url: `https://osv.dev/vulnerability/${encodeURIComponent(vid)}` },
        ratings: [{ source: { name: "AI Asset Gate" }, severity: CDX_SEVERITY[f.severity] ?? "unknown" }],
        description: f.title,
        recommendation: f.remediation,
        ...(ref ? { affects: [{ ref }] } : {}),
      });
    }

    const bom = {
      $schema: "http://cyclonedx.org/schema/bom-1.5.schema.json",
      bomFormat: "CycloneDX",
      specVersion: "1.5",
      serialNumber: `urn:uuid:${crypto.randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [{ vendor: "AI Asset Gate", name: "ai-asset-gate", version: ENGINE_VERSION }],
        component: {
          type: "application",
          "bom-ref": `submission:${s.id}`,
          name: s.asset_name,
          version: s.asset_version || "unversioned",
          ...(s.file_sha256 ? { hashes: [{ alg: "SHA-256", content: s.file_sha256 }] } : {}),
        },
        properties: [
          { name: "ai-asset-gate:submission-id", value: s.id },
          { name: "ai-asset-gate:scan-generated-at", value: s.report.generatedAt },
        ],
      },
      components: [...components.values()],
      vulnerabilities: [...vulns.values()],
    };
    return json(bom, 200, {
      "content-type": "application/vnd.cyclonedx+json; version=1.5; charset=utf-8",
      "content-disposition": `attachment; filename="${downloadName(s.asset_name, "sbom.cdx.json")}"`,
    });
  });
}
