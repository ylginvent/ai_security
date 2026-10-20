import { COMMENT_LINE, isDockerfile, snippetOf, splitLines, type Archive, type RawFinding, type ScannerResult, type SourceFile } from "./archive";
import { runRules } from "./code";
import type { Rule } from "./rules";
import { mask } from "./secrets";

/**
 * Configuratie & IaC. Dockerfile-regels afgeleid van Hadolint, Azure IaC-regels van Checkov
 * (Terraform azurerm, Bicep, ARM), plus Kubernetes, GitHub Actions en repo-hygiëne.
 */

const IAC = [".tf", ".tfvars", ".bicep", ".json"];
const isArm = (f: SourceFile) => f.ext !== ".json" || /deploymentTemplate\.json#|"Microsoft\.\w+\/\w+"/.test(f.text ?? "");

const IAC_RULES: Rule[] = [
  {
    id: "iac-storage-public-blob",
    scanner: "config",
    severity: "high",
    title: "Storage account allows public blob access",
    description: "Anonymous public read access is allowed on the storage account. Any container set to public exposes its documents — for a RAG application typically the full knowledge base — to the internet without authentication.",
    remediation: "Set allowBlobPublicAccess: false (Bicep/ARM) or allow_nested_items_to_be_public = false (Terraform azurerm ≥ 3) and grant access through Entra ID RBAC or short-lived user-delegation SAS.",
    refs: ["Checkov CKV_AZURE_190", "CWE-284", "Azure Security Benchmark DP-2"],
    extensions: IAC,
    pattern: /\ballow_(?:nested_items_to_be_public|blob_public_access)\s*=\s*true\b|\ballowBlobPublicAccess["']?\s*:\s*true\b/i,
    appliesTo: isArm,
  },
  {
    id: "iac-public-network-access",
    scanner: "config",
    severity: "medium",
    title: "Public network access enabled",
    description: "The resource accepts connections from the public internet. Catalogue AI assets are expected to expose data stores and model endpoints only through private endpoints inside the Capgemini network.",
    remediation: "Set publicNetworkAccess: 'Disabled' / public_network_access_enabled = false and connect through a private endpoint (or at minimum restrict networkAcls to known ranges).",
    refs: ["Checkov CKV_AZURE_59", "Checkov CKV_AZURE_134", "CWE-284"],
    extensions: IAC,
    pattern: /\bpublic_network_access_enabled\s*=\s*true\b|\bpublicNetworkAccess["']?\s*:\s*["']Enabled["']/i,
    appliesTo: isArm,
  },
  {
    id: "iac-weak-tls",
    scanner: "config",
    severity: "medium",
    title: "Minimum TLS version below 1.2",
    description: "The resource accepts TLS 1.0/1.1 connections, which are deprecated and vulnerable to downgrade attacks.",
    remediation: "Set the minimum TLS version to TLS1_2 (minimumTlsVersion: 'TLS1_2' / min_tls_version = \"TLS1_2\").",
    refs: ["Checkov CKV_AZURE_44", "CWE-326"],
    extensions: IAC,
    pattern: /\bmin(?:imum)?_?tls_?version["']?\s*[:=]\s*["']?(?:TLS1_0|TLS1_1|1\.0|1\.1)\b/i,
    appliesTo: isArm,
  },
  {
    id: "iac-https-not-enforced",
    scanner: "config",
    severity: "medium",
    title: "HTTPS-only traffic not enforced",
    description: "The resource accepts unencrypted HTTP traffic, exposing data and access keys in transit.",
    remediation: "Set supportsHttpsTrafficOnly / httpsOnly to true (https_traffic_only_enabled / https_only = true in Terraform).",
    refs: ["Checkov CKV_AZURE_3", "Checkov CKV_AZURE_14", "CWE-319"],
    extensions: IAC,
    pattern: /\b(?:https_only|enable_https_traffic_only|https_traffic_only_enabled)\s*=\s*false\b|\b(?:supportsHttpsTrafficOnly|httpsOnly)["']?\s*:\s*false\b/i,
    appliesTo: isArm,
  },
  {
    id: "iac-local-auth-enabled",
    scanner: "config",
    severity: "low",
    title: "Key-based (local) authentication enabled",
    description: "The service accepts static access keys in addition to Entra ID. Keys are long-lived, shared and hard to attribute, and they are the credential most often leaked in code.",
    remediation: "Set disableLocalAuth: true / local_auth_enabled = false and authenticate with managed identities and Entra ID RBAC (e.g. Cognitive Services OpenAI User).",
    refs: ["Checkov CKV_AZURE_236", "CWE-287"],
    extensions: IAC,
    pattern: /\blocal_auth_enabled\s*=\s*true\b|\bdisableLocalAuth["']?\s*:\s*false\b/i,
    appliesTo: isArm,
  },
  {
    id: "k8s-privileged-container",
    scanner: "config",
    severity: "high",
    title: "Privileged container",
    description: "A privileged container has all Linux capabilities and access to host devices; a compromise of the application is a compromise of the node.",
    remediation: "Remove privileged: true and grant only the specific capabilities required.",
    refs: ["Checkov CKV_K8S_16", "CWE-250"],
    extensions: [".yaml", ".yml"],
    pattern: /^\s*-?\s*privileged:\s*true\b/,
  },
  {
    id: "k8s-privilege-escalation",
    scanner: "config",
    severity: "medium",
    title: "Container allows privilege escalation",
    description: "allowPrivilegeEscalation: true lets processes gain more privileges than their parent (e.g. via setuid binaries).",
    remediation: "Set allowPrivilegeEscalation: false and runAsNonRoot: true in the securityContext.",
    refs: ["Checkov CKV_K8S_20", "CWE-250"],
    extensions: [".yaml", ".yml"],
    pattern: /^\s*allowPrivilegeEscalation:\s*true\b/,
  },
];

/* -------------------------------------------------------------------- .env */

const ENV_FILE = /^\.env(?:\.[\w.-]+)?$|^[\w.-]+\.env$/i;
const ENV_TEMPLATE = /\.(?:example|sample|template|tmpl|tpl|dist|defaults?|schema)$|^\.env\.(?:example|sample|template)/i;

function envFiles(archive: Archive): RawFinding[] {
  const out: RawFinding[] = [];
  for (const f of archive.files) {
    if (!ENV_FILE.test(f.name) || ENV_TEMPLATE.test(f.name)) continue;
    const keys = splitLines(f.text ?? "")
      .map((l) => /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\S/.exec(l))
      .filter((m): m is RegExpExecArray => m !== null)
      .map((m) => m[1]);
    if (f.text !== undefined && !keys.length) continue;
    out.push({
      scanner: "config",
      ruleId: "committed-env-file",
      severity: "high",
      title: `Environment file committed (${f.name})`,
      description: `${f.path} is part of the upload${keys.length ? ` and sets ${keys.length} variable(s): ${keys.slice(0, 10).join(", ")}${keys.length > 10 ? ", …" : ""}` : ""}. .env files hold environment-specific configuration and secrets and must never be distributed with the source.`,
      remediation: "Remove the file from the repository and its history, add .env* to .gitignore (keeping a .env.example without values), rotate any secrets it contained and provide configuration through App Service / Container Apps settings backed by Azure Key Vault references.",
      refs: ["CWE-538", "CWE-798"],
      file: f.path,
    });
  }
  return out;
}

/* ------------------------------------------------------------- Dockerfile */

interface Instruction {
  line: number;
  keyword: string;
  args: string;
  raw: string;
}

function instructions(text: string): Instruction[] {
  const out: Instruction[] = [];
  let buf = "";
  let start = 0;
  splitLines(text).forEach((l, i) => {
    const t = l.trim();
    if (!buf && (t === "" || t.startsWith("#"))) return;
    if (!buf) start = i + 1;
    if (t.endsWith("\\")) {
      buf += `${t.slice(0, -1)} `;
      return;
    }
    buf += t;
    const m = /^(\w+)\s+([\s\S]*)$/.exec(buf);
    if (m) out.push({ line: start, keyword: m[1].toUpperCase(), args: m[2], raw: buf });
    buf = "";
  });
  return out;
}

function dockerfile(f: SourceFile): RawFinding[] {
  const out: RawFinding[] = [];
  const base = { scanner: "config" as const, file: f.path };
  const ins = instructions(f.text ?? "");
  const stages = new Set<string>();
  let finalFrom: { ins: Instruction; image: string } | null = null;
  let user: Instruction | null = null;

  for (const it of ins) {
    if (it.keyword === "FROM") {
      const parts = it.args.split(/\s+/).filter((t) => !t.startsWith("--"));
      const image = parts[0] ?? "";
      if (parts[1]?.toLowerCase() === "as" && parts[2]) stages.add(parts[2].toLowerCase());
      finalFrom = { ins: it, image };
      user = null;
      if (!image || image === "scratch" || stages.has(image.toLowerCase()) || image.includes("$")) continue;
      const lastSeg = image.split("@")[0].split("/").pop() ?? "";
      const tag = lastSeg.includes(":") ? lastSeg.slice(lastSeg.indexOf(":") + 1) : "";
      if (!image.includes("@") && (!tag || tag === "latest")) {
        out.push({
          ...base,
          ruleId: "docker-unpinned-base-image",
          severity: "low",
          title: `Base image not pinned (${image})`,
          description: `${tag ? "The :latest tag" : "An untagged image"} resolves to whatever was pushed most recently, so builds are not reproducible and an upstream change or compromise silently enters the image.`,
          remediation: "Pin a specific version tag, ideally with a digest (python:3.12.7-slim@sha256:…), and update it deliberately.",
          refs: ["Hadolint DL3006", "Hadolint DL3007", "OWASP LLM03:2025"],
          line: it.line,
          snippet: snippetOf(it.raw),
        });
      }
    } else if (it.keyword === "USER") {
      user = it;
    } else if (it.keyword === "RUN" && /\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b/.test(it.args)) {
      out.push({
        ...base,
        ruleId: "docker-curl-pipe-shell",
        severity: "medium",
        title: "Remote script piped into a shell",
        description: "A script is downloaded and executed in one step without any integrity check. A compromised or spoofed server can run arbitrary commands in the build.",
        remediation: "Download the script or package, verify its checksum or signature, then execute it — or install from the distribution's package manager.",
        refs: ["CWE-494", "Hadolint DL4006"],
        line: it.line,
        snippet: snippetOf(it.raw),
      });
    } else if (it.keyword === "ADD" && /^(?:--\S+\s+)*https?:\/\//i.test(it.args)) {
      out.push({
        ...base,
        ruleId: "docker-add-remote-url",
        severity: "low",
        title: "ADD with a remote URL",
        description: "ADD fetches remote content without checksum verification and with unexpected extraction semantics.",
        remediation: "Use RUN curl/wget with checksum verification, or ADD --checksum=sha256:… on BuildKit.",
        refs: ["Hadolint DL3020", "CWE-494"],
        line: it.line,
        snippet: snippetOf(it.raw),
      });
    } else if (it.keyword === "ENV" || it.keyword === "ARG") {
      const m = /^([A-Za-z0-9_]*(?:SECRET|PASSWORD|PASSWD|PWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|TOKEN|CREDENTIALS?)[A-Za-z0-9_]*)(?:\s*=\s*|\s+)["']?([^\s"']+)/i.exec(it.args);
      if (m && m[2] && !/^\$/.test(m[2]) && m[2].length >= 4) {
        out.push({
          ...base,
          ruleId: "docker-secret-in-env",
          severity: "high",
          title: `Secret baked into the image (${it.keyword} ${m[1]})`,
          description: `${it.keyword} values are stored in the image metadata and layer history (docker history / docker inspect), so everyone who can pull the image can read ${m[1]}.`,
          remediation: "Remove the value from the Dockerfile and rotate it. Inject secrets at runtime (Key Vault references, managed identity) or use BuildKit secret mounts (RUN --mount=type=secret) for build-time needs.",
          refs: ["CWE-798", "Hadolint DL3044", "Checkov CKV_DOCKER_10"],
          line: it.line,
          snippet: snippetOf(it.raw.split(m[2]).join(mask(m[2]))),
        });
      }
    }
  }

  if (finalFrom && !/nonroot|distroless|chainguard/i.test(finalFrom.image) && finalFrom.image !== "scratch") {
    const name = user ? user.args.trim().split(":")[0] : "";
    if (!user || name === "root" || name === "0") {
      out.push({
        ...base,
        ruleId: "docker-runs-as-root",
        severity: "medium",
        title: user ? "Container explicitly runs as root" : "Container runs as root (no USER instruction)",
        description: "The final image runs its process as root. Any code-execution flaw in the application — or in a model, tool or dependency it loads — then has root privileges in the container, easing escape and lateral movement.",
        remediation: "Create an unprivileged user (RUN useradd -r -u 10001 app) and switch to it with USER 10001 before the CMD/ENTRYPOINT.",
        refs: ["CWE-250", "Hadolint DL3002", "Checkov CKV_DOCKER_3"],
        line: user ? user.line : finalFrom.ins.line,
        snippet: snippetOf(user ? user.raw : finalFrom.ins.raw),
      });
    }
  }
  return out;
}

/* ------------------------------------------------------- open inbound rules */

const OPEN_SOURCE = /\bsource_address_prefix(?:es)?\s*=\s*\[?\s*["'](?:\*|0\.0\.0\.0\/0|Internet|Any)["']|\bsourceAddressPrefix["']?\s*:\s*["'](?:\*|0\.0\.0\.0\/0|Internet)["']|\bcidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']|\bstart_ip_address\s*=\s*["']0\.0\.0\.0["']|\bstartIpAddress["']?\s*:\s*["']0\.0\.0\.0["']/i;

function openInbound(f: SourceFile): RawFinding[] {
  const out: RawFinding[] = [];
  const lines = splitLines(f.text ?? "");
  lines.forEach((l, i) => {
    if (COMMENT_LINE.test(l) || !OPEN_SOURCE.test(l)) return;
    const window = lines.slice(Math.max(0, i - 15), i + 15).join("\n");
    if (/\b(?:Outbound|egress)\b/i.test(window) && !/\b(?:Inbound|ingress)\b/i.test(window)) return;
    // start_ip 0.0.0.0 + end_ip 0.0.0.0 is de "Allow Azure services"-regel, geen open internet
    if (/start_?ip_?address/i.test(l) && !/255\.255\.255\.255/.test(window)) return;
    out.push({
      scanner: "config",
      ruleId: "iac-open-inbound",
      severity: "medium",
      title: "Inbound access open to the internet",
      description: "A network or firewall rule accepts inbound traffic from any source address (*, 0.0.0.0/0 or Internet).",
      remediation: "Restrict the source to known address ranges or service tags, and prefer private endpoints / VNet integration over public ingress.",
      refs: ["Checkov CKV_AZURE_9", "Checkov CKV_AZURE_160", "CWE-284"],
      file: f.path,
      line: i + 1,
      snippet: snippetOf(l),
    });
  });
  return out;
}

/* --------------------------------------------------------- GitHub Actions */

const UNTRUSTED_CONTEXT = /\$\{\{\s*(github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label)|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|head_commit\.message|commits\[\d+\]\.message|pages\[\d+\]\.page_name)|github\.head_ref)\s*\}\}/;

function workflow(f: SourceFile): RawFinding[] {
  const out: RawFinding[] = [];
  const lines = splitLines(f.text ?? "");
  let runIndent = -1;
  lines.forEach((l, i) => {
    const indent = l.length - l.trimStart().length;
    if (runIndent >= 0 && l.trim() !== "" && indent <= runIndent) runIndent = -1;
    const run = /^(\s*)(?:-\s+)?run:\s*(.*)$/.exec(l);
    let inRun = runIndent >= 0;
    if (run) {
      const rest = run[2].trim();
      if (rest === "|" || rest === ">" || rest.startsWith("|") || rest.startsWith(">")) runIndent = indent;
      else inRun = true;
    }
    if (/^\s*pull_request_target\s*:?/.test(l) || /^\s*on:\s*\[?[^\n]*\bpull_request_target\b/.test(l)) {
      out.push({
        scanner: "config",
        ruleId: "gha-pull-request-target",
        severity: "medium",
        title: "Workflow triggered by pull_request_target",
        description: "pull_request_target runs with the base repository's secrets and a write token even for pull requests from forks. Checking out or executing the PR's code in such a workflow lets any external contributor steal secrets or push to the repository.",
        remediation: "Use the pull_request trigger for untrusted code. If pull_request_target is needed, never check out or run the PR head, and limit permissions: to read-only.",
        refs: ["CWE-829", "GitHub Security Lab: preventing pwn requests"],
        file: f.path,
        line: i + 1,
        snippet: snippetOf(l),
      });
    }
    const m = inRun ? UNTRUSTED_CONTEXT.exec(l) : null;
    if (m) {
      out.push({
        scanner: "config",
        ruleId: "gha-script-injection",
        severity: "high",
        title: `Script injection via ${m[1]}`,
        description: `An attacker-controlled value (${m[1]}) is expanded directly into a run: script. A crafted issue or PR title such as \`"; curl … | sh; #\` executes commands in the runner with access to its secrets and token.`,
        remediation: "Pass the value through an environment variable (env: TITLE: ${{ … }}) and reference it as \"$TITLE\" in the script, so it is treated as data.",
        refs: ["CWE-78", "CWE-94", "GitHub Security Lab: untrusted input"],
        file: f.path,
        line: i + 1,
        snippet: snippetOf(l),
      });
    }
  });
  return out;
}

/* ---------------------------------------------------------- repo-hygiëne */

function hygiene(archive: Archive): RawFinding[] {
  if (archive.kind !== "zip") return [];
  const names = archive.files.map((f) => f.path.toLowerCase());
  const root = names.filter((p) => !p.includes("/"));
  const out: RawFinding[] = [];
  if (!root.some((p) => /^readme(?:\.|$)/.test(p))) {
    out.push({
      scanner: "config",
      ruleId: "repo-no-readme",
      severity: "info",
      title: "No README",
      description: "The upload has no README at its root. Catalogue consumers need a description of purpose, intended use, limitations, configuration and ownership.",
      remediation: "Add a README.md (or a model card) describing the asset, its intended and out-of-scope use, data sources, evaluation results and the owning team.",
      refs: ["EU AI Act Art. 13", "ISO/IEC 42001 A.8.2"],
    });
  }
  if (!root.some((p) => /^(?:licen[cs]e|copying)(?:\.|$)/.test(p))) {
    out.push({
      scanner: "config",
      ruleId: "repo-no-license",
      severity: "low",
      title: "No LICENSE file",
      description: "No licence file was found at the root. Assets published to the internal catalogue must state the terms under which other Capgemini teams and clients may reuse them, and must respect the licences of embedded models and datasets.",
      remediation: "Add a LICENSE file (for internal assets, the Capgemini internal-use licence text) and list third-party model and dataset licences in the README.",
      refs: ["ISO/IEC 42001 A.10.3", "OWASP LLM03:2025"],
    });
  }
  if (!names.some((p) => /^(?:\.github\/|docs\/)?security(?:\.md|\.txt|\.rst)?$/.test(p))) {
    out.push({
      scanner: "config",
      ruleId: "repo-no-security-policy",
      severity: "info",
      title: "No SECURITY.md",
      description: "There is no security policy describing how to report vulnerabilities in this asset or who responds to them.",
      remediation: "Add a SECURITY.md with the owning team's contact, supported versions and the vulnerability disclosure process.",
      refs: ["OpenSSF Scorecard: Security-Policy"],
    });
  }
  return out;
}

export function scanConfig(archive: Archive): ScannerResult {
  const findings: RawFinding[] = [...envFiles(archive), ...runRules(archive.files, IAC_RULES)];
  for (const f of archive.files) {
    if (f.text === undefined) continue;
    if (isDockerfile(f.name)) findings.push(...dockerfile(f));
    if (IAC.includes(f.ext) && isArm(f)) findings.push(...openInbound(f));
    if (/(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(f.path)) findings.push(...workflow(f));
  }
  findings.push(...hygiene(archive));
  return { findings };
}
