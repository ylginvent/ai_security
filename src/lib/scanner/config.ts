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
    id: "iac-public-blob-container",
    scanner: "config",
    severity: "high",
    title: "Storage container is publicly readable",
    description: "The blob container allows anonymous read access. Anyone who knows or guesses the URL can list or download its files without signing in; for an AI application this is often the document set behind a RAG index or training data.",
    remediation: "Set container_access_type = \"private\" (Terraform) or publicAccess: 'None' (Bicep/ARM), and give the application access through a managed identity with the Storage Blob Data Reader role.",
    refs: ["Checkov CKV_AZURE_34", "CWE-284", "Azure Security Benchmark DP-2"],
    extensions: IAC,
    pattern: /\bcontainer_access_type\s*=\s*["'](?:blob|container)["']|\bpublicAccess["']?\s*:\s*["'](?:Blob|Container)["']/i,
    appliesTo: isArm,
  },
  {
    id: "iac-s3-public-acl",
    scanner: "config",
    severity: "high",
    title: "S3 bucket or object is public",
    description: "A public-read / public-read-write ACL makes the bucket contents readable (or writable) by anyone on the internet.",
    remediation: "Remove the public ACL, enable S3 Block Public Access (block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets = true) and serve content through signed URLs or CloudFront with origin access control.",
    refs: ["Checkov CKV_AWS_20", "Checkov CKV_AWS_57", "CWE-284"],
    extensions: [".tf", ".json", ".yaml", ".yml"],
    pattern: /\bacl\s*=\s*["']public-read(?:-write)?["']|["']?(?:AccessControl|acl)["']?\s*:\s*["']?(?:PublicRead|PublicReadWrite|public-read(?:-write)?)\b/,
  },
  {
    id: "k8s-host-namespace",
    scanner: "config",
    severity: "high",
    title: "Pod shares the host's network, process or IPC namespace",
    description: "hostNetwork, hostPID or hostIPC removes the isolation between the container and the node: the pod can see host processes, sniff or bind host network traffic, or read shared memory of other workloads.",
    remediation: "Remove hostNetwork / hostPID / hostIPC (or set them to false). Expose the application through a Service and Ingress instead of host ports.",
    refs: ["Checkov CKV_K8S_17", "Checkov CKV_K8S_18", "Checkov CKV_K8S_19", "CWE-250"],
    extensions: [".yaml", ".yml"],
    pattern: /^\s*-?\s*(?:hostNetwork|hostPID|hostIPC):\s*true\b/,
  },
  {
    id: "k8s-hostpath-volume",
    scanner: "config",
    severity: "medium",
    title: "Pod mounts a directory from the host (hostPath)",
    description: "A hostPath volume gives the container direct access to the node's file system. A compromised container can read other workloads' data or credentials, or modify the node.",
    remediation: "Use a PersistentVolumeClaim, ConfigMap, Secret or emptyDir instead. If host access is unavoidable, mount it readOnly: true and restrict the path as narrowly as possible.",
    refs: ["Checkov CKV_K8S_27", "CWE-284"],
    extensions: [".yaml", ".yml"],
    pattern: /^\s*-?\s*hostPath:\s*(?:$|\{|#)/,
  },
  {
    id: "container-docker-socket",
    scanner: "config",
    severity: "high",
    title: "Docker socket mounted into a container",
    description: "Mounting /var/run/docker.sock gives the container full control of the Docker daemon, which is equivalent to root access on the host: it can start privileged containers and read every other container's data.",
    remediation: "Remove the docker.sock mount. If the application needs to build or run containers, use a dedicated build service (e.g. Azure Container Registry Tasks) or rootless tooling such as BuildKit/Kaniko.",
    refs: ["Checkov CKV_K8S_27", "CWE-250", "CWE-284"],
    extensions: [".yaml", ".yml"],
    pattern: /\/var\/run\/docker\.sock|\/run\/containerd\/containerd\.sock/,
    appliesTo: (f) => !/(?:^|\/)\.github\/workflows\//.test(f.path),
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
/** Variabelenamen die op een geheim wijzen. */
const SECRET_NAME = /SECRET|PASSWORD|PASSWD|PWD|PASS\b|_PASS_|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|TOKEN|CREDENTIAL|CONN(?:ECTION)?_?STR|DSN|_KEY$|^KEY$|SAS\b/i;
/** Namen die wel "token/key/secret" bevatten maar een verwijzing of instelling zijn, geen geheim. */
const NON_SECRET_NAME = /_(?:URL|URI|ENDPOINT|PATH|FILE|DIR|NAME|ID|HEADER|TYPE|LENGTH|LEN|EXPIRY|EXPIRES|TTL|TIMEOUT|VERSION|ENABLED|REGION|HOST|PORT|LIMIT|COUNT|SIZE|VAULT)$|^MAX_|TOKENI[SZ]ER|MAX_?TOKENS?/i;

function envFiles(archive: Archive): RawFinding[] {
  const out: RawFinding[] = [];
  for (const f of archive.files) {
    if (!ENV_FILE.test(f.name) || ENV_TEMPLATE.test(f.name)) continue;
    const pairs = splitLines(f.text ?? "")
      .map((l) => /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?!["']{2}\s*$)(\S.*)$/.exec(l))
      .filter((m): m is RegExpExecArray => m !== null);
    const keys = pairs.map((m) => m[1]);
    if (f.text !== undefined && !keys.length) continue;
    // Hoog als er iets geheim-achtigs in staat (of de inhoud onleesbaar is); anders alleen hygiëne
    const sensitive =
      f.text === undefined ||
      pairs.some((m) => (SECRET_NAME.test(m[1]) && !NON_SECRET_NAME.test(m[1])) || /:\/\/[^/\s:@]+:[^@\s]+@/.test(m[2]));
    out.push({
      scanner: "config",
      ruleId: "committed-env-file",
      severity: sensitive ? "high" : "low",
      title: `Environment file committed (${f.name})`,
      description: `${f.path} is part of the upload${keys.length ? ` and sets ${keys.length} variable(s): ${keys.slice(0, 10).join(", ")}${keys.length > 10 ? ", …" : ""}` : ""}. .env files hold environment-specific configuration and secrets and must never be distributed with the source.${sensitive ? "" : " None of the variable names look like credentials, but the file should still not be shipped."}`,
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
    // Commentaar- en lege regels mogen ook midden in een vervolgregel (\) staan
    if (t === "" || t.startsWith("#")) return;
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

/** COPY . /app (of ./) neemt de hele build-context mee; COPY --from=<stage> niet. */
function copiesWholeContext(args: string): boolean {
  if (/--from=/i.test(args)) return false;
  const srcs = args.split(/\s+/).filter((t) => t && !t.startsWith("--")).slice(0, -1);
  return srcs.some((s) => s === "." || s === "./");
}

function dockerfile(f: SourceFile, hasDockerignore: boolean): RawFinding[] {
  const out: RawFinding[] = [];
  const base = { scanner: "config" as const, file: f.path };
  const ins = instructions(f.text ?? "");
  const stages = new Set<string>();
  /** Laatste USER per stage, zodat FROM <stage> de gebruiker van die stage erft. */
  const stageUser = new Map<string, Instruction | null>();
  const stageImage = new Map<string, string>();
  let stageName = "";
  let finalFrom: { ins: Instruction; image: string } | null = null;
  let user: Instruction | null = null;
  let copyAll: Instruction | null = null;

  for (const it of ins) {
    if (it.keyword === "FROM") {
      if (stageName) stageUser.set(stageName, user);
      const parts = it.args.split(/\s+/).filter((t) => !t.startsWith("--"));
      const image = parts[0] ?? "";
      stageName = parts[1]?.toLowerCase() === "as" && parts[2] ? parts[2].toLowerCase() : "";
      const parent = image.toLowerCase();
      const isStage = stages.has(parent);
      // FROM <stage> erft basis-image en USER van die stage
      const baseImage = isStage ? (stageImage.get(parent) ?? image) : image;
      finalFrom = { ins: it, image: baseImage };
      user = isStage ? (stageUser.get(parent) ?? null) : null;
      if (stageName) {
        stages.add(stageName);
        stageImage.set(stageName, baseImage);
      }
      if (!image || image === "scratch" || isStage || image.includes("$")) continue;
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
    } else if ((it.keyword === "COPY" || it.keyword === "ADD") && !copyAll && copiesWholeContext(it.args)) {
      copyAll = it;
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
      // ENV A=1 B=2 (meerdere paren) en de oude vorm ENV KEY value
      const pairs: [string, string][] = [];
      for (const p of it.args.matchAll(/(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|\S+)/g)) pairs.push([p[1], p[2].replace(/^["']|["']$/g, "")]);
      if (!pairs.length) {
        const legacy = /^([A-Za-z_][A-Za-z0-9_]*)\s+["']?([^\s"']+)/.exec(it.args);
        if (legacy) pairs.push([legacy[1], legacy[2]]);
      }
      const hit = pairs.find(
        ([k, v]) =>
          /SECRET|PASSWORD|PASSWD|PWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|TOKEN|CREDENTIALS?/i.test(k) &&
          !NON_SECRET_NAME.test(k) &&
          v.length >= 4 &&
          !/^\$/.test(v) &&
          !/^(?:true|false|none|null|changeme|placeholder|dummy|x+)$/i.test(v),
      );
      const m = hit ? [hit[0], hit[0], hit[1]] : null;
      if (m) {
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

  if (copyAll && !hasDockerignore) {
    out.push({
      ...base,
      ruleId: "docker-copy-all-no-dockerignore",
      severity: "low",
      title: "Whole project folder copied into the image without a .dockerignore",
      description: "COPY . copies everything in the build context into the image, and there is no .dockerignore to exclude anything. Local .env files, .git history, credentials, notebooks with outputs and test data then end up in the image, where anyone who can pull it can read them.",
      remediation: "Add a .dockerignore next to the Dockerfile that excludes at least .env*, .git, *.pem, *.key, __pycache__, node_modules, data/ and notebooks, or copy only the folders the application needs (COPY src/ /app/src/).",
      refs: ["CWE-538", "Docker build best practices: .dockerignore"],
      line: copyAll.line,
      snippet: snippetOf(copyAll.raw),
    });
  }
  return out;
}

/* ------------------------------------------------------- open inbound rules */

const OPEN_SOURCE = /\bsource_address_prefix(?:es)?\s*=\s*\[?\s*["'](?:\*|0\.0\.0\.0\/0|Internet|Any)["']|\bsourceAddressPrefix["']?\s*:\s*["'](?:\*|0\.0\.0\.0\/0|Internet)["']|\bcidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0\/0["']|\bstart_ip_address\s*=\s*["']0\.0\.0\.0["']|\bstartIpAddress["']?\s*:\s*["']0\.0\.0\.0["']/i;

/** De dichtstbijzijnde regel (binnen `radius`) die `re` matcht; bij gelijke afstand wint de regel erboven. */
function nearest(lines: string[], i: number, re: RegExp, radius: number): RegExpExecArray | null {
  for (let d = 0; d <= radius; d++) {
    for (const j of d === 0 ? [i] : [i - d, i + d]) {
      if (j < 0 || j >= lines.length) continue;
      const m = re.exec(lines[j]);
      if (m) return m;
    }
  }
  return null;
}

const ADMIN_PORT = /\b(?:destination_?port_?ranges?|destinationPortRanges?|from_port|to_port|port)["']?\s*[:=]\s*\[?\s*["']?(22|3389|\*|0-65535)(?![\d-])["']?/i;

function openInbound(f: SourceFile): RawFinding[] {
  const out: RawFinding[] = [];
  const lines = splitLines(f.text ?? "");
  lines.forEach((l, i) => {
    if (COMMENT_LINE.test(l) || !OPEN_SOURCE.test(l)) return;
    const window = lines.slice(Math.max(0, i - 15), i + 15).join("\n");
    // Richting en actie van díe regel (de dichtstbijzijnde), niet van een buurregel in hetzelfde bestand
    const direction = nearest(lines, i, /\b(Inbound|Outbound|ingress|egress)\b/i, 15);
    if (direction && /^(?:outbound|egress)$/i.test(direction[1])) return;
    const access = nearest(lines, i, /\baccess["']?\s*[:=]\s*["'](Allow|Deny)["']/i, 12);
    if (access && /^deny$/i.test(access[1])) return; // een deny-all-regel is juist goed
    // start_ip 0.0.0.0 + end_ip 0.0.0.0 is de "Allow Azure services"-regel, geen open internet
    if (/start_?ip_?address/i.test(l) && !/255\.255\.255\.255/.test(window)) return;
    const port = nearest(lines, i, ADMIN_PORT, 12);
    const admin = port !== null && port[1] !== undefined;
    const portLabel = port ? (port[1] === "22" ? "SSH (22)" : port[1] === "3389" ? "RDP (3389)" : "all ports") : "";
    out.push({
      scanner: "config",
      ruleId: "iac-open-inbound",
      severity: admin ? "high" : "medium",
      title: admin ? `Inbound ${portLabel} open to the internet` : "Inbound access open to the internet",
      description: `A network or firewall rule accepts inbound traffic from any source address (*, 0.0.0.0/0 or Internet)${admin ? ` on ${portLabel}. Internet-exposed management ports and any-port rules are scanned and brute-forced continuously` : ""}.`,
      remediation: admin
        ? "Remove the rule or restrict the source to known address ranges. For administration use Azure Bastion, Just-In-Time VM access or a VPN instead of opening SSH/RDP to the internet."
        : "Restrict the source to known address ranges or service tags, and prefer private endpoints / VNet integration over public ingress.",
      refs: ["Checkov CKV_AZURE_9", "Checkov CKV_AZURE_160", "CWE-284"],
      file: f.path,
      line: i + 1,
      snippet: snippetOf(l),
    });
  });
  return out;
}

/* --------------------------------------------------------- GitHub Actions */

const UNTRUSTED_CONTEXT = /\$\{\{\s*(github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.(?:description|homepage))|comment\.body|review\.body|review_comment\.body|discussion\.(?:title|body)|head_commit\.(?:message|author\.(?:name|email))|commits\[\d+\]\.(?:message|author\.(?:name|email))|pages\[\d+\]\.page_name|workflow_run\.(?:head_branch|head_commit\.message|head_commit\.author\.(?:name|email)|display_title))|github\.head_ref)\s*\}\}/;

/** Checkout van de PR-code (head) in plaats van de basis-branch. */
const PR_HEAD_REF = /\$\{\{\s*(?:github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref)\s*\}\}|refs\/pull\//;

const PULL_REQUEST_TARGET = /^\s*(?:-\s*)?["']?pull_request_target["']?\s*:?\s*(?:#.*)?$|^\s*on:\s*\[?[^\n#]*\bpull_request_target\b/;

function workflow(f: SourceFile): RawFinding[] {
  const out: RawFinding[] = [];
  const lines = splitLines(f.text ?? "");
  const base = { scanner: "config" as const, file: f.path };
  let runIndent = -1;
  let prtLine = -1;
  const unpinned: { line: number; action: string }[] = [];
  lines.forEach((l, i) => {
    if (COMMENT_LINE.test(l)) return;
    const indent = l.length - l.trimStart().length;
    if (runIndent >= 0 && l.trim() !== "" && indent <= runIndent) runIndent = -1;
    // run: (shell) en script: (actions/github-script, ssh-actions …) voeren de tekst uit
    const run = /^(\s*)(?:-\s+)?(?:run|script):\s*(.*)$/.exec(l);
    let inRun = runIndent >= 0;
    if (run) {
      const rest = run[2].trim();
      if (rest.startsWith("|") || rest.startsWith(">")) runIndent = indent;
      else inRun = true;
    }
    if (prtLine < 0 && PULL_REQUEST_TARGET.test(l)) prtLine = i;

    const uses = /^\s*(?:-\s+)?uses:\s*["']?([^\s"'#]+)/.exec(l);
    if (uses) {
      const ref = uses[1];
      const at = ref.lastIndexOf("@");
      const owner = ref.split("/")[0].toLowerCase();
      const firstParty = owner === "actions" || owner === "github";
      if (!ref.startsWith("./") && !ref.startsWith("docker://") && !firstParty && (at < 0 || !/^[0-9a-f]{40}$/i.test(ref.slice(at + 1)))) {
        unpinned.push({ line: i + 1, action: ref });
      }
    }

    if (/^\s*permissions:\s*["']?write-all["']?\s*(?:#.*)?$/.test(l)) {
      out.push({
        ...base,
        ruleId: "gha-write-all-permissions",
        severity: "medium",
        title: "Workflow token has write access to everything",
        description: "permissions: write-all gives the GITHUB_TOKEN write access to code, packages, releases and settings of the repository. Any compromised step or action can then push code or publish packages.",
        remediation: "Replace write-all with the minimum needed, e.g. permissions: contents: read, and grant extra scopes (such as pull-requests: write) only to the job that needs them.",
        refs: ["CWE-250", "OpenSSF Scorecard: Token-Permissions"],
        line: i + 1,
        snippet: snippetOf(l),
      });
    }

    const m = inRun ? UNTRUSTED_CONTEXT.exec(l) : null;
    if (m) {
      out.push({
        ...base,
        ruleId: "gha-script-injection",
        severity: "high",
        title: `Script injection via ${m[1]}`,
        description: `An attacker-controlled value (${m[1]}) is pasted directly into a script that the workflow runs. A crafted issue or PR title such as \`"; curl … | sh; #\` then executes commands on the runner, with access to its secrets and token.`,
        remediation: "Pass the value through an environment variable (env: TITLE: ${{ … }}) and reference it as \"$TITLE\" in the script (process.env.TITLE in github-script), so it is treated as data instead of code.",
        refs: ["CWE-78", "CWE-94", "GitHub Security Lab: untrusted input"],
        line: i + 1,
        snippet: snippetOf(l),
      });
    }
  });

  if (prtLine >= 0) {
    // pull_request_target + checkout van de PR-head = "pwn request": fork-code draait met secrets en schrijf-token
    const headIdx = lines.findIndex((l) => !COMMENT_LINE.test(l) && /^\s*(?:-\s+)?ref:/.test(l) && PR_HEAD_REF.test(l));
    if (headIdx >= 0) {
      out.push({
        ...base,
        ruleId: "gha-pwn-request",
        severity: "high",
        title: "pull_request_target workflow checks out untrusted pull request code",
        description: "This workflow runs on pull_request_target, which has access to the repository's secrets and a write token, and it checks out the code from the pull request. Anyone can open a pull request from a fork, so their code (build scripts, package.json scripts, tests) runs with your secrets and can push to the repository.",
        remediation: "Switch to the pull_request trigger for building or testing PR code. If pull_request_target is required (e.g. to label or comment), do not check out the PR head, or split it into a pull_request workflow that builds without secrets and a workflow_run workflow that only consumes its results.",
        refs: ["CWE-829", "GitHub Security Lab: preventing pwn requests"],
        line: headIdx + 1,
        snippet: snippetOf(lines[headIdx]),
      });
    } else {
      out.push({
        ...base,
        ruleId: "gha-pull-request-target",
        severity: "low",
        title: "Workflow triggered by pull_request_target",
        description: "pull_request_target runs with the base repository's secrets and a write token, even for pull requests from forks. No checkout of the pull request code was found, but any later change that checks out or runs PR code would expose those secrets.",
        remediation: "Use the pull_request trigger unless the workflow really needs secrets or write access. Keep permissions: read-only and never check out or execute the PR head in this workflow.",
        refs: ["CWE-829", "GitHub Security Lab: preventing pwn requests"],
        line: prtLine + 1,
        snippet: snippetOf(lines[prtLine]),
      });
    }
  }

  if (unpinned.length) {
    const names = Array.from(new Set(unpinned.map((u) => u.action)));
    out.push({
      ...base,
      ruleId: "gha-unpinned-action",
      severity: "low",
      title: `Third-party actions not pinned to a commit (${names.length})`,
      description: `${names.slice(0, 8).join(", ")}${names.length > 8 ? ` and ${names.length - 8} more` : ""} ${names.length === 1 ? "is" : "are"} referenced by a tag or branch. Tags can be moved by the action's owner or by an attacker who compromises it (as happened with tj-actions/changed-files in 2025), and the new code then runs in your workflow with its secrets.`,
      remediation: "Pin each third-party action to a full 40-character commit SHA (uses: owner/action@<sha> # v1.2.3) and let Dependabot or Renovate propose updates.",
      refs: ["CWE-829", "OpenSSF Scorecard: Pinned-Dependencies", "OWASP LLM03:2025"],
      line: unpinned[0].line,
      snippet: snippetOf(lines[unpinned[0].line - 1] ?? ""),
    });
  }
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
  const paths = new Set(archive.files.map((f) => f.path));
  const dockerignore = (f: SourceFile) =>
    paths.has(".dockerignore") || paths.has(f.dir ? `${f.dir}/.dockerignore` : ".dockerignore") || paths.has(`${f.path}.dockerignore`);
  for (const f of archive.files) {
    if (f.text === undefined) continue;
    if (isDockerfile(f.name)) findings.push(...dockerfile(f, dockerignore(f)));
    if (IAC.includes(f.ext) && isArm(f)) findings.push(...openInbound(f));
    if (/(?:^|\/)\.github\/workflows\/[^/]+\.ya?ml$/i.test(f.path)) findings.push(...workflow(f));
  }
  findings.push(...hygiene(archive));
  return { findings };
}
