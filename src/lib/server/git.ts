import "server-only";
import { STORAGE_MAX_BYTES } from "../store";
import { HttpError, readCapped } from "./http";

/**
 * Downloadt een snapshot (zip) van een publieke GitHub- of GitLab-repository.
 * Alleen vaste hosts, alleen https, redirects worden per stap gecontroleerd (geen SSRF), met groottelimiet en timeout.
 * De server bouwt de download-URL zelf op uit gevalideerde padsegmenten; de invoer-URL wordt nooit direct opgevraagd.
 */

export interface GitSource {
  host: "github" | "gitlab";
  /** owner/repo (GitHub) of group/subgroup/repo (GitLab). */
  path: string;
  repo: string;
  ref: string | null;
  /**
   * Alternatieve refs als de ref uit een /tree/-link kwam: "tree/feature/x/src" kan branch "feature/x" met map "src" zijn.
   * Langste eerst; bij een 404 wordt de volgende geprobeerd.
   */
  refCandidates?: string[];
  /** Genormaliseerde, leesbare URL voor audit en weergave. */
  url: string;
}

const SEGMENT = /^[A-Za-z0-9._-]{1,100}$/;
const REF = /^[A-Za-z0-9._\/-]{1,200}$/;
/** Hosts waar een redirect naartoe mag (GitHub stuurt archieven door naar codeload). */
const ALLOWED_HOSTS = new Set(["github.com", "codeload.github.com", "gitlab.com"]);
const DEFAULT_TIMEOUT_MS = 20_000;
const MAX_REDIRECTS = 5;
const MB = 1024 * 1024;

const NOT_FOUND =
  "Repository, branch or tag not found. Check the link and the branch name. Private repositories are not supported: download the repository as a zip and upload it instead.";

function validRef(r: string) {
  return REF.test(r) && !r.includes("..") && !r.startsWith("/") && !r.endsWith("/") && !r.includes("//");
}

/** Maakt van gangbare varianten een https-URL: "github.com/o/r", "git@github.com:o/r.git". */
function normaliseInput(raw: string): string {
  const t = raw.trim();
  const ssh = /^git@(github\.com|gitlab\.com):(.+)$/i.exec(t);
  if (ssh) return `https://${ssh[1]}/${ssh[2]}`;
  if (/^(www\.)?(github\.com|gitlab\.com)\//i.test(t)) return `https://${t}`;
  return t;
}

export function parseGitUrl(raw: string, rawRef?: string): GitSource {
  if (!raw.trim()) throw new HttpError(400, "Enter a repository URL, for example https://github.com/owner/repo.", { gitUrl: "Required" });
  let u: URL;
  try {
    u = new URL(normaliseInput(raw));
  } catch {
    throw new HttpError(400, "Enter a valid repository URL, for example https://github.com/owner/repo.", { gitUrl: "Invalid URL" });
  }
  if (u.protocol !== "https:" || u.username || u.password || u.port) {
    throw new HttpError(400, "Only https links to github.com or gitlab.com are supported (no credentials or ports in the link).", { gitUrl: "Unsupported URL" });
  }
  // hostname is door de URL-parser al naar kleine letters en punycode genormaliseerd (IDN-lookalikes vallen dus af)
  const host = u.hostname.toLowerCase().replace(/\.$/, "").replace(/^www\./, "");
  const parts = u.pathname.split("/").filter(Boolean);
  const explicitRef = rawRef?.trim() || null;
  let ref = explicitRef;
  let fromTree: string[] | null = null;

  let source: GitSource;
  if (host === "github.com") {
    if (parts.length < 2) throw new HttpError(400, "Use a repository link like https://github.com/owner/repo.", { gitUrl: "Missing owner or repository" });
    const owner = parts[0];
    const repo = parts[1].replace(/\.git$/i, "");
    if (!ref) {
      // https://github.com/o/r/tree/<branch>[/map], /blob/<branch>/bestand, /commit/<sha>, /releases/tag/<tag>
      if ((parts[2] === "tree" || parts[2] === "blob") && parts.length > 3) fromTree = parts.slice(3);
      else if (parts[2] === "commit" && parts[3]) ref = parts[3];
      else if (parts[2] === "releases" && parts[3] === "tag" && parts[4]) ref = parts.slice(4).join("/");
    }
    if (!SEGMENT.test(owner) || !SEGMENT.test(repo)) throw new HttpError(400, "The repository link contains unsupported characters.", { gitUrl: "Invalid repository" });
    source = { host: "github", path: `${owner}/${repo}`, repo, ref, url: `https://github.com/${owner}/${repo}` };
  } else if (host === "gitlab.com") {
    const dash = parts.indexOf("-");
    const segs = (dash >= 0 ? parts.slice(0, dash) : parts).map((s, i, all) => (i === all.length - 1 ? s.replace(/\.git$/i, "") : s));
    if (!ref && dash >= 0 && (parts[dash + 1] === "tree" || parts[dash + 1] === "blob") && parts.length > dash + 2) fromTree = parts.slice(dash + 2);
    else if (!ref && dash >= 0 && parts[dash + 1] === "commit" && parts[dash + 2]) ref = parts[dash + 2];
    if (segs.length < 2 || segs.length > 20 || !segs.every((s) => SEGMENT.test(s))) {
      throw new HttpError(400, "Use a project link like https://gitlab.com/group/project.", { gitUrl: "Invalid project" });
    }
    const path = segs.join("/");
    source = { host: "gitlab", path, repo: segs[segs.length - 1], ref, url: `https://gitlab.com/${path}` };
  } else {
    throw new HttpError(400, "Only public repositories on github.com or gitlab.com are supported.", { gitUrl: "Unsupported host" });
  }

  if (fromTree) {
    // langste kandidaat eerst: branch "feature/x" gaat boven branch "feature" met map "x"
    const candidates: string[] = [];
    for (let n = Math.min(fromTree.length, 6); n >= 1; n--) {
      const c = fromTree.slice(0, n).join("/");
      if (validRef(c)) candidates.push(c);
    }
    if (!candidates.length) throw new HttpError(400, "The branch, tag or commit in the link contains unsupported characters.", { gitRef: "Invalid ref" });
    source.ref = candidates[0];
    source.refCandidates = candidates;
  }

  if (source.ref && !validRef(source.ref)) {
    throw new HttpError(
      400,
      "The branch, tag or commit contains unsupported characters. Use letters, digits, '.', '_', '-' and '/'.",
      explicitRef ? { gitRef: "Invalid ref" } : { gitUrl: "Invalid ref in link" },
    );
  }
  return source;
}

function archiveUrl(s: GitSource, ref: string | null): string {
  if (s.host === "github") return `https://github.com/${s.path}/archive/${ref ? ref.split("/").map(encodeURIComponent).join("/") : "HEAD"}.zip`;
  const q = ref ? `?sha=${encodeURIComponent(ref)}` : "";
  return `https://gitlab.com/api/v4/projects/${encodeURIComponent(s.path)}/repository/archive.zip${q}`;
}

type Attempt = { ok: true; data: Uint8Array } | { ok: false; notFound: true };

async function fetchArchive(start: string, signal: AbortSignal): Promise<Attempt> {
  let url = start;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const res = await fetch(url, {
      redirect: "manual",
      signal,
      cache: "no-store",
      headers: { "user-agent": "ai-asset-gate", accept: "application/zip, application/octet-stream" },
    });
    if (res.status >= 300 && res.status < 400) {
      await res.body?.cancel().catch(() => undefined);
      const next = res.headers.get("location");
      if (!next) throw new HttpError(502, "The repository host returned an invalid redirect.");
      const nu = new URL(next, url);
      // elke hop opnieuw controleren: alleen https naar de vaste hosts, geen credentials of poorten
      if (nu.protocol !== "https:" || nu.username || nu.password || nu.port || !ALLOWED_HOSTS.has(nu.hostname.toLowerCase())) {
        throw new HttpError(502, "The repository host redirected to an unsupported location.");
      }
      url = nu.toString();
      continue;
    }
    if (res.status === 404 || res.status === 401 || res.status === 403) {
      await res.body?.cancel().catch(() => undefined);
      return { ok: false, notFound: true };
    }
    if (res.status === 429) {
      await res.body?.cancel().catch(() => undefined);
      throw new HttpError(503, "The repository host is limiting downloads right now. Try again in a few minutes, or upload the repository as a zip.");
    }
    if (!res.ok) {
      await res.body?.cancel().catch(() => undefined);
      throw new HttpError(502, `The repository host returned an error (HTTP ${res.status}). Try again later, or upload the repository as a zip.`);
    }
    const data = await readCapped(
      res,
      STORAGE_MAX_BYTES,
      `The repository snapshot is larger than ${STORAGE_MAX_BYTES / MB} MB. Upload a zip without dependencies, build output and datasets instead.`,
    );
    if (data.byteLength < 4 || data[0] !== 0x50 || data[1] !== 0x4b) throw new HttpError(502, "The repository host did not return a zip archive.");
    return { ok: true, data };
  }
  throw new HttpError(502, "Too many redirects while downloading the repository.");
}

export async function downloadRepository(s: GitSource, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<{ fileName: string; data: Uint8Array; ref: string | null }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), Math.max(1_000, timeoutMs));
  try {
    const refs: (string | null)[] = s.refCandidates?.length ? s.refCandidates : [s.ref];
    for (const ref of refs) {
      const r = await fetchArchive(archiveUrl(s, ref), ctrl.signal);
      if (!r.ok) continue;
      const label = (ref ?? "default").replace(/[^A-Za-z0-9._-]+/g, "-");
      return { fileName: `${s.repo}-${label}.zip`, data: r.data, ref };
    }
    throw new HttpError(400, NOT_FOUND, { gitUrl: "Not found or private" });
  } catch (e) {
    if (e instanceof HttpError) throw e;
    if (ctrl.signal.aborted) {
      throw new HttpError(504, `Downloading the repository took longer than ${Math.round(timeoutMs / 1000)} seconds. Try again, or upload the repository as a zip.`);
    }
    throw new HttpError(502, "The repository could not be downloaded. Check the link and try again.");
  } finally {
    clearTimeout(timer);
  }
}
