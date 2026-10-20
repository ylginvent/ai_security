import "server-only";
import { STORAGE_MAX_BYTES } from "../store";
import { HttpError } from "./http";

/**
 * Downloadt een snapshot (zip) van een publieke GitHub- of GitLab-repository.
 * Alleen vaste hosts, alleen https, redirects worden per stap gecontroleerd (geen SSRF), met groottelimiet en timeout.
 */

export interface GitSource {
  host: "github" | "gitlab";
  /** owner/repo (GitHub) of group/subgroup/repo (GitLab). */
  path: string;
  repo: string;
  ref: string | null;
  /** Genormaliseerde, leesbare URL voor audit en weergave. */
  url: string;
}

const SEGMENT = /^[A-Za-z0-9._-]{1,100}$/;
const REF = /^[A-Za-z0-9._\/-]{1,200}$/;
const ALLOWED_HOSTS = new Set(["github.com", "codeload.github.com", "gitlab.com"]);
const TIMEOUT_MS = 25_000;

export function parseGitUrl(raw: string, rawRef?: string): GitSource {
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    throw new HttpError(400, "Enter a valid repository URL, for example https://github.com/owner/repo.", { gitUrl: "Invalid URL" });
  }
  if (u.protocol !== "https:" || u.username || u.password || u.port) {
    throw new HttpError(400, "Only https links to github.com or gitlab.com are supported.", { gitUrl: "Unsupported URL" });
  }
  const host = u.hostname.toLowerCase().replace(/^www\./, "");
  const parts = u.pathname.split("/").filter(Boolean);
  let ref = rawRef?.trim() || null;

  let source: GitSource;
  if (host === "github.com") {
    if (parts.length < 2) throw new HttpError(400, "Use a repository link like https://github.com/owner/repo.", { gitUrl: "Missing owner or repository" });
    const owner = parts[0];
    const repo = parts[1].replace(/\.git$/i, "");
    // https://github.com/o/r/tree/<branch> -> branch als ref
    if (!ref && parts[2] === "tree" && parts.length > 3) ref = parts.slice(3).join("/");
    if (!SEGMENT.test(owner) || !SEGMENT.test(repo)) throw new HttpError(400, "The repository link contains unsupported characters.", { gitUrl: "Invalid repository" });
    source = { host: "github", path: `${owner}/${repo}`, repo, ref, url: `https://github.com/${owner}/${repo}` };
  } else if (host === "gitlab.com") {
    const dash = parts.indexOf("-");
    const segs = (dash >= 0 ? parts.slice(0, dash) : parts).map((s, i, all) => (i === all.length - 1 ? s.replace(/\.git$/i, "") : s));
    if (!ref && dash >= 0 && parts[dash + 1] === "tree" && parts.length > dash + 2) ref = parts.slice(dash + 2).join("/");
    if (segs.length < 2 || !segs.every((s) => SEGMENT.test(s))) {
      throw new HttpError(400, "Use a project link like https://gitlab.com/group/project.", { gitUrl: "Invalid project" });
    }
    const path = segs.join("/");
    source = { host: "gitlab", path, repo: segs[segs.length - 1], ref, url: `https://gitlab.com/${path}` };
  } else {
    throw new HttpError(400, "Only public repositories on github.com or gitlab.com are supported.", { gitUrl: "Unsupported host" });
  }

  if (source.ref && (!REF.test(source.ref) || source.ref.includes(".."))) {
    throw new HttpError(400, "The branch, tag or commit contains unsupported characters.", { gitRef: "Invalid ref" });
  }
  return source;
}

function archiveUrl(s: GitSource): string {
  if (s.host === "github") return `https://github.com/${s.path}/archive/${s.ref ? s.ref.split("/").map(encodeURIComponent).join("/") : "HEAD"}.zip`;
  const q = s.ref ? `?sha=${encodeURIComponent(s.ref)}` : "";
  return `https://gitlab.com/api/v4/projects/${encodeURIComponent(s.path)}/repository/archive.zip${q}`;
}

async function readCapped(res: Response, max: number): Promise<Uint8Array> {
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > max) throw new HttpError(413, `The repository snapshot is larger than ${max / 1024 / 1024} MB.`);
  if (!res.body) return new Uint8Array(await res.arrayBuffer());
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      throw new HttpError(413, `The repository snapshot is larger than ${max / 1024 / 1024} MB.`);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

export async function downloadRepository(s: GitSource): Promise<{ fileName: string; data: Uint8Array }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    let url = archiveUrl(s);
    for (let hop = 0; hop < 5; hop++) {
      const res = await fetch(url, { redirect: "manual", signal: ctrl.signal, headers: { "user-agent": "ai-asset-gate" } });
      if (res.status >= 300 && res.status < 400) {
        const next = res.headers.get("location");
        if (!next) break;
        const nu = new URL(next, url);
        if (nu.protocol !== "https:" || !ALLOWED_HOSTS.has(nu.hostname.toLowerCase())) throw new HttpError(400, "The repository host redirected to an unsupported location.");
        url = nu.toString();
        continue;
      }
      if (res.status === 404 || res.status === 401 || res.status === 403) {
        throw new HttpError(400, "Repository or branch not found. Only public repositories are supported for now.", { gitUrl: "Not found or private" });
      }
      if (!res.ok) throw new HttpError(502, `The repository host returned an error (${res.status}). Try again later.`);
      const data = await readCapped(res, STORAGE_MAX_BYTES);
      if (data.byteLength < 4 || data[0] !== 0x50 || data[1] !== 0x4b) throw new HttpError(502, "The repository host did not return a zip archive.");
      const ref = (s.ref ?? "default").replace(/[^A-Za-z0-9._-]+/g, "-");
      return { fileName: `${s.repo}-${ref}.zip`, data };
    }
    throw new HttpError(502, "Too many redirects while downloading the repository.");
  } catch (e) {
    if (e instanceof HttpError) throw e;
    if (ctrl.signal.aborted) throw new HttpError(504, "Downloading the repository took too long. Try a smaller repository or upload a zip.");
    throw new HttpError(502, "The repository could not be downloaded. Check the link and try again.");
  } finally {
    clearTimeout(timer);
  }
}
