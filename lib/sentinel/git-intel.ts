export type GitProvider = "github" | "gitlab" | "bitbucket" | "self-hosted" | "unknown";

export interface GitRemoteRepo {
  remoteName: string;
  rawUrlRedacted: string;
  normalizedWebUrl: string;
  provider: GitProvider;
  host: string;
  owner: string;
  repoName: string;
  hasEmbeddedCredentials: boolean;
  sourcePath: string;
}

export interface GitRefEntry {
  ref: string;
  branch: string;
  sha: string;
  sourcePath: string;
}

export interface GitReflogEntry {
  oldSha: string;
  newSha: string;
  authorName: string;
  authorEmail: string;
  timestamp: number;
  isoDate: string;
  tz: string;
  message: string;
  clonedFromUrl?: string;
}

export interface GitExposedFileHit {
  path: string;
  status: number;
  marker: string;
  contentType: string;
  snippet: string;
}

export interface GitIntelReport {
  domain: string;
  scannedAt: string;
  exposed: boolean;
  riskSeverity: "CRITICAL" | "HIGH" | "NONE";
  primaryRepository: {
    detected: boolean;
    provider: GitProvider;
    repoFullName: string | null;
    webUrl: string | null;
    cloneUrlRedacted: string | null;
    hasEmbeddedCredentials: boolean;
  };
  remotes: GitRemoteRepo[];
  head: {
    raw: string | null;
    SymbolicRef: string | null;
    activeBranch: string | null;
    detachedSha: string | null;
  };
  branches: GitRefEntry[];
  commits: {
    latestSha: string | null;
    commitEditMsg: string | null;
    contributors: Array<{ name: string; email: string }>;
    reflogHistory: GitReflogEntry[];
  };
  exposedFiles: GitExposedFileHit[];
}

export interface GitPathProbeSpec {
  path: string;
  findingTitle: string;
  kind:
    | "config"
    | "head"
    | "reflog"
    | "ref_sha"
    | "packed_refs"
    | "commit_msg"
    | "description"
    | "gitmodules";
}

export const GIT_PASSIVE_PROBES: GitPathProbeSpec[] = [
  { path: "/.git/config", findingTitle: "Git repository config exposed (/.git/config)", kind: "config" },
  { path: "/.git/config/.git", findingTitle: "Nested Git config artifact exposed (/.git/config/.git)", kind: "config" },
  { path: "/.git/HEAD", findingTitle: "Git HEAD reference exposed (/.git/HEAD)", kind: "head" },
  { path: "/.git/logs/HEAD", findingTitle: "Git reflog history exposed (/.git/logs/HEAD)", kind: "reflog" },
  { path: "/logs/HEAD", findingTitle: "Root reflog history exposed (/logs/HEAD)", kind: "reflog" },
  { path: "/.git/refs/heads/main", findingTitle: "Git branch ref exposed (/.git/refs/heads/main)", kind: "ref_sha" },
  { path: "/.git/refs/heads/master", findingTitle: "Git branch ref exposed (/.git/refs/heads/master)", kind: "ref_sha" },
  { path: "/.git/refs/heads/production", findingTitle: "Git branch ref exposed (/.git/refs/heads/production)", kind: "ref_sha" },
  { path: "/.git/refs/heads/develop", findingTitle: "Git branch ref exposed (/.git/refs/heads/develop)", kind: "ref_sha" },
  { path: "/.git/refs/heads/staging", findingTitle: "Git branch ref exposed (/.git/refs/heads/staging)", kind: "ref_sha" },
  { path: "/.git/refs/remotes/origin/HEAD", findingTitle: "Git origin HEAD ref exposed (/.git/refs/remotes/origin/HEAD)", kind: "head" },
  { path: "/.git/refs/remotes/origin/main", findingTitle: "Git origin main ref exposed (/.git/refs/remotes/origin/main)", kind: "ref_sha" },
  { path: "/.git/refs/remotes/origin/master", findingTitle: "Git origin master ref exposed (/.git/refs/remotes/origin/master)", kind: "ref_sha" },
  { path: "/.git/packed-refs", findingTitle: "Git packed-refs exposed (/.git/packed-refs)", kind: "packed_refs" },
  { path: "/.git/COMMIT_EDITMSG", findingTitle: "Git last commit message exposed (/.git/COMMIT_EDITMSG)", kind: "commit_msg" },
  { path: "/.git/description", findingTitle: "Git repository description exposed (/.git/description)", kind: "description" },
  { path: "/.gitmodules", findingTitle: "Git submodules config exposed (/.gitmodules)", kind: "gitmodules" },
];

const HTML_RE = /<(!doctype|html|head|body|script|meta|title)\b/i;
const SHA40_RE = /^[0-9a-f]{40}$/i;
const REFLOG_LINE_RE = /^([0-9a-f]{40})\s+([0-9a-f]{40})\s+([^<\r\n]+)<([^>\r\n]+)>\s+(\d+)\s+([+-]\d{4})\t(.*)$/gm;

export function validateGitProbeResponse(
  spec: GitPathProbeSpec,
  status: number,
  contentType: string,
  body: string
): { valid: boolean; marker: string } {
  if (status !== 200) return { valid: false, marker: "" };
  const ct = contentType.toLowerCase();
  if (ct.includes("text/html") || ct.includes("application/xhtml") || HTML_RE.test(body.slice(0, 800))) {
    return { valid: false, marker: "" };
  }

  const trimmed = body.trim();
  if (!trimmed) return { valid: false, marker: "" };

  switch (spec.kind) {
    case "config": {
      if (/^\s*\[(core|remote\s+"[^"]+"|branch\s+"[^"]+"|submodule\s+"[^"]+")\]/im.test(body)) {
        const hasRemote = /\[remote\s+"[^"]+"\]/i.test(body);
        return { valid: true, marker: hasRemote ? '[core] + [remote "origin"]' : "[core]" };
      }
      return { valid: false, marker: "" };
    }
    case "head": {
      const m = /^ref:\s*(refs\/[\w./-]+)\s*$/m.exec(trimmed);
      if (m) return { valid: true, marker: `ref: ${m[1]}` };
      if (SHA40_RE.test(trimmed)) return { valid: true, marker: `detached SHA (${trimmed.slice(0, 12)})` };
      return { valid: false, marker: "" };
    }
    case "reflog": {
      REFLOG_LINE_RE.lastIndex = 0;
      const m = REFLOG_LINE_RE.exec(body);
      if (m) {
        const hasClone = /clone:\s*from\s+/i.test(body);
        return {
          valid: true,
          marker: hasClone ? "git reflog (contains clone URL)" : `git reflog (${m[2].slice(0, 8)})`,
        };
      }
      return { valid: false, marker: "" };
    }
    case "ref_sha": {
      const firstLine = trimmed.split(/\r?\n/)[0]?.trim() ?? "";
      if (SHA40_RE.test(firstLine)) {
        return { valid: true, marker: `commit SHA ${firstLine.slice(0, 12)}` };
      }
      return { valid: false, marker: "" };
    }
    case "packed_refs": {
      if (/^#\s*pack-refs with:/m.test(body) || /^[0-9a-f]{40}\s+refs\/(heads|tags|remotes)\//m.test(body)) {
        return { valid: true, marker: "pack-refs table" };
      }
      return { valid: false, marker: "" };
    }
    case "commit_msg": {
      if (
        trimmed.length > 2 &&
        trimmed.length < 4096 &&
        !trimmed.startsWith("{") &&
        !trimmed.startsWith("<") &&
        (/^(feat|fix|chore|Merge|Initial|Update|Refactor|hotfix|release|docs|style|test)\b/i.test(trimmed) ||
          /^#\s*Please enter the commit message/m.test(body))
      ) {
        return { valid: true, marker: "COMMIT_EDITMSG" };
      }
      return { valid: false, marker: "" };
    }
    case "description": {
      if (trimmed.includes("Unnamed repository; edit this file 'description'") || (trimmed.length < 400 && !trimmed.includes("<"))) {
        if (trimmed.includes("Unnamed repository")) {
          return { valid: true, marker: "default git description" };
        }
      }
      return { valid: false, marker: "" };
    }
    case "gitmodules": {
      if (/\[submodule\s+"[^"]+"\]/i.test(body) && /\burl\s*=\s*\S+/i.test(body)) {
        return { valid: true, marker: "[submodule] url" };
      }
      return { valid: false, marker: "" };
    }
  }
}

export function parseGitRemoteUrl(rawUrl: string, remoteName = "origin", sourcePath = "/.git/config"): GitRemoteRepo | null {
  const cleaned = rawUrl.trim().replace(/^['"]|['"]$/g, "");
  if (!cleaned) return null;

  let hasEmbeddedCredentials = false;
  let host = "";
  let owner = "";
  let repoName = "";
  let rawUrlRedacted = cleaned;

  // Pattern 1: SCP-like SSH (git@github.com:owner/repo.git)
  const sshMatch = /^(?:([A-Za-z0-9_.-]+)@)?([A-Za-z0-9.-]+):([A-Za-z0-9_./-]+?)(?:\.git)?$/.exec(cleaned);
  if (sshMatch && !cleaned.includes("://")) {
    host = sshMatch[2].toLowerCase();
    const parts = sshMatch[3].replace(/^\/+/, "").split("/");
    if (parts.length >= 2) {
      owner = parts.slice(0, -1).join("/");
      repoName = parts[parts.length - 1].replace(/\.git$/i, "");
    }
  } else {
    // Pattern 2: URL with scheme (https://..., ssh://..., git://...)
    try {
      const u = new URL(cleaned);
      host = u.hostname.toLowerCase();
      if (u.username || u.password) {
        hasEmbeddedCredentials = true;
        u.username = u.username ? "REDACTED_USER" : "";
        u.password = u.password ? "REDACTED_TOKEN" : "";
        rawUrlRedacted = u.toString();
      }
      const parts = u.pathname.replace(/^\/+|\/+$/g, "").split("/");
      if (parts.length >= 2) {
        owner = parts.slice(0, -1).join("/");
        repoName = parts[parts.length - 1].replace(/\.git$/i, "");
      }
    } catch {
      return null;
    }
  }

  if (!host || !repoName) return null;

  let provider: GitProvider = "unknown";
  if (host === "github.com" || host.endsWith(".github.com")) provider = "github";
  else if (host === "gitlab.com" || host.includes("gitlab")) provider = "gitlab";
  else if (host === "bitbucket.org" || host.includes("bitbucket")) provider = "bitbucket";
  else provider = "self-hosted";

  const normalizedWebUrl = owner ? `https://${host}/${owner}/${repoName}` : `https://${host}/${repoName}`;

  return {
    remoteName,
    rawUrlRedacted,
    normalizedWebUrl,
    provider,
    host,
    owner,
    repoName,
    hasEmbeddedCredentials,
    sourcePath,
  };
}

export function buildGitIntelReport(domain: string, hits: GitExposedFileHit[]): GitIntelReport {
  const remotes: GitRemoteRepo[] = [];
  const branches: GitRefEntry[] = [];
  const reflogHistory: GitReflogEntry[] = [];
  const contributorsMap = new Map<string, { name: string; email: string }>();

  let headRaw: string | null = null;
  let symbolicRef: string | null = null;
  let activeBranch: string | null = null;
  let detachedSha: string | null = null;
  let commitEditMsg: string | null = null;

  const addRemote = (r: GitRemoteRepo | null) => {
    if (!r) return;
    if (!remotes.some((x) => x.normalizedWebUrl === r.normalizedWebUrl && x.remoteName === r.remoteName)) {
      remotes.push(r);
    }
  };

  const addBranch = (ref: string, sha: string, sourcePath: string) => {
    const cleanSha = sha.trim().toLowerCase();
    if (!SHA40_RE.test(cleanSha)) return;
    const branch = ref
      .replace(/^refs\/heads\//, "")
      .replace(/^refs\/remotes\//, "")
      .replace(/^refs\/tags\//, "tag:");
    if (!branches.some((b) => b.ref === ref && b.sha === cleanSha)) {
      branches.push({ ref, branch, sha: cleanSha, sourcePath });
    }
  };

  for (const hit of hits) {
    const text = hit.snippet;

    // 1. Parse .git/config or .gitmodules
    if (hit.path.includes("config") || hit.path === "/.gitmodules") {
      const sectionRe = /\[(remote|submodule|branch)\s+"([^"]+)"\]([\s\S]*?)(?=\n\[|$)/gi;
      let m: RegExpExecArray | null;
      while ((m = sectionRe.exec(text))) {
        const kind = m[1].toLowerCase();
        const name = m[2];
        const block = m[3];
        if (kind === "remote" || kind === "submodule") {
          const urlMatch = /^\s*url\s*=\s*(.+)$/im.exec(block);
          if (urlMatch) {
            addRemote(parseGitRemoteUrl(urlMatch[1], kind === "submodule" ? `submodule:${name}` : name, hit.path));
          }
        }
      }
      // Fallback: direct scan for github/gitlab/bitbucket URLs anywhere in config
      const directUrlRe = /(?:https?:\/\/[^\s"'<>]+|git@[A-Za-z0-9.-]+:[A-Za-z0-9_./-]+)/g;
      let dm: RegExpExecArray | null;
      while ((dm = directUrlRe.exec(text))) {
        addRemote(parseGitRemoteUrl(dm[0], "origin", hit.path));
      }
    }

    // 2. Parse .git/HEAD or origin/HEAD
    if (hit.path.endsWith("/HEAD") && !hit.path.includes("logs/")) {
      headRaw = text.trim().split(/\r?\n/)[0] ?? null;
      const refMatch = /^ref:\s*(refs\/[\w./-]+)$/i.exec(headRaw ?? "");
      if (refMatch) {
        symbolicRef = refMatch[1];
        activeBranch = symbolicRef.replace(/^refs\/(heads|remotes\/origin)\//, "");
      } else if (headRaw && SHA40_RE.test(headRaw)) {
        detachedSha = headRaw.toLowerCase();
      }
    }

    // 3. Parse .git/logs/HEAD or /logs/HEAD
    if (hit.path.endsWith("logs/HEAD")) {
      REFLOG_LINE_RE.lastIndex = 0;
      let rm: RegExpExecArray | null;
      while ((rm = REFLOG_LINE_RE.exec(text))) {
        const oldSha = rm[1];
        const newSha = rm[2];
        const authorName = rm[3].trim();
        const authorEmail = rm[4].trim();
        const tsSec = Number(rm[5]);
        const tz = rm[6];
        const message = rm[7].trim();

        contributorsMap.set(authorEmail.toLowerCase(), { name: authorName, email: authorEmail });

        let clonedFromUrl: string | undefined;
        const cloneMatch = /clone:\s*from\s+(\S+)/i.exec(message);
        if (cloneMatch) {
          const parsed = parseGitRemoteUrl(cloneMatch[1], "origin (reflog clone)", hit.path);
          if (parsed) {
            clonedFromUrl = parsed.normalizedWebUrl;
            addRemote(parsed);
          }
        }

        reflogHistory.push({
          oldSha,
          newSha,
          authorName,
          authorEmail,
          timestamp: tsSec * 1000,
          isoDate: new Date(tsSec * 1000).toISOString(),
          tz,
          message,
          clonedFromUrl,
        });
      }
    }

    // 4. Parse branch SHA files (/.git/refs/heads/main, etc.)
    if (hit.path.startsWith("/.git/refs/")) {
      const firstLine = text.trim().split(/\r?\n/)[0]?.trim() ?? "";
      if (SHA40_RE.test(firstLine)) {
        const refName = hit.path.replace(/^\/\.git\//, "");
        addBranch(refName, firstLine, hit.path);
      }
    }

    // 5. Parse /.git/packed-refs
    if (hit.path === "/.git/packed-refs") {
      const packedRe = /^([0-9a-f]{40})\s+(refs\/[\w./-]+)$/gim;
      let pm: RegExpExecArray | null;
      while ((pm = packedRe.exec(text))) {
        addBranch(pm[2], pm[1], hit.path);
      }
    }

    // 6. Parse /.git/COMMIT_EDITMSG
    if (hit.path === "/.git/COMMIT_EDITMSG") {
      commitEditMsg = text.trim().slice(0, 500);
    }
  }

  const primary = remotes[0] ?? null;
  const latestReflog = reflogHistory[reflogHistory.length - 1];
  const latestSha =
    (activeBranch && branches.find((b) => b.branch === activeBranch)?.sha) ||
    latestReflog?.newSha ||
    branches[0]?.sha ||
    detachedSha ||
    null;

  return {
    domain,
    scannedAt: new Date().toISOString(),
    exposed: hits.length > 0,
    riskSeverity: hits.length > 0 ? "CRITICAL" : "NONE",
    primaryRepository: {
      detected: Boolean(primary),
      provider: primary?.provider ?? "unknown",
      repoFullName: primary ? (primary.owner ? `${primary.owner}/${primary.repoName}` : primary.repoName) : null,
      webUrl: primary?.normalizedWebUrl ?? null,
      cloneUrlRedacted: primary?.rawUrlRedacted ?? null,
      hasEmbeddedCredentials: remotes.some((r) => r.hasEmbeddedCredentials),
    },
    remotes,
    head: {
      raw: headRaw,
      SymbolicRef: symbolicRef,
      activeBranch,
      detachedSha,
    },
    branches,
    commits: {
      latestSha,
      commitEditMsg: commitEditMsg ?? latestReflog?.message ?? null,
      contributors: Array.from(contributorsMap.values()),
      reflogHistory: reflogHistory.slice(-15).reverse(),
    },
    exposedFiles: hits,
  };
}
