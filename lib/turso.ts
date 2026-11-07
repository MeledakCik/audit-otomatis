// lib/turso.ts
// Native Turso (libSQL / Hrana v2 over HTTP) Database Engine & Auto-Discovery Client
// Dirancang untuk menggantikan ketergantungan pada Upstash Redis yang mudah terkena
// batas bandwidth 10 GB / suspended.
//
// Mendukung 2 mode konfigurasi otomatis:
// 1. Direct Database URL + Auth Token (`TURSO_DATABASE_URL` + `TURSO_AUTH_TOKEN`)
// 2. Platform API Token (`TURSO_API_TOKEN`) — otomatis menemukan organisasi & database
//    pertama milik user (atau membuat database `sentinel-id-db` jika belum ada), lalu
//    men-generate database JWT token secara dinamis dan menyimpannya di cache memori.

const DEFAULT_TURSO_API_TOKEN =
  "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJWM01mLWRwNUVmR2RWUHFmQVlPc0xBIiwib3JnX2lkIjoxMDAwMjk2MDcwfQ.pStpf7dEMxRpfBDwoxLPQj2bBUy9NqaksRRBMYebClIiL_tv0_ONKOP9jz4fHvuTDznQubYDrOeGo20tmvgYCQ";

export interface TursoEndpoint {
  httpUrl: string; // https://<db>-<org>.turso.io
  authToken: string;
}

export type SqlArg =
  | { type: "null" }
  | { type: "integer"; value: string }
  | { type: "float"; value: number }
  | { type: "text"; value: string };

export interface HranaStmt {
  sql: string;
  args?: SqlArg[];
}

interface HranaRowCell {
  type: "null" | "integer" | "float" | "text" | "blob";
  value?: string | number;
}

interface HranaExecuteResult {
  cols: Array<{ name: string; decltype?: string | null }>;
  rows: HranaRowCell[][];
  affected_row_count: number;
}

interface HranaPipelineResponse {
  results?: Array<{
    type: "ok" | "error";
    response?: {
      type: "execute" | "close";
      result?: HranaExecuteResult;
    };
    error?: { message: string; code?: string };
  }>;
}

const globalForTurso = globalThis as unknown as {
  __sentinelTursoEndpoint?: TursoEndpoint | null;
  __sentinelTursoResolving?: Promise<TursoEndpoint | null>;
  __sentinelTursoSchemaInit?: boolean;
  __sentinelTursoFailedUntil?: number;
};

function normalizeDbUrl(rawUrl: string): string {
  const trimmed = rawUrl.trim().replace(/\/+$/, "");
  if (trimmed.startsWith("libsql://")) {
    return "https://" + trimmed.slice("libsql://".length);
  }
  if (trimmed.startsWith("turso://")) {
    return "https://" + trimmed.slice("turso://".length);
  }
  if (trimmed.startsWith("wss://")) {
    return "https://" + trimmed.slice("wss://".length);
  }
  if (!/^https?:\/\//i.test(trimmed)) {
    return `https://${trimmed}`;
  }
  return trimmed;
}

export function sqlArg(val: string | number | null | undefined): SqlArg {
  if (val === null || val === undefined) return { type: "null" };
  if (typeof val === "number") {
    if (Number.isInteger(val)) return { type: "integer", value: String(val) };
    return { type: "float", value: val };
  }
  return { type: "text", value: String(val) };
}

/**
 * Resolves the active Turso database HTTP URL & Database JWT Token.
 * - First checks `TURSO_DATABASE_URL` + (`TURSO_AUTH_TOKEN` or `TURSO_API_TOKEN`)
 * - Otherwise uses `TURSO_API_TOKEN` (or the built-in user token) via `https://api.turso.tech/v1/organizations`
 *   to auto-discover or provision `sentinel-id-db` and mint a database token.
 */
export async function resolveTursoEndpoint(): Promise<TursoEndpoint | null> {
  if (globalForTurso.__sentinelTursoEndpoint) {
    return globalForTurso.__sentinelTursoEndpoint;
  }
  if (
    globalForTurso.__sentinelTursoFailedUntil &&
    Date.now() < globalForTurso.__sentinelTursoFailedUntil
  ) {
    return null;
  }
  if (globalForTurso.__sentinelTursoResolving) {
    return globalForTurso.__sentinelTursoResolving;
  }

  const resolving = (async (): Promise<TursoEndpoint | null> => {
    try {
      const explicitUrl = (process.env.TURSO_DATABASE_URL || process.env.LIBSQL_URL || "").trim();
      const explicitDbToken = (
        process.env.TURSO_AUTH_TOKEN ||
        process.env.LIBSQL_AUTH_TOKEN ||
        ""
      ).trim();

      const platformToken = (
        process.env.TURSO_API_TOKEN ||
        explicitDbToken ||
        DEFAULT_TURSO_API_TOKEN
      ).trim();

      // If user explicitly provided TURSO_DATABASE_URL and TURSO_AUTH_TOKEN, try direct pipeline first
      if (explicitUrl && explicitDbToken) {
        const ep: TursoEndpoint = {
          httpUrl: normalizeDbUrl(explicitUrl),
          authToken: explicitDbToken,
        };
        globalForTurso.__sentinelTursoEndpoint = ep;
        return ep;
      }

      if (!platformToken) return null;

      // Auto-discover via Turso Platform API v1
      const orgsRes = await fetch("https://api.turso.tech/v1/organizations", {
        headers: {
          Authorization: `Bearer ${platformToken}`,
          Accept: "application/json",
        },
        signal: AbortSignal.timeout(4000),
      });

      if (!orgsRes.ok) {
        // If explicitUrl was set without explicitDbToken, maybe platformToken is actually a DB token
        if (explicitUrl) {
          const ep = { httpUrl: normalizeDbUrl(explicitUrl), authToken: platformToken };
          globalForTurso.__sentinelTursoEndpoint = ep;
          return ep;
        }
        globalForTurso.__sentinelTursoFailedUntil = Date.now() + 60_000;
        return null;
      }

      const orgsData = (await orgsRes.json()) as Array<{ slug?: string; name?: string }> | { organizations?: Array<{ slug?: string }> };
      const orgList = Array.isArray(orgsData)
        ? orgsData
        : Array.isArray(orgsData?.organizations)
        ? orgsData.organizations
        : [];

      const orgSlug = orgList[0]?.slug;
      if (!orgSlug) {
        globalForTurso.__sentinelTursoFailedUntil = Date.now() + 60_000;
        return null;
      }

      // List existing databases in the organization
      const dbsRes = await fetch(
        `https://api.turso.tech/v1/organizations/${encodeURIComponent(orgSlug)}/databases`,
        {
          headers: {
            Authorization: `Bearer ${platformToken}`,
            Accept: "application/json",
          },
          signal: AbortSignal.timeout(4000),
        }
      );

      let dbName = "";
      let dbHostname = "";

      if (dbsRes.ok) {
        const dbsJson = (await dbsRes.json()) as {
          databases?: Array<{ Name?: string; name?: string; Hostname?: string; hostname?: string }>;
        };
        const dbs = dbsJson.databases ?? [];
        const preferred =
          dbs.find((d) => /sentinel|trout|audit/i.test(d.Name || d.name || "")) || dbs[0];
        if (preferred) {
          dbName = (preferred.Name || preferred.name || "").trim();
          dbHostname = (preferred.Hostname || preferred.hostname || "").trim();
        }
      }

      // If no database exists yet, automatically create "sentinel-id-db" in default group
      if (!dbName || !dbHostname) {
        // Ensure a group exists first
        await fetch(
          `https://api.turso.tech/v1/organizations/${encodeURIComponent(orgSlug)}/groups`,
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${platformToken}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ name: "default", location: "sin" }),
            signal: AbortSignal.timeout(4000),
          }
        ).catch(() => {});

        const createRes = await fetch(
          `https://api.turso.tech/v1/organizations/${encodeURIComponent(orgSlug)}/databases`,
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${platformToken}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ name: "sentinel-id-db", group: "default" }),
            signal: AbortSignal.timeout(5000),
          }
        );

        if (createRes.ok) {
          const createdJson = (await createRes.json()) as {
            database?: { Name?: string; name?: string; Hostname?: string; hostname?: string };
          };
          dbName = (createdJson.database?.Name || createdJson.database?.name || "sentinel-id-db").trim();
          dbHostname = (createdJson.database?.Hostname || createdJson.database?.hostname || "").trim();
        }
      }

      if (!dbName || !dbHostname) {
        globalForTurso.__sentinelTursoFailedUntil = Date.now() + 60_000;
        return null;
      }

      // Mint a database auth JWT token via Platform API
      const tokenRes = await fetch(
        `https://api.turso.tech/v1/organizations/${encodeURIComponent(
          orgSlug
        )}/databases/${encodeURIComponent(dbName)}/auth/tokens?expiration=never&authorization=full-access`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${platformToken}`,
            Accept: "application/json",
          },
          signal: AbortSignal.timeout(4000),
        }
      );

      if (!tokenRes.ok) {
        globalForTurso.__sentinelTursoFailedUntil = Date.now() + 60_000;
        return null;
      }

      const tokenJson = (await tokenRes.json()) as { jwt?: string };
      if (!tokenJson.jwt) {
        globalForTurso.__sentinelTursoFailedUntil = Date.now() + 60_000;
        return null;
      }

      const endpoint: TursoEndpoint = {
        httpUrl: normalizeDbUrl(dbHostname),
        authToken: tokenJson.jwt,
      };
      globalForTurso.__sentinelTursoEndpoint = endpoint;
      return endpoint;
    } catch {
      globalForTurso.__sentinelTursoFailedUntil = Date.now() + 30_000;
      return null;
    } finally {
      globalForTurso.__sentinelTursoResolving = undefined;
    }
  })();

  globalForTurso.__sentinelTursoResolving = resolving;
  return resolving;
}

/**
 * Execute one or multiple SQL statements in a single HTTP roundtrip via Turso `/v2/pipeline`.
 */
export async function tursoPipeline(statements: HranaStmt[]): Promise<HranaExecuteResult[] | null> {
  const ep = await resolveTursoEndpoint();
  if (!ep) return null;

  const requests = [
    ...statements.map((stmt) => ({
      type: "execute" as const,
      stmt,
    })),
    { type: "close" as const },
  ];

  const res = await fetch(`${ep.httpUrl}/v2/pipeline`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${ep.authToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ requests }),
    signal: AbortSignal.timeout(4500),
  });

  if (!res.ok) {
    throw new Error(`Turso HTTP ${res.status}`);
  }

  const data = (await res.json()) as HranaPipelineResponse;
  const out: HranaExecuteResult[] = [];
  for (const r of data.results ?? []) {
    if (r.type === "error") {
      throw new Error(r.error?.message || "Turso SQL error");
    }
    if (r.response?.type === "execute" && r.response.result) {
      out.push(r.response.result);
    }
  }
  return out;
}

/**
 * Ensures the 2 core SQLite tables (`sentinel_kv` and `sentinel_list`) exist in Turso.
 */
export async function ensureTursoSchema(): Promise<boolean> {
  if (globalForTurso.__sentinelTursoSchemaInit) return true;
  try {
    const res = await tursoPipeline([
      {
        sql: `CREATE TABLE IF NOT EXISTS sentinel_kv (
          k TEXT PRIMARY KEY,
          v TEXT NOT NULL,
          exp INTEGER
        )`,
      },
      {
        sql: `CREATE TABLE IF NOT EXISTS sentinel_list (
          k TEXT NOT NULL,
          idx INTEGER PRIMARY KEY AUTOINCREMENT,
          v TEXT NOT NULL,
          exp INTEGER
        )`,
      },
      {
        sql: `CREATE INDEX IF NOT EXISTS idx_sentinel_list_k ON sentinel_list(k, idx)`,
      },
    ]);
    if (res) {
      globalForTurso.__sentinelTursoSchemaInit = true;
      return true;
    }
  } catch {
    // ignore
  }
  return false;
}

export function cellToString(cell?: HranaRowCell): string | null {
  if (!cell || cell.type === "null" || cell.value === undefined || cell.value === null) {
    return null;
  }
  return String(cell.value);
}

export function cellToNumber(cell?: HranaRowCell): number | null {
  if (!cell || cell.type === "null" || cell.value === undefined || cell.value === null) {
    return null;
  }
  const n = Number(cell.value);
  return Number.isFinite(n) ? n : null;
}
