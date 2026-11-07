import { getKv, REDIS_CONFIGURED } from "./redis";
import { redis as sentinelRedis } from "./sentinel/redis";

export type ActivityModule =
  | "FULL_SCAN"
  | "SENTINEL_AUDIT"
  | "SENTINEL_CLAIM"
  | "SENTINEL_VIEW"
  | "QC_SCAN"
  | "SEO_MASTER"
  | "HEADER_ARMOR"
  | "SECRET_HUNTER"
  | "ATTACK_MAP"
  | "BREACH_PEEK"
  | "SUBDOMAIN_WATCH"
  | "TECH_STACK"
  | "SHIELD_STATUS"
  | "OSINT_LOOKUP"
  | "DNS_INTEL"
  | "EXPOSURE_CHECK"
  | "JS_SUPPLY_CHAIN"
  | "SSL_CHECKER"
  | "MAINTENANCE_LOG"
  | "ENDPOINT_TEST";

export type ActivityStatus =
  | "SUCCESS"
  | "RUNNING"
  | "WARNING"
  | "CRITICAL"
  | "BLOCKED"
  | "ERROR";

export interface UserActivityRecord {
  id: string;
  timestamp: number;
  ip: string;
  userAgent: string;
  userId: string;
  module: ActivityModule;
  moduleLabel: string;
  action: string;
  target: string;
  status: ActivityStatus;
  summary: string;
  meta?: Record<string, string | number | boolean | null | undefined>;
}

export interface UserProfileSummary {
  userKey: string;
  ip: string;
  userId: string;
  userAgent: string;
  firstSeen: number;
  lastActive: number;
  totalActivities: number;
  domainsTargeted: string[];
  modulesUsed: string[];
  criticalHits: number;
  lastTarget: string;
  lastModule: string;
}

const ACTIVITY_KEY = "sentinel:admin:user_activities";
const ACTIVITY_TTL_SECONDS = 7 * 24 * 3600; // 7 days
const MAX_ACTIVITIES = 500;

export const MODULE_LABELS: Record<ActivityModule, string> = {
  FULL_SCAN: "Full Passive Scan",
  SENTINEL_AUDIT: "Sentinel Vault Audit",
  SENTINEL_CLAIM: "Klaim Kepemilikan Domain",
  SENTINEL_VIEW: "Buka Evidence Vault (1x)",
  QC_SCAN: "QC Otomatis (SEO/Perf)",
  SEO_MASTER: "SEO Master & Global Rank #1",
  HEADER_ARMOR: "Header Armor",
  SECRET_HUNTER: "Secret Hunter",
  ATTACK_MAP: "Attack Surface Map",
  BREACH_PEEK: "Breach Peek OSINT",
  SUBDOMAIN_WATCH: "Subdomain Watch",
  TECH_STACK: "Tech Stack Fingerprint",
  SHIELD_STATUS: "Shield Status",
  OSINT_LOOKUP: "OSINT Lookup",
  DNS_INTEL: "DNS Intelligence",
  EXPOSURE_CHECK: "Exposure Check",
  JS_SUPPLY_CHAIN: "JS Supply Chain",
  SSL_CHECKER: "SSL/TLS Checker",
  MAINTENANCE_LOG: "Maintenance Log AI",
  ENDPOINT_TEST: "API Endpoint Tester",
};

const globalForActivity = globalThis as unknown as {
  __sentinelActivitiesMem?: UserActivityRecord[];
};
const memActivities = globalForActivity.__sentinelActivitiesMem ?? [];
globalForActivity.__sentinelActivitiesMem = memActivities;

function makeId(): string {
  return `act_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

export function extractRequestIdentity(req?: Request | null, fallbackIp = "anonymous"): {
  ip: string;
  userAgent: string;
  userId: string;
} {
  if (!req) {
    return { ip: fallbackIp, userAgent: "System / Server Action", userId: `uid_${fallbackIp}` };
  }
  const xff = req.headers.get("x-forwarded-for");
  const ip = (xff ? xff.split(",")[0].trim() : req.headers.get("x-real-ip") || fallbackIp).trim() || "anonymous";
  const userAgent = (req.headers.get("user-agent") || "Unknown Browser").slice(0, 220);

  // Extract sentinel_uid cookie if present
  const cookieHeader = req.headers.get("cookie") || "";
  const match = /(?:^|;\s*)sentinel_uid=([^;]+)/.exec(cookieHeader);
  const cookieUid = match ? decodeURIComponent(match[1]).slice(0, 32) : "";
  const shortHash = Buffer.from(`${ip}:${userAgent.slice(0, 40)}`).toString("base64url").slice(0, 10);
  const userId = cookieUid || `usr_${shortHash}`;

  return { ip, userAgent, userId };
}

export async function logUserActivity(input: {
  req?: Request | null;
  ip?: string;
  userAgent?: string;
  userId?: string;
  module: ActivityModule;
  action: string;
  target: string;
  status: ActivityStatus;
  summary: string;
  meta?: Record<string, string | number | boolean | null | undefined>;
}): Promise<UserActivityRecord> {
  const identity = extractRequestIdentity(input.req, input.ip || "anonymous");
  const ip = input.ip || identity.ip;
  const userAgent = input.userAgent || identity.userAgent;
  const userId = input.userId || identity.userId;

  const record: UserActivityRecord = {
    id: makeId(),
    timestamp: Date.now(),
    ip,
    userAgent,
    userId,
    module: input.module,
    moduleLabel: MODULE_LABELS[input.module] ?? input.module,
    action: input.action,
    target: input.target || "-",
    status: input.status,
    summary: input.summary,
    meta: input.meta,
  };

  // Always keep in-memory copy for fast fallback
  memActivities.unshift(record);
  if (memActivities.length > MAX_ACTIVITIES) {
    memActivities.length = MAX_ACTIVITIES;
  }

  // Persist to Redis (try Upstash REST first, then getKv())
  try {
    if (REDIS_CONFIGURED) {
      await getKv().rpushJSON(ACTIVITY_KEY, record, ACTIVITY_TTL_SECONDS, MAX_ACTIVITIES);
      return record;
    }
  } catch {
    // Fallback to sentinelRedis if getKv fails
  }

  try {
    const r = sentinelRedis();
    const p = r.pipeline();
    p.rpush(ACTIVITY_KEY, JSON.stringify(record));
    p.ltrim(ACTIVITY_KEY, -MAX_ACTIVITIES, -1);
    p.expire(ACTIVITY_KEY, ACTIVITY_TTL_SECONDS);
    await p.exec();
  } catch {
    // Silent fallback to memory if Redis is unreachable
  }

  return record;
}

export async function listUserActivities(limit = 250): Promise<UserActivityRecord[]> {
  const seen = new Map<string, UserActivityRecord>();

  for (const item of memActivities) {
    seen.set(item.id, item);
  }

  try {
    if (REDIS_CONFIGURED) {
      const items = await getKv().lrangeJSON<UserActivityRecord | string>(ACTIVITY_KEY, 0, -1);
      for (const raw of items) {
        const parsed: UserActivityRecord | null =
          typeof raw === "string"
            ? (() => {
                try {
                  return JSON.parse(raw) as UserActivityRecord;
                } catch {
                  return null;
                }
              })()
            : raw;
        if (parsed && parsed.id) {
          seen.set(parsed.id, parsed);
        }
      }
    } else {
      const r = sentinelRedis();
      const rawList = await r.lrange<string>(ACTIVITY_KEY, 0, -1);
      for (const raw of rawList ?? []) {
        try {
          const parsed = (typeof raw === "string" ? JSON.parse(raw) : raw) as UserActivityRecord;
          if (parsed && parsed.id) seen.set(parsed.id, parsed);
        } catch {
          // ignore malformed entry
        }
      }
    }
  } catch {
    // fallback to seen map from memory
  }

  return Array.from(seen.values())
    .sort((a, b) => b.timestamp - a.timestamp)
    .slice(0, limit);
}

export function buildUserProfiles(activities: UserActivityRecord[]): UserProfileSummary[] {
  const map = new Map<
    string,
    {
      userKey: string;
      ip: string;
      userId: string;
      userAgent: string;
      firstSeen: number;
      lastActive: number;
      totalActivities: number;
      domains: Set<string>;
      modules: Set<string>;
      criticalHits: number;
      lastTarget: string;
      lastModule: string;
    }
  >();

  for (const act of activities) {
    const key = act.userId && act.userId !== "usr_anonymous" ? act.userId : act.ip || "anonymous";
    const existing = map.get(key);
    if (!existing) {
      const domains = new Set<string>();
      if (act.target && act.target !== "-") domains.add(act.target);
      const modules = new Set<string>([act.moduleLabel]);
      map.set(key, {
        userKey: key,
        ip: act.ip,
        userId: act.userId,
        userAgent: act.userAgent,
        firstSeen: act.timestamp,
        lastActive: act.timestamp,
        totalActivities: 1,
        domains,
        modules,
        criticalHits: act.status === "CRITICAL" ? 1 : 0,
        lastTarget: act.target,
        lastModule: act.moduleLabel,
      });
    } else {
      existing.totalActivities += 1;
      if (act.timestamp < existing.firstSeen) existing.firstSeen = act.timestamp;
      if (act.timestamp > existing.lastActive) {
        existing.lastActive = act.timestamp;
        existing.lastTarget = act.target;
        existing.lastModule = act.moduleLabel;
        if (act.ip && act.ip !== "anonymous") existing.ip = act.ip;
        if (act.userAgent && act.userAgent !== "System / Server Action") existing.userAgent = act.userAgent;
      }
      if (act.target && act.target !== "-") existing.domains.add(act.target);
      existing.modules.add(act.moduleLabel);
      if (act.status === "CRITICAL") existing.criticalHits += 1;
    }
  }

  return Array.from(map.values())
    .map((u) => ({
      userKey: u.userKey,
      ip: u.ip,
      userId: u.userId,
      userAgent: u.userAgent,
      firstSeen: u.firstSeen,
      lastActive: u.lastActive,
      totalActivities: u.totalActivities,
      domainsTargeted: Array.from(u.domains),
      modulesUsed: Array.from(u.modules),
      criticalHits: u.criticalHits,
      lastTarget: u.lastTarget,
      lastModule: u.lastModule,
    }))
    .sort((a, b) => b.lastActive - a.lastActive);
}
