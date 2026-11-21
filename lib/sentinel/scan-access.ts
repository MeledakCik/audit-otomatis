import { guardAdmin } from "@/lib/sentinel/admin-auth";
import type { ScanState } from "@/lib/types";

export async function guardPrivateScan(req: Request, scan: Pick<ScanState, "adminOnly">) {
  return scan.adminOnly ? guardAdmin(req) : null;
}
