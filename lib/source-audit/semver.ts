/** Perbandingan versi longgar (semver, PEP 440 sederhana, tag Go "v1.2.3"). */
export function compareVersions(a: string, b: string): number {
  const norm = (v: string) => v.replace(/^v/i, "").split(/[.+-]/).map((x) => (/^\d+$/.test(x) ? Number(x) : x));
  const pa = norm(a);
  const pb = norm(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x === y) continue;
    if (typeof x === "number" && typeof y === "number") return x - y;
    // pre-release (string) < rilis (angka)
    if (typeof x === "number") return 1;
    if (typeof y === "number") return -1;
    return String(x).localeCompare(String(y));
  }
  return 0;
}

/** Versi perbaikan tertinggi = versi minimum yang menutup semua kerentanan yang diketahui. */
export function maxVersion(list: (string | undefined)[]): string | undefined {
  return list.filter((v): v is string => !!v).sort(compareVersions).pop();
}
