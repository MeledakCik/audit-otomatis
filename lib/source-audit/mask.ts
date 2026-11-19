import type { Lang } from "./rules";

export const CODE_LANGS = new Set<Lang>(["js", "php", "py", "go", "java", "cs", "rb"]);

type State = null | "'" | '"' | "`" | "block" | "'''" | '"""';

/**
 * Salinan baris dengan isi string literal & komentar diganti spasi (posisi karakter tetap).
 * Dipakai untuk memastikan pola cocok di KODE, bukan di teks/deskripsi/dokumentasi.
 * Melacak template literal (`) dan blok komentar lintas baris, serta triple-quote Python.
 */
export function maskCode(lines: string[], lang: Lang): string[] {
  const out: string[] = [];
  let state: State = null;
  const hash = lang === "py" || lang === "rb" || lang === "php";
  const slash = lang !== "py" && lang !== "rb";
  for (const line of lines) {
    if (state === "'" || state === '"') state = null;
    let res = "";
    let i = 0;
    while (i < line.length) {
      const c = line[i];
      const c2 = line.slice(i, i + 2);
      const c3 = line.slice(i, i + 3);
      if (state === "block") {
        if (c2 === "*/") { res += "  "; i += 2; state = null; } else { res += " "; i++; }
        continue;
      }
      if (state === "'''" || state === '"""') {
        if (c3 === state) { res += c3; i += 3; state = null; } else { res += " "; i++; }
        continue;
      }
      if (state) {
        if (c === "\\") { res += "  "; i += 2; continue; }
        if (c === state) { res += c; i++; state = null; continue; }
        res += " "; i++;
        continue;
      }
      if (lang === "py" && (c3 === "'''" || c3 === '"""')) { state = c3; res += c3; i += 3; continue; }
      if (slash && c2 === "//") { res += " ".repeat(line.length - i); break; }
      if (slash && c2 === "/*") { state = "block"; res += "  "; i += 2; continue; }
      if (hash && c === "#") { res += " ".repeat(line.length - i); break; }
      if (c === "'" || c === '"' || (c === "`" && lang === "js")) { state = c; res += c; i++; continue; }
      res += c; i++;
    }
    out.push(res.slice(0, line.length).padEnd(line.length, " "));
  }
  return out;
}
