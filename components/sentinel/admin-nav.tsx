"use client";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";

export function AdminNav() {
  const path = usePathname();
  const router = useRouter();
  const tab = (href: string, label: string) => (
    <Link href={href} className={`rounded-full px-4 py-1.5 text-sm ${path.startsWith(href) ? "bg-accent text-accent-fg" : "border border-border text-muted hover:text-foreground"}`}>
      {label}
    </Link>
  );
  async function logout() {
    await fetch("/api/admin/logout", { method: "POST" });
    router.replace("/admin/login"); router.refresh();
  }
  return (
    <nav className="mb-6 flex flex-wrap items-center gap-2">
      {tab("/admin/vault", "Vault")}
      {tab("/admin/requests", "Requests")}
      <button onClick={logout} className="ml-auto text-sm text-muted hover:text-sev-critical">Logout</button>
    </nav>
  );
}
