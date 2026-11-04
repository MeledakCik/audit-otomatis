import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { COOKIE, verifySession } from "@/lib/sentinel/session";
import { AdminNav } from "@/components/sentinel/admin-nav";

export const dynamic = "force-dynamic";
export const metadata = { title: "Admin", robots: { index: false, follow: false } };

export default async function PanelLayout({ children }: { children: React.ReactNode }) {
  // Lapis 2 (setelah proxy.ts): re-check session di Redis sebelum render apa pun.
  if (!(await verifySession((await cookies()).get(COOKIE)?.value))) redirect("/admin/login");
  return (
    <div className="mx-auto w-full max-w-5xl p-4 md:p-8">
      <AdminNav />
      {children}
    </div>
  );
}
