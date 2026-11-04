import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { COOKIE, verifySession } from "@/lib/sentinel/session";
import { AdminNav } from "@/components/sentinel/admin-nav";

export const dynamic = "force-dynamic";
export const metadata = { title: "Admin Command Center", robots: { index: false, follow: false } };

export default async function PanelLayout({ children }: { children: React.ReactNode }) {
  if (!(await verifySession((await cookies()).get(COOKIE)?.value))) redirect("/admin/login");
  return (
    <div className="mx-auto w-full max-w-7xl px-4 sm:px-6 lg:px-8 py-6">
      <AdminNav />
      {children}
    </div>
  );
}
