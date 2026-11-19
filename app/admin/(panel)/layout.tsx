import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { COOKIE, verifySession } from "@/lib/sentinel/session";
import { AdminNav } from "@/components/sentinel/admin-nav";

export const dynamic = "force-dynamic";
export const metadata = { title: "Admin Sentinel-ID", robots: { index: false, follow: false } };

export default async function PanelLayout({ children }: { children: React.ReactNode }) {
  if (!(await verifySession((await cookies()).get(COOKIE)?.value))) redirect("/admin/login");
  return (
    <div className="mx-auto w-full max-w-7xl space-y-5 sm:space-y-7">
      <AdminNav />
      {children}
    </div>
  );
}
