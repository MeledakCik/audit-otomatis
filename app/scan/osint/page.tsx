import { OsintView } from "@/components/osint/osint-view";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "OSINT Lookup — Data Publik",
  description:
    "OSINT pasif dari nama, domain, email, dan username (Instagram, TikTok, Facebook, dll) memakai sumber data publik saja.",
};

export default function OsintPage() {
  return <OsintView />;
}
