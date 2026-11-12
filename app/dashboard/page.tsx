import type { Metadata } from "next";
import { HomePage } from "@/components/home-glass-view";

export const metadata: Metadata = {
  title: "Dashboard — Sentinel-ID",
  description: "Jalankan audit keamanan pasif dan akses seluruh modul Sentinel-ID.",
};

export default function DashboardPage() {
  return <HomePage />;
}
