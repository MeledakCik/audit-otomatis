import { redirect } from "next/navigation";

export const metadata = {
  title: "Sentinel Vault Audit — Integrated in Scan",
};

export default function SentinelRedirectPage() {
  redirect("/?tab=sentinel");
}
