import { HeaderArmorView } from "@/components/header-armor/header-armor-view";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "Header Armor Checker",
  description: "Cek header keamanan HTTP domain kamu secara pasif — satu request GET, tanpa exploit.",
};

export default function HeaderArmorPage() {
  return <HeaderArmorView />;
}
