import { RequestInspector } from "@/components/request-inspector";

export const dynamic = "force-dynamic";

export default async function RequestDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <RequestInspector scanId={id} />;
}
