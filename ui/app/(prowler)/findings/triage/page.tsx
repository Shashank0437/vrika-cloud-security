import Link from "next/link";
import { notFound } from "next/navigation";

import { loadTrackedFindings } from "@/actions/findings/findings-triage.server";
import { Button } from "@/components/shadcn/button/button";
import { ContentLayout } from "@/components/shadcn/content-layout";
import type { SearchParamsProps } from "@/types/components";

import { TrackedFindings } from "./tracked-findings";

export default async function TriagePage({
  searchParams,
}: {
  searchParams: Promise<SearchParamsProps>;
}) {
  if (process.env.NEXT_PUBLIC_VRIKA_TRIAGE_ENABLED !== "true") notFound();
  const params = await searchParams;
  const page = Number(params.page ?? "1");
  const status = params.status?.toString() || "";
  const search = params.search?.toString() || "";
  const providerId = params.providerId?.toString() || "";
  const result = await loadTrackedFindings({
    page,
    status: status || undefined,
    search,
    providerId: providerId || undefined,
  });
  return (
    <ContentLayout title="Tracked findings" icon="lucide:history">
      <div className="mb-4 flex items-center justify-between gap-4">
        <p className="text-text-neutral-secondary text-sm">
          Findings your team has triaged or annotated, including resolved and
          missing resources. Historical results do not count as results in the
          latest scan.
        </p>
        <Button asChild variant="outline">
          <Link href="/findings">Current findings</Link>
        </Button>
      </div>
      <TrackedFindings
        result={result}
        page={page}
        status={status}
        search={search}
        providerId={providerId}
      />
    </ContentLayout>
  );
}
