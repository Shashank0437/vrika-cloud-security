"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  loadLatestFindingTriageNote,
  updateFindingTriage,
} from "@/actions/findings/findings-triage";
import { FindingNoteModal } from "@/components/findings/table/finding-note-modal";
import { FindingTriageStatusCell } from "@/components/findings/table/finding-triage-cells";
import { Button } from "@/components/shadcn/button/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/shadcn/table/table";
import { brandText } from "@/lib/branding";
import {
  FINDING_TRIAGE_BILLING_HREF,
  FINDING_TRIAGE_NOTE_MAX_LENGTH,
  FINDING_TRIAGE_STATUS_LABELS,
  type FindingTriageDetail,
  type FindingTriageSummary,
  type TrackedFinding,
  type TrackedFindingsPage,
  TRIAGE_OBSERVATION_LABELS,
  TRIAGE_RESOLUTION_LABELS,
  type TriageActionResult,
  type UpdateFindingTriageInput,
} from "@/types/findings-triage";

import { ConfirmRemovalDialog } from "./confirm-removal-dialog";

interface TrackedFindingsProps {
  result: TriageActionResult<TrackedFindingsPage>;
  page: number;
  status: string;
  search: string;
  providerId: string;
}

function TrackedFindingRow({ finding }: { finding: TrackedFinding }) {
  const router = useRouter();
  const [detail, setDetail] = useState<FindingTriageDetail | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const attrs = finding.attributes;
  const snapshot = attrs.snapshot;
  const triage: FindingTriageSummary = {
    findingId: snapshot.finding_id || finding.id,
    findingUid: attrs.finding_uid,
    triageId: finding.id,
    status: attrs.status,
    label: FINDING_TRIAGE_STATUS_LABELS[attrs.status],
    notesCount: attrs.notes_count,
    hasVisibleNote: attrs.notes_count > 0,
    isMuted: snapshot.muted === true,
    canEdit: attrs.can_edit,
    canManageExceptions: attrs.can_manage_exceptions,
    vrikaTriage: true,
    billingHref: FINDING_TRIAGE_BILLING_HREF,
    resolutionReason: attrs.resolution_reason,
  };
  const title = brandText(
    snapshot.title || snapshot.check_id || "Finding context not retained",
  );
  const resources = snapshot.resources
    ?.map((resource) => resource.name || resource.uid)
    .join(", ");
  const provider =
    attrs.provider_alias || snapshot.provider_uid || attrs.provider_id;
  const canConfirmRemoval =
    attrs.can_edit &&
    attrs.can_manage_exceptions &&
    attrs.status !== "resolved" &&
    ["not_seen", "verification_failed"].includes(attrs.observation) &&
    Boolean(
      attrs.observation_scan_id &&
        snapshot.finding_id &&
        snapshot.resources?.length,
    );
  const update = async (input: UpdateFindingTriageInput) => {
    await updateFindingTriage(input);
    router.refresh();
  };
  const openHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const note =
        attrs.notes_count > 0
          ? await loadLatestFindingTriageNote(triage)
          : null;
      setDetail({
        ...triage,
        noteId: note?.noteId ?? null,
        noteBody: note?.noteBody ?? "",
        maxNoteLength: FINDING_TRIAGE_NOTE_MAX_LENGTH,
      });
    } catch (cause) {
      setError(
        cause instanceof Error ? cause.message : "Could not load triage notes.",
      );
    } finally {
      setLoading(false);
    }
  };
  return (
    <TableRow>
      <TableCell className="max-w-sm break-words">
        <p className="font-medium">{title}</p>
        <p className="text-text-neutral-secondary text-xs">
          {resources || attrs.finding_uid}
        </p>
        <p className="text-text-neutral-secondary text-xs">
          {attrs.provider_type.toUpperCase()} · {provider}
        </p>
      </TableCell>
      <TableCell>
        <span>{snapshot.result || "Not retained"}</span>
        <p className="text-text-neutral-secondary text-xs">
          Historical scan result
        </p>
      </TableCell>
      <TableCell>
        <FindingTriageStatusCell
          triage={triage}
          onTriageUpdateAction={update}
        />
        {TRIAGE_RESOLUTION_LABELS[attrs.resolution_reason] && (
          <p className="text-text-neutral-secondary text-xs">
            {TRIAGE_RESOLUTION_LABELS[attrs.resolution_reason]}
          </p>
        )}
      </TableCell>
      <TableCell className="max-w-xs">
        <p>
          {TRIAGE_OBSERVATION_LABELS[attrs.observation] ||
            "Observation unavailable"}
        </p>
        {attrs.observation_detail && (
          <p className="text-text-neutral-secondary text-xs">
            {attrs.observation_detail}
          </p>
        )}
        {attrs.verification_checked_at && (
          <p className="text-text-neutral-secondary text-xs">
            Checked: {new Date(attrs.verification_checked_at).toLocaleString()}
          </p>
        )}
      </TableCell>
      <TableCell>
        {snapshot.observed_at
          ? new Date(snapshot.observed_at).toLocaleString()
          : "Not retained"}
      </TableCell>
      <TableCell>
        {canConfirmRemoval && (
          <Button variant="outline" onClick={() => setConfirmOpen(true)}>
            Confirm resource removal
          </Button>
        )}
        {confirmOpen && (
          <ConfirmRemovalDialog
            finding={finding}
            onClose={() => setConfirmOpen(false)}
            onConfirmed={() => router.refresh()}
          />
        )}
        <Button variant="outline" disabled={loading} onClick={openHistory}>
          {loading ? "Loading..." : "Notes & history"}
        </Button>
        {error && (
          <p role="alert" className="text-sm">
            {error}
          </p>
        )}
        {detail && (
          <FindingNoteModal
            open
            onOpenChange={(open) => {
              if (!open) setDetail(null);
            }}
            triage={detail}
            findingContext={{ title, resource: resources, provider }}
            onTriageUpdateAction={update}
          />
        )}
      </TableCell>
    </TableRow>
  );
}

export function TrackedFindings({
  result,
  page,
  status,
  search,
  providerId,
}: TrackedFindingsProps) {
  const router = useRouter();
  const pageHref = (number: number) => {
    const params = new URLSearchParams({ page: String(number) });
    if (status) params.set("status", status);
    if (search) params.set("search", search);
    if (providerId) params.set("providerId", providerId);
    return `/findings/triage?${params}`;
  };
  return (
    <>
      <form
        className="mb-4 flex flex-wrap items-end gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          const data = new FormData(event.currentTarget);
          const params = new URLSearchParams();
          data.forEach((value, key) => {
            if (typeof value === "string" && value.trim())
              params.set(key, value.trim());
          });
          router.push(`/findings/triage?${params}`);
        }}
      >
        <label className="flex flex-col gap-1 text-sm">
          Search findings or resources
          <input
            className="border-border-input-primary rounded-lg border p-2"
            name="search"
            defaultValue={search}
            maxLength={200}
          />
        </label>
        <label className="flex flex-col gap-1 text-sm">
          Triage status
          <select
            className="bg-bg-neutral-primary border-border-input-primary rounded-lg border p-2"
            name="status"
            defaultValue={status}
          >
            <option value="">All statuses</option>
            {Object.entries(FINDING_TRIAGE_STATUS_LABELS).map(
              ([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ),
            )}
          </select>
        </label>
        {providerId && (
          <input type="hidden" name="providerId" value={providerId} />
        )}
        <Button type="submit">Apply filters</Button>
        <Button
          type="button"
          variant="outline"
          onClick={() => router.refresh()}
        >
          Refresh
        </Button>
      </form>
      {!result.ok ? (
        <p role="alert">{result.message}</p>
      ) : (
        <>
          <Table aria-label="Tracked findings">
            <TableHeader>
              <TableRow>
                <TableHead>Finding / Resource</TableHead>
                <TableHead>Last result</TableHead>
                <TableHead>Triage</TableHead>
                <TableHead>Observation</TableHead>
                <TableHead>Last observed</TableHead>
                <TableHead>History</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {result.value.findings.map((finding) => (
                <TrackedFindingRow
                  key={`${finding.id}:${finding.attributes.updated_at}`}
                  finding={finding}
                />
              ))}
              {result.value.findings.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6}>
                    No tracked findings match these filters. Change a
                    finding&apos;s triage status or add a note to track it.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
          <div className="mt-4 flex items-center gap-3">
            {page > 1 && (
              <Button asChild variant="outline">
                <Link href={pageHref(page - 1)}>Previous</Link>
              </Button>
            )}
            <span>Page {page}</span>
            {result.value.hasNext && (
              <Button asChild variant="outline">
                <Link href={pageHref(page + 1)}>Next</Link>
              </Button>
            )}
          </div>
        </>
      )}
    </>
  );
}
