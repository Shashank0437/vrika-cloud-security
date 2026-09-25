"use client";

import { type FormEvent, useState } from "react";

import { confirmFindingRemoval } from "@/actions/findings/findings-triage";
import { Button, Textarea } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import type { TrackedFinding } from "@/types/findings-triage";

interface ConfirmRemovalDialogProps {
  finding: TrackedFinding;
  onClose: () => void;
  onConfirmed: () => void;
}

export function ConfirmRemovalDialog({
  finding,
  onClose,
  onConfirmed,
}: ConfirmRemovalDialogProps) {
  const [evidence, setEvidence] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const attrs = finding.attributes;
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!confirmed || evidence.trim().length < 3) {
      setError("Confirm removal and provide evidence of 3-500 characters.");
      return;
    }
    if (!attrs.snapshot.finding_id || !attrs.observation_scan_id) {
      setError("Finding context changed. Refresh before confirming removal.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      await confirmFindingRemoval({
        triageId: finding.id,
        findingId: attrs.snapshot.finding_id,
        observationScanId: attrs.observation_scan_id,
        previousStatus: attrs.status,
        evidence: evidence.trim(),
        confirmRemoved: confirmed,
      });
      onConfirmed();
      onClose();
    } catch (cause) {
      setError(
        cause instanceof Error
          ? cause.message
          : "Could not confirm resource removal.",
      );
    } finally {
      setSaving(false);
    }
  };
  return (
    <Modal
      open
      title="Confirm resource removal"
      onOpenChange={(open) => {
        if (!open && !saving) onClose();
      }}
    >
      <form onSubmit={submit} className="flex flex-col gap-4">
        <p className="text-sm">
          This records your confirmation, not automatic cloud verification. The
          finding will be resolved as Resource removed. Its historical scan
          result and earlier history will be retained, and your confirmation
          will be added to the audit trail.
        </p>
        <div className="text-sm">
          <p>Provider: {attrs.snapshot.provider_uid || attrs.provider_id}</p>
          {attrs.snapshot.resources?.map((resource) => (
            <p key={resource.uid} className="break-all">
              {resource.name} ({resource.uid})
            </p>
          ))}
        </div>
        <label className="flex flex-col gap-2 text-sm">
          Removal evidence
          <Textarea
            value={evidence}
            onChange={(event) => setEvidence(event.target.value)}
            maxLength={500}
            disabled={saving}
            placeholder="Describe how you confirmed removal, including a deletion log or change reference."
            required
          />
        </label>
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(event) => setConfirmed(event.target.checked)}
            disabled={saving}
          />
          I confirmed that all listed resources were removed from this account
          or project.
        </label>
        {error && (
          <p role="alert" className="text-sm">
            {error}
          </p>
        )}
        <div className="flex justify-end gap-2">
          <Button
            type="button"
            variant="outline"
            disabled={saving}
            onClick={onClose}
          >
            Cancel
          </Button>
          <Button
            type="submit"
            disabled={saving || !confirmed || evidence.trim().length < 3}
          >
            {saving ? "Saving..." : "Confirm and resolve"}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
