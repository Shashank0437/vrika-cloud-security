import {
  loadFindingTriageHistory as loadHistoryAction,
  loadLatestFindingTriageNote as loadNoteAction,
  updateFindingTriage as updateAction,
} from "@/actions/findings/findings-triage.server";
import type {
  FindingTriageSummary,
  TriageActionResult,
  UpdateFindingTriageInput,
} from "@/types/findings-triage";

function unwrap<T>(result: TriageActionResult<T>): T {
  if (!result.ok) {
    throw new Error(result.message);
  }
  return result.value;
}

export async function updateFindingTriage(input: UpdateFindingTriageInput) {
  unwrap(await updateAction(input));
}

export async function loadLatestFindingTriageNote(
  triage: FindingTriageSummary,
) {
  return unwrap(await loadNoteAction(triage));
}

export async function loadFindingTriageHistory(
  triage: FindingTriageSummary,
  page = 1,
) {
  return unwrap(await loadHistoryAction(triage, page));
}
