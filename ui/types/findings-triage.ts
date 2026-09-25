export const FINDING_TRIAGE_STATUS = {
  OPEN: "open",
  UNDER_REVIEW: "under_review",
  REMEDIATING: "remediating",
  RESOLVED: "resolved",
  RISK_ACCEPTED: "risk_accepted",
  FALSE_POSITIVE: "false_positive",
  REOPENED: "reopened",
} as const;

export type FindingTriageStatus =
  (typeof FINDING_TRIAGE_STATUS)[keyof typeof FINDING_TRIAGE_STATUS];

export const FINDING_TRIAGE_STATUS_LABELS = {
  [FINDING_TRIAGE_STATUS.OPEN]: "Open",
  [FINDING_TRIAGE_STATUS.UNDER_REVIEW]: "Under Review",
  [FINDING_TRIAGE_STATUS.REMEDIATING]: "Remediating",
  [FINDING_TRIAGE_STATUS.RESOLVED]: "Resolved",
  [FINDING_TRIAGE_STATUS.RISK_ACCEPTED]: "Risk Accepted",
  [FINDING_TRIAGE_STATUS.FALSE_POSITIVE]: "False Positive",
  [FINDING_TRIAGE_STATUS.REOPENED]: "Reopened",
} as const satisfies Record<FindingTriageStatus, string>;

export const FINDING_TRIAGE_MANUAL_STATUS_VALUES = [
  FINDING_TRIAGE_STATUS.OPEN,
  FINDING_TRIAGE_STATUS.UNDER_REVIEW,
  FINDING_TRIAGE_STATUS.REMEDIATING,
  FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
  FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
] as const;

export type FindingTriageManualStatus =
  (typeof FINDING_TRIAGE_MANUAL_STATUS_VALUES)[number];

export const FINDING_TRIAGE_AUTOMATION_STATUS_VALUES = [
  FINDING_TRIAGE_STATUS.RESOLVED,
  FINDING_TRIAGE_STATUS.REOPENED,
] as const;

export const FINDING_TRIAGE_MUTELIST_SHORTCUT_STATUS_VALUES = [
  FINDING_TRIAGE_STATUS.RISK_ACCEPTED,
  FINDING_TRIAGE_STATUS.FALSE_POSITIVE,
] as const;

export const isManualStatus = (
  status: unknown,
): status is FindingTriageManualStatus => {
  return FINDING_TRIAGE_MANUAL_STATUS_VALUES.some((value) => value === status);
};

export const isMutelistShortcutStatus = (status: unknown): boolean => {
  return FINDING_TRIAGE_MUTELIST_SHORTCUT_STATUS_VALUES.some(
    (value) => value === status,
  );
};

export const getFindingTriageMuteInfoCopy = (status: FindingTriageStatus) =>
  `Changing triage to ${FINDING_TRIAGE_STATUS_LABELS[status]} will mute the finding`;

// Only RESOLVED locks manual edits: automation owns the transition out of it
// (REOPENED on a failing rescan), while REOPENED invites human re-triage.
export const isTriageStatusLocked = (status: FindingTriageStatus): boolean =>
  status === FINDING_TRIAGE_STATUS.RESOLVED;

export const FINDING_TRIAGE_RESOLVED_LOCKED_COPY =
  "Triage status is managed automatically once the finding is resolved." as const;

export const FINDING_TRIAGE_DISABLED_REASON = {
  CLOUD_ONLY: "cloud_only",
  FORBIDDEN: "forbidden",
  LOADING: "loading",
} as const;

export type FindingTriageDisabledReason =
  (typeof FINDING_TRIAGE_DISABLED_REASON)[keyof typeof FINDING_TRIAGE_DISABLED_REASON];

export const FINDING_TRIAGE_ORIGIN = {
  TABLE: "table",
  MODAL: "modal",
} as const;

export const FINDING_TRIAGE_NOTE_MAX_LENGTH = 500 as const;
export const FINDING_TRIAGE_BILLING_HREF =
  "https://prowler.com/pricing" as const;

export interface FindingTriageSummary {
  findingId: string;
  findingUid: string;
  triageId: string | null;
  notesCount: number;
  status: FindingTriageStatus;
  label: string;
  hasVisibleNote: boolean;
  isMuted: boolean;
  canEdit: boolean;
  canManageExceptions?: boolean;
  vrikaTriage?: boolean;
  disabledReason?: FindingTriageDisabledReason;
  billingHref: string;
  resolutionReason?: string;
}

export const TRIAGE_RESOLUTION_LABELS: Record<string, string> = {
  check_passed: "Scan passed",
  resource_removed: "Resource removed",
};

export const TRIAGE_OBSERVATION_LABELS: Record<string, string> = {
  observed: "Observed",
  not_seen: "Not seen in latest scan",
  verification_failed: "Deletion not verified",
  resource_removed: "Deletion verified",
  removal_confirmed: "Removal confirmed by reviewer",
};

export interface TrackedResource {
  uid: string;
  name: string;
  region: string;
  service: string;
  type: string;
}

export interface TrackedFindingSnapshot {
  finding_id?: string;
  scan_id?: string;
  observed_at?: string;
  provider_uid?: string;
  check_id?: string;
  title?: string;
  severity?: string;
  result?: string;
  muted?: boolean;
  resources?: TrackedResource[];
}

export interface TrackedFindingAttributes {
  finding_uid: string;
  provider_id: string;
  provider_alias: string | null;
  provider_type: string;
  status: FindingTriageStatus;
  resolution_reason: string;
  observation: string;
  observation_detail: string;
  snapshot: TrackedFindingSnapshot;
  notes_count: number;
  can_edit: boolean;
  can_manage_exceptions: boolean;
  updated_at: string;
  verification_checked_at: string | null;
  observation_scan_id: string | null;
}

export interface TrackedFinding {
  id: string;
  attributes: TrackedFindingAttributes;
}

export interface TrackedFindingsPage {
  findings: TrackedFinding[];
  hasNext: boolean;
}

export interface TrackedFindingsFilters {
  page?: number;
  status?: string;
  search?: string;
  providerId?: string;
}

export interface ConfirmFindingRemovalInput {
  triageId: string;
  findingId: string;
  observationScanId: string;
  previousStatus: FindingTriageStatus;
  evidence: string;
  confirmRemoved: boolean;
}

export interface FindingTriageDetail extends FindingTriageSummary {
  noteId: string | null;
  noteBody: string;
  maxNoteLength: typeof FINDING_TRIAGE_NOTE_MAX_LENGTH;
}

export interface UpdateFindingTriageInput {
  findingId: string;
  findingUid: string;
  triageId: string | null;
  notesCount: number;
  noteId?: string | null;
  status?: FindingTriageManualStatus;
  previousStatus?: FindingTriageStatus;
  isMuted?: boolean;
  note?: string;
  reason?: string;
  confirmMute?: boolean;
}

interface TriageChange<T> {
  from: T;
  to: T;
}

interface FindingTriageChanges {
  status?: TriageChange<FindingTriageStatus>;
  note?: TriageChange<string>;
  reason?: string;
  verification?: FindingTriageVerification;
}

interface FindingTriageVerification {
  method: string;
  evidence?: string;
  checked_at?: string;
}

interface FindingTriageEventAttributes {
  kind: string;
  actor_name: string;
  inserted_at: string;
  changes: FindingTriageChanges;
}

export interface FindingTriageEvent {
  id: string;
  attributes: FindingTriageEventAttributes;
}

export interface FindingTriageHistory {
  events: FindingTriageEvent[];
  hasNext: boolean;
}

interface TriageActionSuccess<T> {
  ok: true;
  value: T;
}

interface TriageActionFailure {
  ok: false;
  message: string;
}

export type TriageActionResult<T> =
  | TriageActionSuccess<T>
  | TriageActionFailure;

export interface FindingTriageLoadedNote {
  noteId: string;
  noteBody: string;
}
